#!/usr/bin/env python

#
# Code to allow the ICE board to interact with the PRC
# via MBUS
#
#
# Andrew Lukefahr
# lukefahr@umich.edu
#
#

#from pdb import set_trace as bp



# Coerce Py2k to act more like Py3k
from __future__ import (absolute_import, division, print_function, unicode_literals)
from builtins import (
        ascii, bytes, chr, dict, filter, hex, input, int, isinstance, list, map,
        next, object, oct, open, pow, range, round, str, super, zip,
        )

import argparse
import atexit
import binascii
import csv
import inspect
import os
import sys
import socket
import queue as Queue
import time
import threading

from pdb import set_trace as bp

import struct

# if Py2K:
import imp

from . import __version__ 

from . import m3_logging
logger = m3_logging.getGlobalLogger()




class mbus_controller( object):

    TITLE = "MBUS Programmer"
    DESCRIPTION = "Tool to program M3 chips using the MBUS protocol."
    DEFAULT_PRC_PREFIX = '0x1'

    #MSG_TYPE = 'b+'

    def __init__(self, m3_ice, parser):
        self.m3_ice = m3_ice
        self.parser = parser
        self.add_parse_args(parser)

    def add_parse_args(self, parser):


        self.subparsers = parser.add_subparsers(
                title = 'MBUS Commands',
                description='MBUS Actions supported through ICE',
                )

        self.parser_program = self.subparsers.add_parser('program',
                help = 'Program the PRC via MBUS')
        self.parser_program.add_argument('-p', '--short-prefix',
                help="The short MBUS address of the PRC, e.g. 0x1",
                default=mbus_controller.DEFAULT_PRC_PREFIX,
                )
        self.parser_program.add_argument('BINFILE', 
                help="Program to flash over MBUS",
                )
        self.parser_program.set_defaults(func=self.cmd_program)

        self.parser_debug = self.subparsers.add_parser('debug',
                help = 'Debug the PRC via MBUS')
        self.parser_debug.add_argument('DbgAddr',
                help='The memory address to insert a dbgpoint'
                )
        self.parser_debug.add_argument('-p', '--short-prefix',
                help="The short MBUS address of the PRC, e.g. 0x1",
                default=mbus_controller.DEFAULT_PRC_PREFIX,
                )
        self.parser_debug.set_defaults(func=self.cmd_debug)

    def cmd_program(self):
        
        self.m3_ice.dont_do_default("Run power-on sequence", 
                    self.m3_ice.power_on)
        self.m3_ice.dont_do_default("Reset M3", self.m3_ice.reset_m3)

        logger.info("** Setting ICE MBus controller to slave mode")
        self.m3_ice.ice.mbus_set_master_onoff(False)

        logger.info("** Disabling ICE MBus snoop mode")
        self.m3_ice.ice.mbus_set_snoop(False)

        #logger.info("Triggering MBUS internal reset")
        #self.m3_ice.ice.mbus_set_internal_reset(True)
        #self.m3_ice.ice.mbus_set_internal_reset(False)

        #pull prc_addr from command line
        # and convert to binary
        prc_addr = int(self.m3_ice.args.short_prefix, 16)

        if (prc_addr > 0x0 and prc_addr < 0xf):
            mbus_short_addr = (prc_addr << 4 | 0x02)
            mbus_addr = struct.pack(">I", mbus_short_addr)
        elif (prc_addr >= 0xf0000 and prc_addr < 0xfffff):
            raise Exception("Only short prefixes supported")
            #mbus_addr = struct.pack(">I", mbus_long_addr)
        else: raise Exception("Bad MBUS Addr")

        logger.info('MBus_PRC_Addr: ' + binascii.hexlify(mbus_addr))

        # 0x0 = mbus register write
        mbus_regwr = struct.pack(">I", ( prc_addr << 4) | 0x0 ) 
        # 0x2 = memory write
        mbus_memwr = struct.pack(">I", ( prc_addr << 4) | 0x2 ) 

        # number of bytes per packet (must be < 256)
        chunk_size_bytes = 128 
        # actual binfile is hex characters (1/2 byte), so twice size
        chunk_size_chars = chunk_size_bytes * 2

        ## lower CPU reset 
        ## This won't work until PRCv16+
            #RUN_CPU = 0xA0000040  # Taken from PRCv14_PREv14.pdf page 19. 
            #mem_addr = struct.pack(">I", RUN_CPU) 
        # instead use the RUN_CPU MBUS register
        data= struct.pack(">I", 0x10000000) 
        logger.debug("raising RESET signal... ")
        self.m3_ice.ice.mbus_send(mbus_regwr, data)

        # load the program
        logger.debug ( 'loading binfile: '  + self.m3_ice.args.BINFILE) 
        datafile = self.m3_ice.read_binfile_static(self.m3_ice.args.BINFILE)
        # convert to hex
        datafile = binascii.unhexlify(datafile)
        # then switch endian-ness
        # https://docs.python.org/2/library/struct.html
        bigE= '>' +  str(int(len(datafile)/4)) + 'I' # words = bytes/4
        litE= '<' + str(int(len(datafile)/4)) + 'I' 
        # unpack little endian, repack big endian
        datafile = struct.pack(bigE, * struct.unpack(litE, datafile))
 
        # split file into chunks, pair each chunk with an address, 
        # then write each addr,chunk over mbus
        logger.debug ( 'splitting binfile into ' + str(chunk_size_bytes) 
                            + ' byte chunks')
        payload_chunks = self.split_transmission(datafile, chunk_size_bytes)
        payload_addrs = range(0, len(datafile), chunk_size_bytes) 

        for mem_addr, payload in zip(payload_addrs, payload_chunks):

            mem_addr = struct.pack(">I", mem_addr)
            logger.debug('Mem Addr: ' + binascii.hexlify(mem_addr))

            logger.debug('Payload: ' + binascii.hexlify(payload))

            data = mem_addr + payload 
            #logger.debug( 'data: ' + binascii.hexlify(data ))
            logger.debug("Sending Packet... ")
            self.m3_ice.ice.mbus_send(mbus_memwr, data)

        time.sleep(0.1)


        # @TODO: add code here to verify the write? 

        #mbus_addr = struct.pack(">I", 0x00000013) 
        #read_req = struct.pack(">I",  0x0A000080) 
        #dma_addr = struct.pack(">I",  0x00000000) 
        #logger.debug("sending read req... ")
        #self.m3_ice.ice.mbus_send(mbus_addr, read_req + dma_addr)
        #time.sleep(0.1)
        
        # see above, just using RUN_CPU MBUS register again
        clear_data= struct.pack(">I", 0x10000001)  # 1 clears reset
        logger.debug("clearing RESET signal... ")
        self.m3_ice.ice.mbus_send(mbus_regwr, clear_data)
 

        logger.info("")
        logger.info("Programming complete.")
        logger.info("")

        return 
    

    def split_transmission( self, payload, chunk_size = 255):
        return [ payload[i:i+chunk_size] for i in \
                        range(0, len(payload), chunk_size) ]


    #
    #
    #
    def _cmd_debug_callback(self, *args, **kwargs):
        self._callback_queue.put((time.time(), args, kwargs))


    #
    #
    #
    def cmd_debug (self):
      
    
        #
        #
        #
        #
        #
        class MBusInterface:

            #
            #
            #
            def __init__(this, _ice, prc_addr):
                this.ice = _ice
                this.ice_addr = 0xe
                this.prc_addr = prc_addr

                logger.info("** Re-configuring ICE MBus to listen for "+\
                            "Debug Packets")
                this.ice.mbus_set_internal_reset(True)
                this.ice.mbus_set_snoop(False)
                this.ice.mbus_set_short_prefix( hex(this.ice_addr))
                this.ice.mbus_set_internal_reset(False)

                #register the callback
                this.callback_queue = Queue.Queue()
                this.ice.msg_handler['b++'] = this._callback
                #this.ice.msg_handler['B++'] = this._callback
 
                
          
            #
            #
            #
            def _callback(this,*args, **kwargs):
                this.callback_queue.put((time.time(), args, kwargs))
           
            #
            #
            #
            def read(this,):
                _d, [mbus_addr, mbus_data], _d = this.callback_queue.get()
                return [mbus_addr, mbus_data]
            #
            #
            #
            def read_mem(this,addr,size):

                logger.debug("Requesting " + hex(addr))
                assert( size in [32,16,8] )
                
                #first, find the 32-bit word around addr
                align32 = this._align32(addr,size)

                #third, form the request message
                logger.debug("Requesting the word @ " + hex(align32))
                prc_memrd = struct.pack(">I", ( this.prc_addr << 4) | 0x3 ) 
                memrd_reply = struct.pack(">I",  0xe0000000)
                memrd_addr = struct.pack(">I", align32) 
                memrd_resp_addr = struct.pack(">I", 0x00000000)
                this.ice.mbus_send(prc_memrd, 
                            memrd_reply + memrd_addr +  memrd_resp_addr )
               
                #fourth, wait for a response
                #FIXME: need to figure this out
                [mbus_addr, mbus_data]= this.read()
                [mbus_addr] = struct.unpack(">I", mbus_addr)
                [mem_addr, mem_data] = struct.unpack(">II", mbus_data)
                assert( mbus_addr == 0xe0)
                assert( mem_addr == 0x00000000)

                logger.debug( "Received: " + hex(align32) + " = " \
                                + hex(mem_data) )
                
                #fifth, split data back to requested size
                mask = 2 ** size - 1
                if size == 32: shift = 0
                elif size == 16: shift = 8*(addr & 0x02) 
                elif size == 8:  shift = 8*(addr & 0x03)

                mem_data = mem_data >> shift
                mem_data = mem_data & mask

                return mem_data

            #
            #
            #
            def write_mem(this, addr, value, size):
                
                logger.debug('Writing ' + hex(value) + ' to ' + hex(addr))
                
                assert(isinstance(addr, int))
                assert(isinstance(value, int))
                assert(size in [32,16,8])

                align32 = this._align32(addr,size)

                if size == 32:
                    write32 = value
                elif size == 16:
                    mask32 = ((2 ** size -1) << 8 * (addr & 0x02))
                    mask32n = 0xffffffff - mask32

                    orig32 = this.read_mem(align32,32)
                    value32 =  value << size | value # just duplicate it

                    write32 = orig32 & mask32n 
                    write32 = write32 | (value32 & mask32)
                elif size == 8:
                    assert(False and "Fixme Me!")
               
                logger.debug("Writing " + hex(write32) + " @ " + hex(align32))
                prc_memwr = struct.pack(">I", ( this.prc_addr << 4) | 0x2 ) 
                memwr_addr = struct.pack(">I", align32)  
                memwr_data = struct.pack(">I", write32)
                this.ice.mbus_send(prc_memwr, 
                    memwr_addr + memwr_data) 

            #
            #
            #
            def _align32(this,addr,size):

                align32 =  addr & 0xfffffffc

                if size == 32:
                    assert( align32 == ((addr + 3) & 0xfffffffc))
                elif size == 16:
                    assert( align32 == ((addr + 1) & 0xfffffffc))
                
                return align32


        #
        #
        #
        #
        #
        class Memory(object):
            
            #
            #
            #
            def __init__(this, mbus):
                assert( isinstance(mbus, MBusInterface))
                this.mbus = mbus

            #
            #
            #
            def __getitem__(this,key):
                addr = key[0]
                size = key[1]
                logger.debug("MemRd: (" + hex(addr) + ',' + str(size) + ')')
                assert( isinstance(addr, int))
                return this.mbus.read_mem(addr,size)

            #
            #
            #
            def __setitem__(this,key,val):
                logger.debug("MemWr: " + str(key) + ':' + str(val))
                addr = key[0]
                size = key[1]
                assert( isinstance(addr, int))
                assert( isinstance(val, int))
                this.mbus.write_mem(addr,val,size)
     
        #
        #
        #
        #
        #
        class RegFile(Memory):
            
            #
            #
            #
            def __init__(this, mbus, base_addr, writeback=False):
                super( RegFile, this).__init__(mbus)
                this.base_addr = base_addr 
                
                # specific ordering matching on-board gdb code
                this.names = [  'isr_lr', 'sp', 'r8', 'r9', 'r10', 'r11', 
                                'r4', 'r5', 'r6', 'r7', 'r0', 'r1', 'r2', 
                                'r3', 'r12', 'lr', 'pc', 'xpsr', ]
                this.offsets = dict( zip(this.names, 
                                    range(0, 4* len(this.names), 4))
                                  )
                this.writeback = writeback
                this.local =  {}                                
                

            #
            #
            #
            def __getitem__(this,key):
                logger.debug("RegRd: " + str(key))
                assert( key in this.names)
                mem_addr = this.base_addr + this.offsets[key]
                return Memory.__getitem__(this,(mem_addr,32))

            #
            #
            #
            def __setitem__(this,key,val):
                logger.debug("RegWr: " + str(key) + ':' + str(val))
                assert( key in this.names)
                assert( isinstance(val, int))

                if (this.writeback):
                    mem_addr = this.base_addr + this.offsets[key]
                    Memory.__setitem__(this,(key,32),val)
                else: 
                    this.local[key] = val
            
            #
            #
            #
            def getLocal(this, key):
                if key in this.local:
                    return this.local[key]
                else: return None
   
               

        #logger.info("Triggering MBUS internal reset")
        #self.m3_ice.ice.mbus_set_internal_reset(True)
        #self.m3_ice.ice.mbus_set_internal_reset(False)

        #pull prc_addr from command line
        # and convert to binary
        prc_addr = int(self.m3_ice.args.short_prefix, 16)


        if (prc_addr > 0x0 and prc_addr < 0xf):
            mbus_short_addr = (prc_addr << 4 | 0x02)
            mbus_addr = struct.pack(">I", mbus_short_addr)
        elif (prc_addr >= 0xf0000 and prc_addr < 0xfffff):
            raise Exception("Only short prefixes supported")
            #mbus_addr = struct.pack(">I", mbus_long_addr)
        else: raise Exception("Bad MBUS Addr")
     
        #bp()

        # create MBus Interface
        mbus = MBusInterface( self.m3_ice.ice, prc_addr) 

        # might not word aligned :(
        break_addr = int(self.m3_ice.args.DbgAddr, 16) 
        svc_01 = 0xdf01 # asm("SVC #01")

        while True: 
            logger.debug("DBG Requesting original instruction @" + \
                        hex(break_addr))
            orig_inst = mbus.read_mem( break_addr, 16)

            logger.info("DBG Inserting DBGpoint at " + hex(break_addr))
            mbus.write_mem( break_addr, svc_01, 16)

            logger.info("DBG Waiting for trigger")
            # read the gdb_flag pointer
            mbus_addr, mbus_data = mbus.read()

            [mbus_addr] = struct.unpack(">I", mbus_addr)
            assert( mbus_addr == 0xe0)
            [flag_addr ] = struct.unpack(">I", mbus_data)
            logger.info("DBGpoint triggered")
            logger.debug("DBG flag at: 0x" + hex(flag_addr))

            mbus_addr, mbus_data = mbus.read()
            [mbus_addr] = struct.unpack(">I", mbus_addr)
            assert( mbus_addr == 0xe0)
            [reg_addr ] = struct.unpack(">I", mbus_data)
            logger.debug("DBG regs at: 0x" + hex(reg_addr))

            # put the original instruction back
            logger.debug("DBG restoring origional instruction " +  \
                        hex(orig_inst)  + " at 0x" + hex( break_addr) )
            mbus.write_mem( break_addr, orig_inst, 16)

            logger.debug("DBG Soft-Stepping with Mulator")
            mem = Memory(mbus)
            rf = RegFile(mbus,reg_addr)
            from PyMulator.PyMulator import PyMulator
            mulator = PyMulator(rf,mem,debug=True)

            mulator.stepi()

            bp()
            npc = rf.getLocal('pc')

            # setup for the next breakpoint
            break_addr = npc

            # clear the gdb_flag
            logger.debug("DBG clearing flag @" + hex(flag_addr))
            mbus.write_mem(flag_addr, 0x01, 32)

        logger.info("")
        logger.info("Debugging complete.")
        logger.info("")

        return 
 



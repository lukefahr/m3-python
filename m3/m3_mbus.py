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
        
        _ice = self.m3_ice.ice
        
        self._callback_queue = Queue.Queue()
        _ice.msg_handler['b++'] = self._cmd_debug_callback

        regs = {    'isr_lr' : 0x0,     'sp' : 0x0,     'r8' : 0x0, 
                    'r9' : 0x0,         'r10' : 0x0,    'r11' : 0x0, 
                    'r4' : 0x0,         'r5' : 0x0,     'r6' : 0x0, 
                    'r7' : 0x0,         'r0' : 0x0,     'r1' : 0x0, 
                    'r2' : 0x0,         'r3' : 0x0,     'r12' : 0x0, 
                    'lr' : 0x0,         'pc' : 0x0,     'xPSR' : 0x0,
                }


        logger.info("** Setting ICE MBus controller to slave mode")
        self.m3_ice.ice.mbus_set_master_onoff(False)


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
       
        prc_memrd = struct.pack(">I", ( prc_addr << 4) | 0x3 ) 
        prc_memwr = struct.pack(">I", ( prc_addr << 4) | 0x2 ) 

        svc_01 = 0xdf01 # asm("SVC #01")

        break_addr = 0x41e # might not word aligned :(


        logger.info("** Re-configuring ICE MBus to listen for dbg packets")
        _ice.mbus_set_internal_reset(True)
        _ice.mbus_set_snoop(False)
        _ice.mbus_set_short_prefix( bin(int('0xe',16))[2:] )
        _ice.mbus_set_internal_reset(False)

        break_addr_high_nibble = True if (break_addr % 4) else False
        break_addr_align = break_addr & 0xfffffffc            
        
        logger.info("Inserting breakpoint at " + hex(break_addr))
        logger.debug("    which is the " + 
                        ("HIGH" if break_addr_high_nibble else "LOW") +
                        " nibble of the word: " + 
                        hex(break_addr_align)) 

        logger.debug("Requesting the word: @" + hex(break_addr_align))
        memrd_reply = struct.pack(">I",  0xe0000000)
        memrd_addr = struct.pack(">I", break_addr_align) 
        memrd_resp_addr = struct.pack(">I", 0x00000000)
        _ice.mbus_send(prc_memrd, memrd_reply + memrd_addr +  memrd_resp_addr )

        _dummy , [mbus_addr, mbus_data], _dummy = self._callback_queue.get()
        [mbus_addr] = struct.unpack(">I", mbus_addr)
        [mem_addr, mem_data] = struct.unpack(">II", mbus_data)
        assert( mbus_addr == 0xe0)
        assert( mem_addr == 0x00000000)
        
        logger.debug("Saving the word: " + hex(mem_data) + " @" + hex(break_addr_align))
        orig_mem_addr = memrd_addr
        orig_mem_data = mem_data

        # now we change it
        wr_addr = orig_mem_addr
        if (break_addr_high_nibble): # the endian-ness is backwards on x86
            wr_data = struct.pack(">I", (svc_01 << 16) | ( mem_data & 0xffff) )
        else:   # XXXX-svc01
            wr_data = struct.pack(">I", (mem_data &0xffff0000) |  (svc_01) )
        logger.debug("Updating the word: 0x" + binascii.hexlify(wr_data) + 
                        " @" + hex(break_addr_align))
        _ice.mbus_send(prc_memwr, wr_addr + wr_data)

        logger.info("waiting for DBG to trigger")
        # read the gdb_flag's memory address
        timestamp, [mbus_addr, mbus_data], kwargs = self._callback_queue.get()
        [mbus_addr] = struct.unpack(">I", mbus_addr)
        assert( mbus_addr == 0xe0)
        [mem_data] = struct.unpack(">I", mbus_data)
        logger.debug("DBG triggered, flag at: 0x" + hex(mem_data))

        #save the flag 
        flag_addr =  mem_data 

        # read the regs
        timestamp, [mbus_addr, mbus_data], kwargs = self._callback_queue.get()
        [mbus_addr] = struct.unpack(">I", mbus_addr)
        assert( mbus_addr == 0xe0)
        #print ( binascii.hexlify( mbus_data) )
        [ regs['isr_lr'], regs['sp'], regs['r8'],
          regs['r9'], regs['r10'], regs['r11'],
          regs['r4'], regs['r5'], regs['r6'],
          regs['r7'], regs['r0'], regs['r1'],
          regs['r2'], regs['r3'], regs['r12'],
          regs['lr'], regs['pc'], regs['xPSR'], ] = \
                                struct.unpack(">"+"I"*len(regs), mbus_data)
         
        reg_list = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                      'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc',
                        'isr_lr', 'xPSR', ]
        logger.info("DBG triggered, dumping registers")
        for reg in reg_list:
            logger.info(" reg: " + reg + ' : ' + hex(regs[reg]) )

        # put the original instruction back
        logger.debug("restoring origional word " +  hex(orig_mem_data)  + 
                    " at 0x" + binascii.hexlify( orig_mem_addr) )
        wr_orig_addr = orig_mem_addr
        wr_orig_data = struct.pack(">I", orig_mem_data)
        _ice.mbus_send(prc_memwr, wr_orig_addr + wr_orig_data)

        # clear the gdb_flag
        logger.debug("DBG clearing flag @" + hex(flag_addr))
        wr_flag_addr = struct.pack(">I", flag_addr)
        wr_flag_data = struct.pack(">I", 0x1) 
        _ice.mbus_send(prc_memwr, wr_flag_addr + wr_flag_data)


        logger.info("")
        logger.info("Debugging complete.")
        logger.info("")

        return 
 



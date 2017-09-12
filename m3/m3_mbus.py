#!/usr/bin/env python

#
# Code to allow the ICE board to interact with the PRC
# via MBUS
#
#
# Andrew Lukefahr
# lukefahr@indiana.edu
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
import logging
import os
import sys
import socket
import queue as Queue
import time
import threading
import multiprocessing

import struct

# if Py2K:
import imp

from . import __version__ 


from . import m3_logging
logger = m3_logging.getGlobalLogger()

 

#logging.basicConfig( level=logging.WARN, 
#                        format='%(levelname)s %(name)s: %(message)s')

class MBusInterface(object):
    
    class UnalignedException(Exception): pass
    class MBusInterfaceException(Exception): pass

    '''
    A class to wrap MBus into simple read/write commands
    '''

    #
    def __init__(this, _ice, prc_addr, log_level = logging.WARN):
        this.ice = _ice
        this.ice_addr = 0xe

        if (prc_addr > 0x0 and prc_addr < 0xf):
            this.prc_addr = prc_addr
        elif (prc_addr >= 0xf0000 and prc_addr < 0xfffff):
            raise MBusInterfaceException("Only short prefixes supported")
        else: raise MBusInterfaceException("Bad MBUS Addr")

        this.log = m3_logging.get_logger( type(this).__name__)
        this.log.setLevel(log_level)

        this.log.info("MBUS Re-configuring ICE MBus to listen for "+\
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
    def _callback(this,*args, **kwargs):
        this.callback_queue.put((time.time(), args, kwargs))
   
    #
    def read(this):
        while True:
            try:
                _, [mbus_addr, mbus_data], _ = this.callback_queue.get(True,10)
                return [mbus_addr, mbus_data]
            except Queue.Empty:  continue

    #
    def read_mem(this,addr,size):
        this.log.debug("MBUS Requesting " + hex(addr))
        
        #first, find the 32-bit word around addr
        align32 = this._align32(addr,size)

        #third, form the request message
        this.log.debug("MBUS Requesting the full word @ " + hex(align32))
        prc_memrd = struct.pack(">I", ( this.prc_addr << 4) | 0x3 ) 
        memrd_reply = struct.pack(">I",  0xe1000000)
        memrd_addr = struct.pack(">I", align32) 
        memrd_resp_addr = struct.pack(">I", 0x00000000)
        this.ice.mbus_send(prc_memrd, 
                    memrd_reply + memrd_addr +  memrd_resp_addr )
        this.log.debug("MBUS Request sent")

        #fourth, wait for a response
        while True: 
            [mbus_addr, mbus_data]= this.read()
            [mbus_addr] = struct.unpack(">I", mbus_addr)
            if (mbus_addr == 0xe1):
                [mem_addr, mem_data] = struct.unpack(">II", mbus_data)
                assert( mem_addr == 0x00000000)
                break
            else: 
                this.log.debug('Found non-debug MBUS message:' + \
                        hex(mbus_addr) + ' ' + str(repr(mbus_data)))
                continue # try again

        this.log.debug( "MBUS Received: " + hex(align32) + " = " \
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
    def write_mem(this, addr, value, size):
        
        this.log.debug('MBUS Writing ' + hex(value) + ' to ' + hex(addr))
        
        assert(isinstance(addr, int))
        assert(isinstance(value, int))
        assert(size in [32,16,8])

        align32 = this._align32(addr,size)

        if size == 32:
            write32 = value

        elif size == 16:
            byte_idx = addr & 0x02
            mask32 = ((2 ** size -1) << (8 * byte_idx))
            mask32n = 0xffffffff - mask32 # bitwise not hack

            orig32 = this.read_mem(align32,32)
            value32 =  value << size | value # just duplicate it
            value32 = value32 & mask32 # and mask it

            write32 = orig32 & mask32n 
            write32 = write32 | value32

        elif size == 8:
            byte_idx = addr & 0x3
            mask32 = ((2 ** size -1) << (8 * byte_idx))
            mask32n = 0xffffffff - mask32 # bitwise not hack
            
            orig32 = this.read_mem(align32,32)
            value32 = (value << (8 * byte_idx)) 
            value32 = value32 & mask32

            write32 = orig32 & mask32n
            write32 = write32 | value32

        this.log.debug("MBUS Writing " + hex(write32) + " @ " + \
                hex(align32))
        prc_memwr = struct.pack(">I", ( this.prc_addr << 4) | 0x2 ) 
        memwr_addr = struct.pack(">I", align32)  
        memwr_data = struct.pack(">I", write32)
        this.ice.mbus_send(prc_memwr, 
            memwr_addr + memwr_data) 
    
    #
    def write_reg(this, reg, val):

        this.log.debug('MBUS: writing register: ' + str(reg) + '=' + hex(val) )
        assert( reg < 8)
        assert( val < ((2 ** 24) -1) )

        mbus_regwr = struct.pack(">I", ( this.prc_addr << 4) | 0x0 ) 
        data = struct.pack(">I", reg << 24 | val )
        this.ice.mbus_send(mbus_regwr, data)


    #
    def _align32(this,addr,size):

        align32 =  addr & 0xfffffffc

        if size == 32:
            if not ( align32 == ((addr + 3) & 0xfffffffc)):
                raise this.UnalignedException()
        elif size == 16:
            if not ( align32 == ((addr + 1) & 0xfffffffc)):
                raise this.UnalignedException()
        
        return align32


#
class Memory(object):
    '''
    Allows dictionary-like access to the M3's memory
    '''
    
    #
    def __init__(this, mbus, writeback=False, log_level = logging.WARN):
        assert( isinstance(mbus, MBusInterface))
        this.mbus = mbus
        this.writeback = writeback
        this.local = {}

        this.log = m3_logging.get_logger( type(this).__name__)
        this.log.setLevel(log_level)

    #
    def __getitem__(this,key):
        addr = key[0]
        size = key[1]
        this.log.debug("MemRd: (" + hex(addr) + ',' + str(size) + ')')
        assert( isinstance(addr, int))
        try:
            return this.mbus.read_mem(addr,size)
        except this.mbus.UnalignedException: 
            # looks like we do it the hard way
            this.log.debug('MemRd: unaligned access')
            assert( size in [32,16] )
            val = 0
            while size > 0:
                tval = this.mbus.read_mem(addr,8)
                assert(tval <= 0xff)
                val = val << 8 | tval 
                size -= 8
            return val

    #
    def __setitem__(this,key,val):
        '''
        note: by default this only caches updates locally
        '''
        this.log.debug("MemWr: " + str(key) + ':' + str(val))
        addr = key[0]
        size = key[1]
        assert( isinstance(addr, int))
        assert( isinstance(val, int))
        if this.writeback:
            this.mbus.write_mem(addr,val,size)
        else:
            this.local[key] = val # not the best, but ehh

    #
    def forceWrite(this,key,val):
        '''
        Always writes through to MBUS
        '''
        this.log.debug("fored-write: " + str(key) + ':' + str(val))
        addr = key[0]
        size = key[1]
        assert( isinstance(addr, int))
        assert( isinstance(val, int))
        this.mbus.write_mem(addr,val,size)



#
class RegFile(Memory):
    '''
    Allows dictionary-like access to the M3's registers
    '''
    
    #
    def __init__(this, mbus, base_addr, writeback=False, \
                                        log_level = logging.WARN):
        '''
        note: base_addr will need to be updated every time
        '''
        super( RegFile, this).__init__(mbus)
        this.base_addr = base_addr 

        this.log = m3_logging.get_logger( type(this).__name__)
        this.log.setLevel(log_level)
        
        # specific ordering matching on-board gdb code
        this.names = [  'isr_lr', 'sp', 'r8', 'r9', 'r10', 'r11', 
                        'r4', 'r5', 'r6', 'r7', 'r0', 'r1', 'r2', 
                        'r3', 'r12', 'lr', 'pc', 'xpsr', ]
        this.trans_names = { 'r13': 'sp', 'r14':'lr', 'r15':'pc'}
        # The M0 does not include floating-point registers
        this.warn_names = [ 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 
                            'fps', ]
        this.warn_trans_names = { 'cpsr':'xpsr' }                            
        this.offsets = dict( zip(this.names, 
                            range(0, 4* len(this.names), 4))
                          )
        this.writeback = writeback
        this.local =  {}                                
        
    #
    def update_base_addr(this, base_addr):
        '''
        used to update the base pointer of the register file
        '''
        this.log.debug('Update Base Addr: ' + hex(base_addr))
        this.base_addr = base_addr
        this.local = {} # clear local reg cache

    #
    def __getitem__(this,key):
        # just pretend all fp regs are zero
        if key in this.warn_names:
            this.log.warn('Reading: ' + str(key) + ' as 0')
            return 0
        elif key in this.warn_trans_names:
            this.log.warning('Reading ' + str(this.warn_trans_names[key]) + \
                            ' in place of ' + str(key))
            key = this.warn_trans_names[key] 
        elif key in this.trans_names:
            key = this.trans_names[key]

        assert( key in this.names)
        mem_addr = this.base_addr + this.offsets[key]
        val = this.mbus.read_mem(mem_addr,32)
        # ARM pc reads return pc + 4 (it's wierd)
        if key == 'pc': 
            val += 4
            this.log.debug("RegRd: pc(+4) " + hex(val))
        else: 
            this.log.debug("RegRd: " + str(key) + " " + hex(val))
        return val

    #
    def __setitem__(this,key,val):
        '''
        note: by default this only caches updates locally
        '''
        this.log.debug("RegWr: " + str(key) + ':' + hex(val))

        if key in this.warn_names:
            this.log.warn('Writing: ' + str(key) + ' as 0')
            return 0
        elif key in this.warn_trans_names:
            this.log.warning('Writing' + str(this.warn_trans_names[key]) + \
                            ' in place of ' + str(key))
            key = this.warn_trans_names[key] 
        elif key in this.trans_names:
            key = this.trans_names[key]

        assert( key in this.names)
        assert( isinstance(val, int))

        if (this.writeback):
            mem_addr = this.base_addr + this.offsets[key]
            this.mbus.write_mem(mem_addr,val,32)
        else: 
            this.local[key] = val

    #
    def forceWrite(this,key,val):
        '''
        Always writes through to MBUS
        '''
        this.log.debug("fored-write: " + str(key) + ':' + str(val))
        assert( key in this.names)
        mem_addr = this.base_addr + this.offsets[key]
        this.mbus.write_mem(mem_addr,val,32)

    #
    def getLocal(this, key):
        if key in this.local:
            if key == 'pc': #ARM pc reg is wierd
                return this.local[key] + 4
            else:
                return this.local[key]
        else: return None





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

        self.parser_gdb = self.subparsers.add_parser('gdb',
                help = 'Debug the PRC via GDB')
        self.parser_gdb.add_argument('-p', '--short-prefix',
                help="The short MBUS address of the PRC, e.g. 0x1",
                default=mbus_controller.DEFAULT_PRC_PREFIX,
                )
        self.parser_gdb.add_argument('--port',
                help="The TCP port GDBServer should bind to",
                default='10001'
                )
        self.parser_gdb.add_argument('--input-mode',
                help="Where should we look for input: \n"\
                     "'gdb': start a gdbserver remote on --port,\n"
                     "'direct': accept gdbserver commands directly from stdin",
                default='gdb'
                )


        self.parser_gdb.set_defaults(func=self.cmd_gdb)


    def cmd_program(self):
        '''
        Programs the PRC over MBUS
        '''

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
        payload_chunks = [ datafile[i:i+chunk_size_bytes] for i in \
                        range(0, len(datafile), chunk_size_bytes) ]
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

        # see above, just using RUN_CPU MBUS register again
        clear_data= struct.pack(">I", 0x10000001)  # 1 clears reset
        logger.debug("clearing RESET signal... ")
        self.m3_ice.ice.mbus_send(mbus_regwr, clear_data)
 
        logger.info("")
        logger.info("Programming complete.")
        logger.info("")

        return 
    



   
    #
    #
    #

    #
    #
    #
    def cmd_gdb(self):
      
        class GdbCtrl(object):
            '''
            The backend controller that impliments the GDB commands
            '''

            class PrcMBusInterface(MBusInterface):
                # this will get used later
                def _callback(this,*args, **kwargs):
                    this.callback_queue.put((time.time(), args, kwargs))

            def __init__(this, ice, prc_addr, log_level = logging.WARN):

                # setup our log
                this.log = m3_logging.get_logger( type(this).__name__)
                this.log.setLevel(log_level)

                this.mbus = this.PrcMBusInterface( ice, prc_addr, log_level)
                this.mem = Memory(this.mbus, writeback=False, \
                                        log_level=log_level)
                this.rf = RegFile(this.mbus,None,writeback=False, \
                                        log_level=log_level)

                this.flag_addr = None

                this.svc_01 = 0xdf01 # asm("SVC #01")
                # were displaced instructions live
                # these have the form { (addr,size) : inst }
                this.displaced_insts = {} 

                try:
                    from PyMulator.PyMulator import PyMulator
                    this.mulator = PyMulator(this.rf, this.mem,debug=True)
                except:  
                    this.log.warn('='*40 + '\n' + \
                                 '\tPyMulator not found\n' +\
                                 '\tSingle-stepping will not work!\n' + \
                                 '='*40)

                this.regs = [   'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 
                                'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 
                                'lr', 'pc', 
                                'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',                                 'fps', 
                                'xpsr', ]
                this.regsPads= { 'r0':0, 'r1':0, 'r2':0, 'r3':0, 'r4':0, 
                                'r5':0, 'r6':0, 'r7':0, 'r8':0, 'r9':0, 
                                'r10':0, 'r11':0, 'r12':0, 'sp':0, 'lr':0, 
                                'pc':0, 
                                'f0':8, 'f1':8, 'f2':8, 'f3':8, 'f4':8, 
                                'f5':8, 'f6':8, 'f7':8, 'fps':0, 
                                'xpsr':0, }


                this.encode_str = { 4:'<I', 2:'<H', 1:'<B' }

            def cmd__question_(this,):
                this.log.info("? Cmd")
                assert(this.flag_addr != None)
                return 'S05'

            def cmd__ctrlc_(this,):
                this.log.info("CTRL+C (HALT)")

                if this.flag_addr != None:
                    raise Exception("PRC already halted")

                this.mbus.write_reg( 0x7, 0x1) # write something to MBUS_R7

                this.log.debug("waiting for HALT to trigger... ")
                this._wait_for_flag()

            def cmd_M(this, subcmd):
                preamble, data = subcmd.split(':')
                addr,size_bytes= preamble.split(',')
                addr,size_bytes = map(lambda x: int(x, 16), [addr, size_bytes])
                this.log.info('mem write: ' + hex(addr) + ' of ' + str(size_bytes))
                data = binascii.unhexlify(data) 
                
                while size_bytes > 0:
                    this.log.debug('Writing ' + repr(data[0]) + ' to ' \
                        + hex(addr))

                    #this is not the most efficient, but it works...
                    this.mem.forceWrite((addr,8), data[0])

                    size_bytes -= 1
                    addr += 1
                    data = data[1:]
                return 'OK'

            def cmd_P(this, subcmd):
                reg,val = subcmd.split('=')
                reg = int(reg, 16)
                reg = this.regs[ reg]
                # fix endiananess, conver to int
                val = int(binascii.hexlify( binascii.unhexlify(val)[::-1]),16)
                this.log.warn('register write :' + str(reg) + ' = ' + hex(val) )
                this.rf.forceWrite(reg,val)
                return "OK"

            def cmd_X(this, subcmd):
                this.log.info("Binary Memory Write not supported.")
                return ""

            def cmd_Z(this, subcmd):
                this.log.info("Breakpoint Set")
                args = subcmd.split(',')
                brType, addr, size = map(lambda x: int(x,16), args)
                assert(brType == 0)
                assert(size == 2)
                this.log.info("Replacing instruction @" + \
                                hex(addr) + " with trap" )
                size *= 8 # convert to bits
                if (addr,size) in this.displaced_insts: 
                    this.log.info( hex(addr) + '('+str(size)+')' + \
                        'already a soft-breakpoint')
                else:
                    this.displaced_insts[(addr,size)] = \
                            this.mbus.read_mem( addr, size)
                    this.mbus.write_mem( addr, this.svc_01, 16)
                return 'OK'


            def cmd_c(this):
                this.log.info("continue")
                assert(this.flag_addr != None)
                
                this._clear_flag()
                this.log.debug("waiting for something to trigger... ")
                this._wait_for_flag()
                return "S05"


            def cmd_g(this, ):
                this.log.info('read all regs')
                assert(this.flag_addr != None)

                resp = ''
                for ix in range(0, len(this.regs)):
                    val = this.cmd_p( this.regs[ix] )
                    resp += val
                return resp

            def cmd_k(this):
                this.log.info("kill")
                this.log.warn('Caught Kill Command, doing nothing')

            def cmd_m(this, subcmd):
                args = subcmd.split(',')
                addr,size_bytes = map(lambda x: int(x, 16), args)

                this.log.info('mem read: ' + hex(addr) + ' of ' + \
                                    str(size_bytes))
                assert(this.flag_addr != None)

                resp = '' 
                while size_bytes > 0:
                    read_bytes = 4 if size_bytes >4 else size_bytes
                    encode_str = this.encode_str[read_bytes]
                    val = this.mem[(addr,read_bytes * 8)]
                    val = struct.pack(encode_str, val).encode('hex')#lit endian
                    resp += val
                    addr += read_bytes
                    size_bytes -= read_bytes
                return resp

                        
            def cmd_p(this, subcmd):
                reg = subcmd
                this.log.info('reg read: ' + str(reg))
                assert(this.flag_addr != None)
                encode = this.encode_str[4]

                val = this.rf[reg]
                if reg == 'pc': val -= 4
                val = struct.pack(encode ,val).encode('hex') #lit endian 
                val = '00' * this.regsPads[reg] + val # add some front-padding
                return val

            def cmd_q(this, subcmd):
                this.log.info('Query')
                if subcmd.startswith('C'):
                    # asking about current thread, 
                    # again, what threads...
                    return ""
                elif subcmd.startswith('fThreadInfo'):
                    # info on threads? what threads?
                    return ""
                elif subcmd.startswith('L'):
                    # legacy form of fThreadInfo
                    return ""
                elif subcmd.startswith('Attached'):
                    # did we attach to a process, or spawn a new one
                    # processes?
                    return ""
                elif subcmd.startswith('Offsets'):
                    # did we translate the sections vith virtual memory?
                    # virtual memory?
                    return ""
                elif subcmd.startswith('Supported'):
                    # startup command
                    this.log.debug('qSupported')
                    return "PacketSize=4096"
                elif subcmd.startswith('Symbol'):
                    # gdb is offering us the symbol table
                    return "OK"
                elif subcmd.startswith('TStatus'):
                    #this has to do with tracing, we're not handling that yet
                    return ""
                else: raise this.UnsupportedException( subcmd)
               
            def cmd_s(this, ):
                this.log.info('single-step ')
                assert(this.flag_addr != None)

                # might have to temporarially replace a trap
                displaced_trap = False
                pc = this.rf['pc'] - 4
                
                if (pc,16) in this.displaced_insts:
                    this.log.debug("Trap @ " + hex(pc) + \
                            ", but we need the inst, fixing...")
                    this.cmd_z('0,' + hex(pc)[2:] + ',2')
                    displaced_trap = True

                # if flag_addr is set, the reg file is valid 
                if True:
                    this.log.debug("Soft-Stepping with Mulator")
                    this.mulator.stepi()
                    break_addr = this.rf.getLocal('pc') - 4
                    this.log.debug("Next PC: " + hex(break_addr) )
               
                # insert soft-trap at next instruction
                this.cmd_Z('0,' + hex(break_addr)[2:] + ',2')
                
                #step to the soft-trap
                this.log.debug("Waiting for trigger")
                this._clear_flag() 
                this._wait_for_flag()
                
                #fix the next instruction
                this.cmd_z('0,' + hex(break_addr)[2:] + ',2')
                #and the orig inst
                if displaced_trap:
                    this.cmd_Z('0,' + hex(pc)[2:] + ',2')

                return 'S05'

            def cmd_v(this, subcmd):
                this.log.info('v command')
                assert(this.flag_addr != None)
                if subcmd.startswith('Cont?'):
                    this.log.debug('vCont')
                    return "vCont;cs"
                else: assert(False) 

            def cmd_z(this, subcmd):
                this.log.info("Breakpoint Clear")
                args = subcmd.split(',')
                brType, addr, size = map(lambda x: int(x,16), args)
                assert(brType == 0)
                assert(size == 2)
                this.log.info("Replacing trap with origional instruction @" +\
                                hex(addr) )
                size *= 8 # convert to bites                                
                if (addr,size) not in this.displaced_insts:
                    this.log.info( hex(addr) + '('+str(size)+')' + \
                        'not a soft-breakpoint')
                else:
                    orig_inst = this.displaced_insts[(addr,size)]
                    this.mbus.write_mem( addr, orig_inst, size)
                    del this.displaced_insts[(addr,size)]
                return 'OK'

            def _clear_flag(this,):
                this.log.debug("clearing flag @" + hex(this.flag_addr))
                this.mbus.write_mem(this.flag_addr, 0x01, 32)
                this.flag_addr = None
 
            def _wait_for_flag(this,timeout=None):
                assert( this.flag_addr == None)

                # read the gdb_flag and register pointer
                mbus_addr, mbus_data = this.mbus.read()
                [mbus_addr] = struct.unpack(">I", mbus_addr)
                assert( mbus_addr == 0xe0)
                [flag_addr ] = struct.unpack(">I", mbus_data)
                this.log.debug("flag triggered")
                this.log.debug("flag at: " + hex(flag_addr))
                this.flag_addr = flag_addr

                mbus_addr, mbus_data = this.mbus.read()
                [mbus_addr] = struct.unpack(">I", mbus_addr)
                assert( mbus_addr == 0xe0)
                [reg_addr ] = struct.unpack(">I", mbus_data)
                this.log.debug("updating regFile at: " + hex(reg_addr))
                this.rf.update_base_addr(reg_addr)
 
        class InputManager(object):
            '''
            Alternate frontend that skips GDB and 
            processes commands straight form stdin
            '''
            def run(this): pass
            def get(this):
                s = raw_input("<: ")
                if len(s) == 1:
                    return s[0], (), {}
                elif s[0] == '_':
                    return s, (), {}
                else:
                    return s[0], (s[1:]), {}
            def put(this, msg):
                print (">: " + str(msg) )

        #pull prc_addr from command line
        # and convert to binary
        prc_addr = int(self.m3_ice.args.short_prefix, 16)
   
        #determin current logging level
        dbgLvl = m3_logging.logger.getEffectiveLevel()

        print ("Manually setting debug for this module")
        dbgLvl = logging.DEBUG 

        #parse command line args
        port =  int(self.m3_ice.args.port)
        input_mode = self.m3_ice.args.input_mode.lower()

        if input_mode == 'gdb':
            # gdb interface
            from . import m3_gdb
            interface= m3_gdb.GdbRemote(tcp_port = port , log_level = dbgLvl )
        elif input_mode == 'direct':
            interface = InputManager()
        else: raise Exception('Unsupported input_mode' + \
                        str(self.m3_ice.args.input_mode) )

        #try: # create and start our gdb thread
        #except m3_gdb.GdbRemote.PortTakenException:
        #    logger.warn("Using Alternative Port: " + str(10002))
        #    interface= m3_gdb.GdbRemote(tcp_port = 10002, 
        #                log_level = log_level)

        # create MBus Interface
        ctrl = GdbCtrl( self.m3_ice.ice, prc_addr, log_level = dbgLvl)

        # @todo
        # this will need a more advanced threading model at some point
        # to process a CTRL+C  while waiting on continue
        # currently, we interpret CTRL+C as terminate

        logger.debug ("GDB main loop")
        interface.run()                                        
        while (True):
            cmd, args, kwargs = interface.get()
            cmd = 'cmd_'+cmd

            if cmd == 'cmd__quit_': 
                logger.info('GDB CTRL Quiting')
                break
            else : 
                func = getattr(ctrl, cmd)
                ret = func(*args, **kwargs)
                if ret != None: interface.put(ret)


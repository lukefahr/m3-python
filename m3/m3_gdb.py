#
#
# Andrew Lukefahr
# lukefahr@umich.edu
#
#

import binascii
import logging
import os
import queue 
import socket
import struct
import sys
import threading

#inspired by
# https://github.com/0vercl0k/ollydbg2-python/blob/master/samples/gdbserver/gdbserver.py#L147

try: from . import m3_logging
except ValueError: import logging as m3_logging

class GdbRemote(object):

    class UnsupportedException(Exception): pass
    class PortTakenException(Exception): pass
    class DisconnectException(Exception): pass
    class CtrlCException(Exception): pass

    def __init__(this, tcp_port = 10001, log_level = logging.WARN):
        
        # setup our log
        this.log = m3_logging.getLogger( type(this).__name__)
        this.log.setLevel(log_level)
        
        #open our tcp/ip socket
        this.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM)

        #Bind socket to local host and port
        assert( isinstance(tcp_port,int) )
        try:
            this.sock.bind( ('localhost', tcp_port) )
        except socket.error as msg:
            this.log.error('Bind failed. Error Code : ' + \
                            str(msg[0]) + ' Message ' + msg[1] )
            raise this.PortTakenException()

        this.log.info( 'Bound to port: ' + str(tcp_port))
        
        # inter-thread queues
        this.respQ = queue.Queue()
        this.reqQ = queue.Queue()

        # https://opensource.apple.com/source/gdb/gdb-1469/src/gdb/arm-tdep.c.auto.html        
        this.regs = [   'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 
                        'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc', 
                        'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'fps', 
                        'cpsr', ]
        this.regsPads= { 'r0':0, 'r1':0, 'r2':0, 'r3':0, 'r4':0, 'r5':0, 
                        'r6':0, 'r7':0, 'r8':0, 'r9':0, 'r10':0, 'r11':0, 
                        'r12':0, 'sp':0, 'lr':0, 'pc':0, 
                        'f0':8, 'f1':8, 'f2':8, 'f3':8, 'f4':8, 'f5':8, 'f6':8, 
                        'f7':8, 'fps':0, 
                        'cpsr':0, }

    def get(this,):
        while True:
            try: return this.reqQ.get(True, 10)
            except queue.Empty: pass

    def put(this,msg):
        this.respQ.put(msg)

    def _gdbPut(this, cmd, *args, **kwargs):
        this.reqQ.put( (cmd, args, kwargs) )
    
    def _gdbGet(this, timeout=None):
        ztime = 10 if timeout == None else timeout
        while True:
            try: return this.respQ.get(True, ztime)
            except queue.Empty: 
                if timeout == None: continue
                else: return None
    
    def run(this,): 
        this.RxTid = threading.Thread( target=this._gdb_rx, )
        this.RxTid.daemon = True
        this.RxTid.start()
        this.log.debug("Started GDB Thread")
        
    #
    # Internal Thread's main loop
    #
    def _gdb_rx(this):

        this.sock.listen(1) #not sure why 1
        
        while True:
            [conn, client] = this.sock.accept()
            this.log.info('New connection from: ' + str(client[0]))
            
            #grab the opening '+'
            this.log.debug('Grabbing opening +')
            plus = conn.recv(1)
            assert(plus == '+')

            # start a response thread
            TxTid = threading.Thread( target=this._gdb_tx, args=(conn,) )
            TxTid.daemon = True
            TxTid.start()

            try:
                while True:
                    msg  = this._gdb_recv( conn)
                    if msg: 
                        this._process_command(msg)

            except this.DisconnectException: 
                this.log.info('Closing connection with: ' + str(client[0]))
                conn.close()
                this._gdbPut('CTRL_QUIT')
                this.put('GDB_QUIT')
                TxTid.join()
            except this.CtrlCException:
                this.log.info('Caught CTRL+C')
                this.log.info('Closing connection with: ' + str(client[0]))
                conn.close()
                this._gdbPut('CTRL_QUIT')
                this.put('GDB_QUIT')
                TxTid.join()

    #
    #
    #
    def _gdb_tx(this, conn):
        while True:
            msg = this._gdbGet()
            if msg == 'GDB_QUIT': 
                return
            elif msg == '+':
                this.log.debug('TX: ' + str(msg))
                conn.send(msg)
            else:
                this._gdb_resp(conn, msg) 

    #
    #
    #
    def _process_command(this,cmd):
        
        assert(len(cmd) > 0)

        cmdType = cmd[0]
        subCmd = cmd[1:]
       
        if cmdType == '+': return
        if cmdType == '?': 
            this._process_Question()
        elif cmdType in [ 'D', 'c', 'k', 'g', 's' ]: 
            this._gdbPut(cmdType)
        elif cmdType in [ 'Z', 'm', 'p', 'q', 'v', 'z' ]: 
            this._gdbPut(cmdType, subCmd)
        elif cmdType in [ 'H', ]: 
            this._unsupported(cmdType, subCmd)
        else: raise this.UnsupportedException( cmdType)

    #
    #
    #
    def _process_Question(this):
        this.log.debug('? command')
        this._gdbPut('_ctrlc_')
        this._gdbPut('_question_')



    #
    #
    #
    def _unsupported(this, cmdType, subCmd):
        this.log.info("unsupported Type:" + str(cmdType))
        this.log.debug("SubCommand:" + str(subCmd))
        this.put("") #by-pass control thread

    
    
    #
    #
    #
    def _gdb_recv(this, conn):
    
        while True:
            rawdata= conn.recv(1024)
                    
            if not rawdata:
                raise this.DisconnectException()

            this.log.debug('RX: ' + str(rawdata) ) 

            # CTRL+C
            if chr(0x03) in rawdata:
                raise this.CtrlCException()
            
                # static buffer to tack on the new data
            # (plus fun way to make a static-ish function variable)
            try: this._buf_data += rawdata
            except AttributeError: this._buf_data = rawdata

            # acks "+" at the beginning can be safely removed
            if this._buf_data[0] == '+':
                this._buf_data= this._buf_data[1:]
        
            msg = None
            
            chkIdx = this._buf_data.find('#')
            # look for a checksum marker + 2 checksum bytes
            if (chkIdx > 0) and (len(this._buf_data) >= chkIdx + 3):
                #this.log.debug('Found # at: ' + str(chkIdx) )

                # get the message and checksum
                assert(this._buf_data[0] == '$')
                msg = this._buf_data[1:chkIdx]
                msgSum = int(this._buf_data[chkIdx+1:chkIdx+3],16)

                calcSum= 0
                for byte in msg:
                    calcSum = (calcSum + ord(byte)) & 0xff

                if calcSum != msgSum:
                    raise Exception("Checksum Error")
                else:
                    #this.log.debug('Checksum pass')
                    pass
                
                if '}' in msg:
                    raise Exception("FIXME: escape sequence")

                this._buf_data = this._buf_data[chkIdx+3:]

                this.log.debug('Parsed message : ' + str(msg) ) 
                #this.log.debug('Advanced buffered data: ' + \
                    # str(this._buf_data) ) 

                #ack message
                this.put('+') # bypass CTRL 

            return msg

    #
    #
    #
    def _gdb_resp(this, conn, msg):
        # calc checksum
        chkSum = 0
        for c in msg:
            chkSum += ord(c)
        chkSum = chkSum & 0xff
        
        if '}' in msg:
            raise Exception("FIXME: escape sequence")

        gdb_msg = '$%s#%.2x' % (msg, chkSum)
       
        this.log.debug('TX: ' + str(gdb_msg))
        conn.send( gdb_msg )

   
#
#
#
class testing_gdb_ctrl(object):
    
    def __init__(this):

        this.log = m3_logging.getLogger( type(this).__name__)
        this.log.setLevel(logging.DEBUG)
        this.regs = [   'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 
                        'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc', 
                        'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'fps', 
                        'cpsr', ]
        this.regsPads= { 'r0':0, 'r1':0, 'r2':0, 'r3':0, 'r4':0, 'r5':0, 
                        'r6':0, 'r7':0, 'r8':0, 'r9':0, 'r10':0, 'r11':0, 
                        'r12':0, 'sp':0, 'lr':0, 'pc':0, 
                        'f0':8, 'f1':8, 'f2':8, 'f3':8, 'f4':8, 'f5':8, 'f6':8, 
                        'f7':8, 'fps':0, 
                        'cpsr':0, }

    def cmd__question_(this,):
        this.log.info("? Cmd")
        return 'S05'

    def cmd__ctrlc_(this,):
        this.log.info("CTRL+C (HALT)")

    def cmd_Z(this, subcmd):
        zType,addr,size= subcmd.split(',')
        this.log.info('breakpoint set: ' + addr + 'type: ' + zType )
        return 'OK'

    def cmd_c(this):
        this.log.info("continue")

    def cmd_g(this, ):
        this.log.debug('Read all Regs')
        resp = ''
        for ix in range(0, len(this.regs)):
            val = this.cmd_p( this.regs[ix] )
            resp += val
        return resp

    def cmd_m(this, subcmd):
        addr,size_bytes= subcmd.split(',')
        addr,size_bytes = map(lambda x: int(x, 16), [addr, size_bytes])
        this.log.info('mem read: ' + hex(addr) + ' of ' + str(size_bytes))
        if size_bytes == 4:
            return struct.pack('<I',0x46c046c0).encode('hex') #lit endian hex
        else: 
            return struct.pack('<H',0x46c).encode('hex') #lit endian hex
                
    def cmd_p(this, subcmd):
        reg = subcmd
        this.log.info('reg_read: ' + str(reg))
        val = 0x1234
        val = struct.pack('<I',val).encode('hex') #lit endian hex
        val = '00' * this.regsPads[reg] + val # add some front-padding
        return val

    def cmd_q(this, subcmd):
        this.log.debug('Query')
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
        return 'S05'
    
    def cmd_v(this, subcmd):
        if subcmd.startswith('Cont?'):
            this.log.debug('vCont')
            return "vCont;cs"
        else: assert(False) 

    def cmd_z(this, subcmd):
        ztype,addr,size= subcmd.split(',')
        this.log.info('breakpoint clear: ' + (addr))
        return 'OK'


if __name__ == '__main__':
   
    logging.basicConfig( level=logging.WARN, 
                            format='%(levelname)s %(name)s %(message)s')

    port = 10001

    if (len(sys.argv) > 1):
        for arg in sys.argv:
            if '--port=' in arg:
               port = int(arg.split("=")[1])
               print 'set port=' + str(port)

    ctrl = testing_gdb_ctrl()
    gdb = GdbRemote( tcp_port=port, log_level = logging.DEBUG)
    gdb.run()

    while True: 
        cmd, args, kwargs = gdb.get()
        cmd = 'cmd_'+cmd

        if cmd == 'cmd_CTRL_QUIT': 
            print ('GDB CTRL Quiting')
            break
        else : 
            func = getattr(ctrl, cmd)
            ret = func(*args, **kwargs)
            if ret != None: gdb.put(ret)


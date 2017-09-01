#
#
# Andrew Lukefahr
# lukefahr@umich.edu
#
#

import binascii
import logging
import os
import socket
import struct
import sys

#inspired by
# https://github.com/0vercl0k/ollydbg2-python/blob/master/samples/gdbserver/gdbserver.py#L147


class GdbRemote(object):

    class GdbRemoteException(Exception):
        pass
    class DisconnectException(Exception):
        pass
    class CtrlCException(Exception):
        pass

    def __init__(this, callback, tcp_port = 10001, log_level = logging.WARN):
        
        # setup our log
        this.log = logging.getLogger(type(this).__name__)
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
            raise this.GdbRemoteException()

        this.log.info( 'Listening on port: ' + str(tcp_port))
        this.sock.listen(1) #not sure why 1

        #remember the callback function
        this.callback = callback
       
        # https://opensource.apple.com/source/gdb/gdb-1469/src/gdb/arm-tdep.c.auto.html        
        this.regs = [ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", 
                     "r9", "r10", "r11", "r12", "sp", "lr", "pc", 
                     "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "fps",
                     "cpsr", ]

    def run(this):
        
        while True:
            [conn, client] = this.sock.accept()
            this.log.info('New connection from: ' + str(client[0]))
            
            #grab the opening '+'
            this.log.debug('Grabbing opening +')
            plus = conn.recv(1)
            assert(plus == '+')

            this.callback('HALT')
            try:
                while True:
                    msg  = this._gdb_recv( conn)

                    resp = this._process_command(msg)

                    if resp != None:
                        this.log.debug('Sending: ' + str(resp))
                        this._gdb_resp(conn, resp)

            except this.DisconnectException: 
                this.log.info('Closing connection with: ' + str(client[0]))
                conn.close()
            except this.CtrlCException: 
                this.log.info('Caught CTRL+C')
                return


    #
    #
    #
    def _process_command(this,cmd):
        
        assert(len(cmd) > 0)

        cmdType = cmd[0]
        subCmd = cmd[1:]
        
        if cmdType == '?': return this._process_Question()
        elif cmdType == 'D': return this._process_D()
        elif cmdType == 'H': return this._process_H(subCmd)
        elif cmdType == 'k': return this._process_k()
        elif cmdType == 'g': return this._process_g(subCmd)
        elif cmdType == 'm': return this._process_m(subCmd)
        elif cmdType == 'p': return this._process_p(subCmd)
        elif cmdType == 'q': return this._process_q(subCmd)
        else: raise Exception()

        return None

    #
    #
    #
    def _process_Question(this):
        # Report why the target is halted
        # SIGTRAP?  Why not...
        return "S05"
    #
    #
    #
    def _process_D(this, ):
        this.log.debug('gdb detaching')
        this.callback("RESUME")
        return "OK"

    #
    #
    #
    def _process_H(this, subcmd):
        this.log.debug("unsupported H command")
        return ""

    #
    #
    #
    def _process_k(this):
        this.log.warn("Kill command")
        this.callback("RESUME")
        return None

    #
    # Read all regs
    #
    def _process_g(this, subcmd):
        this.log.debug('Read all Regs')
        resp = ''
        for r in this.regs:
            val = this.callback('REG READ ' + r)
            val = struct.pack('<I', val).encode('hex')
            resp += val

        return resp
  
    #
    # memory read
    #
    def _process_m(this, subcmd):
        this.log.debug('Memory Read')
        addr,size = subcmd.split(',')
        assert(size == '4')
        val = this.callback('MEM READ 0x'+addr + ' ' + size)
        val = int(val, 16)
        val = struct.pack('<I', val).encode('hex')
        resp = val
        return resp

    #
    # read specific reg
    #
    def _process_p(this, subcmd):
        this.log.debug('Register Read')
        reg =  int( subcmd, 16)
        reg = this.regs[reg]
        val = this.callback('REG READ '+ reg)
        val = int(val,16)
        val = struct.pack('<I',val).encode('hex')
        resp = val
        return resp

    #
    # general query commands
    #
    def _process_q(this, subcmd):
        
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
        else: raise Exception()
    
    #
    #
    #
    def _gdb_recv(this, conn):
    
        while True:
            rawdata= conn.recv(1024)
                    
            if not rawdata:
                raise this.DisconnectException()

            # CTRL+C
            if chr(0x03) in rawdata:
                raise this.CtrlCException()

            this.log.debug('RX: ' + str(rawdata) ) 

            # static buffer to tack on the new data
            # (plus fun way to make a static-ish function variable)
            try: this._buf_data += rawdata
            except AttributeError: this._buf_data = rawdata
            
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
            conn.send('+')

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

        rawdata= conn.recv(1)
        assert(rawdata[0] == '+')

   
#
#
#
def stub(msg):
    print("="*40 + "\n" + msg + "\n" + "="*40)
    return '0x300'


if __name__ == '__main__':
   
    logging.basicConfig( level=logging.WARN, 
                            format='%(levelname)s %(name)s %(message)s')
    port = 10001

    if (len(sys.argv) > 1):
        for arg in sys.argv:
            if '--port=' in arg:
               port = int(arg.split("=")[1])
               print 'set port=' + str(port)

    gdb = GdbRemote( callback=stub, tcp_port=port, log_level = logging.DEBUG)
    gdb.run()

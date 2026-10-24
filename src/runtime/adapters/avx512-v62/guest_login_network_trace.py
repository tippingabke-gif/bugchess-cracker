"""One-call-per-API Winsock observation in an owned offline process."""
import ctypes as C
from ctypes import wintypes as W
import socket
import struct
import sys
import time
from guest_firmware_scanner_probe import capture_stub,FIELDS

class LoginNetworkTrace:
    def __init__(self,probe):
        self.p=probe
        self.items=[]
        self.listener=None
        self.connection=None
        self.received=bytearray()
        self.p.report['loginNetworkTrace']={'calls':[],'skipped':[],
            'limitations':['Only the first call per selected export is observed; private paths and other APIs are outside coverage.']}
        self.report=self.p.report['loginNetworkTrace']
        if '--local-transport' in sys.argv:
            self.listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.listener.bind(('127.0.0.1',0))
            self.listener.listen(1)
            self.listener.setblocking(False)
            self.report['localRecorder']={'address':'127.0.0.1','port':self.listener.getsockname()[1],
                'serverResponseSent':False,'receivedBytes':0}
        self.dll=C.WinDLL('ws2_32',use_last_error=True)
        self.allocation=probe.k.VirtualAllocEx(probe.handle,None,0x3000,0x3000,4)
        if not self.allocation: raise C.WinError(C.get_last_error())
        prior=W.DWORD()
        if not probe.k.VirtualProtectEx(probe.handle,self.allocation,4096,0x20,C.byref(prior)):
            raise C.WinError(C.get_last_error())
        for index,name in enumerate(('getaddrinfo','GetAddrInfoW','gethostbyname','connect','WSAConnect','send','recv')):
            target=C.cast(getattr(self.dll,name),C.c_void_p).value
            original=probe.read(target,14)
            if original!=C.string_at(target,14):
                self.report['skipped'].append(name)
                continue
            code=self.allocation+index*0x200
            record=self.allocation+0x1000+index*0x200
            stub=capture_stub(record,target)
            if len(stub)>0x100: raise RuntimeError('Network gate exceeded slot')
            probe.protected_write(code,stub)
            probe.protected_write(target,b'\xff\x25\0\0\0\0'+struct.pack('<Q',code))
            self.items.append({'name':name,'target':target,'original':original,'code':code,'record':record,
                               'stage':'entry','restored':False})
        self.report['armed']=[i['name'] for i in self.items]

    def poll(self):
        p=self.p
        base=int(p.report['base'],16)
        if self.listener and self.connection is None:
            try:
                self.connection,peer=self.listener.accept()
                self.connection.setblocking(False)
                self.report['localRecorder']['accepted']=True
            except BlockingIOError:
                pass
        if self.connection:
            try:
                block=self.connection.recv(65536)
                if block and len(self.received)+len(block)<=1024*1024:
                    self.received.extend(block)
                    (p.out/'local-client-request.bin').write_bytes(self.received)
                    self.report['localRecorder']['receivedBytes']=len(self.received)
                    p.save()
            except (BlockingIOError,ConnectionResetError):
                pass
        for item in self.items:
            if item['stage']=='done': continue
            record=item['record']+(0x100 if item['stage']=='return' else 0)
            if p.read(record,4)!=b'\x01\0\0\0': continue
            raw=p.read(record,0xa0)
            regs={n:struct.unpack_from('<Q',raw,o)[0] for n,o in FIELDS.items()}
            if item['stage']=='entry':
                caller=int.from_bytes(p.read(regs['rsp'],8),'little')
                row={'api':item['name'],'caller':hex(caller),
                     'callerRva':hex(caller-base) if base<=caller<base+45916160 else None,
                     'elapsed':round(time.monotonic()-p.started,6)}
                (p.out/(item['name']+'-stack.bin')).write_bytes(p.read(regs['rsp'],8192))
                if item['name'] in ('connect','WSAConnect'):
                    sockaddr=p.read(regs['rdx'],min(regs['r8'],128))
                    if len(sockaddr)>=8:
                        family=struct.unpack_from('<H',sockaddr)[0]
                        row['family']=family
                        row['port']=struct.unpack_from('>H',sockaddr,2)[0]
                        if family==2: row['address']=socket.inet_ntop(socket.AF_INET,sockaddr[4:8])
                        if family==23 and len(sockaddr)>=24: row['address']=socket.inet_ntop(socket.AF_INET6,sockaddr[8:24])
                        if self.listener and family==2:
                            local=bytearray(sockaddr)
                            local[2:4]=struct.pack('>H',self.listener.getsockname()[1])
                            local[4:8]=socket.inet_pton(socket.AF_INET,'127.0.0.1')
                            p.write(regs['rdx'],bytes(local))
                            item['sockaddrRestore']=(regs['rdx'],sockaddr)
                            row['actualDestination']='127.0.0.1:'+str(self.listener.getsockname()[1])
                            p.report['networkArgumentsChanged']=True
                elif item['name'] in ('send','recv'):
                    row['requestedBytes']=regs['r8']
                    item['buffer']=regs['rdx']
                    if item['name']=='send':
                        data=p.read(regs['rdx'],min(regs['r8'],65536))
                        (p.out/'first-send.bin').write_bytes(data)
                        row['capturedBytes']=len(data)
                else:
                    rawname=p.read(regs['rcx'],512)
                    if item['name']=='GetAddrInfoW':
                        row['queryName']=rawname.decode('utf-16-le',errors='replace').split('\0')[0][:128]
                    else:
                        row['queryName']=rawname.split(b'\0')[0].decode(errors='replace')[:128]
                self.report['calls'].append(row)
                item['row']=row
                retcode=item['code']+0x100
                p.protected_write(retcode,capture_stub(item['record']+0x100,caller))
                p.write(regs['rsp'],struct.pack('<Q',retcode))
                p.protected_write(item['target'],item['original'])
                item['restored']=True
                item['stage']='return'
            else:
                teb=struct.unpack_from('<Q',raw,0x90)[0]
                item['row'].update(returnValue=hex(regs['rax']),
                    lastErrorValue=int.from_bytes(p.read(teb+0x68,4),'little'),
                    returnedAt=round(time.monotonic()-p.started,6))
                if 'sockaddrRestore' in item:
                    pointer,data=item['sockaddrRestore']
                    p.write(pointer,data)
                if item['name']=='recv' and 0<regs['rax']<0x10000:
                    (p.out/'first-recv.bin').write_bytes(p.read(item['buffer'],regs['rax']))
                item['stage']='done'
            p.save()
            p.write(record+4,struct.pack('<I',1))

    def cleanup(self):
        p=self.p
        if self.connection: self.connection.close()
        if self.listener: self.listener.close()
        if p.process is None or p.process.poll() is not None: return
        for item in self.items:
            try:
                if not item['restored']:
                    p.protected_write(item['target'],item['original'])
                p.write(item['record']+4,struct.pack('<I',1))
                p.write(item['record']+0x104,struct.pack('<I',1))
            except OSError as exc:
                self.report.setdefault('cleanupNotes',[]).append(str(exc))

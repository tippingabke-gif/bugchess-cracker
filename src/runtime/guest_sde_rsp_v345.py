"""Small GDB remote client for the guest-local Intel SDE debugger."""
import socket,struct

REGISTERS=['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
           'r8','r9','r10','r11','r12','r13','r14','r15','rip']

class Rsp:
    def __init__(self,port):
        self.socket=socket.create_connection(('127.0.0.1',port),timeout=8)
        self.socket.settimeout(20)
        self.socket.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        self.packets=[]
    def exact(self,n):
        if not hasattr(self,'_buffer'):self._buffer=bytearray()
        while len(self._buffer)<n:
            part=self.socket.recv(max(4096,n-len(self._buffer)))
            if not part:raise EOFError('RSP connection closed')
            self._buffer.extend(part)
        result=bytes(self._buffer[:n]);del self._buffer[:n]
        return result
    def send(self,text):
        raw=text.encode('ascii')
        self.socket.sendall(b'$'+raw+b'#'+f'{sum(raw)%256:02x}'.encode())
    def receive(self,skip_console=True):
        while self.exact(1)!=b'$':pass
        raw=bytearray()
        while True:
            char=self.exact(1)
            if char==b'#':break
            raw.extend(char)
        assert int(self.exact(2),16)==sum(raw)%256
        self.socket.sendall(b'+')
        result=bytearray();i=0
        while i<len(raw):
            if raw[i]==125:i+=1;result.append(raw[i]^32)
            elif raw[i]==42:i+=1;result.extend(result[-1:]*(raw[i]-29))
            else:result.append(raw[i])
            i+=1
        text=result.decode('ascii')
        if skip_console and text.startswith('O') and text!='OK':
            self.packets.append({'console':bytes.fromhex(text[1:]).decode(errors='replace')})
            return self.receive(skip_console=True)
        return text
    def ask(self,command):
        self.send(command);reply=self.receive()
        self.packets.append({'command':command[:96],'reply':reply[:160],'length':len(reply)})
        return reply
    def regs(self):
        raw=bytes.fromhex(self.ask('g'))
        assert len(raw)>=140
        result=dict(zip(REGISTERS,struct.unpack_from('<17Q',raw)))
        result['eflags']=struct.unpack_from('<I',raw,136)[0]
        return result
    def monitor(self,command):
        self.send('qRcmd,'+command.encode().hex());output=[]
        while True:
            reply=self.receive(skip_console=False)
            if reply.startswith('O') and reply!='OK':
                output.append(bytes.fromhex(reply[1:]).decode(errors='replace'))
            else:
                result={'reply':reply,'output':''.join(output)}
                self.packets.append({'monitor':command,**result})
                return result
    def setreg(self,name,value):
        number=REGISTERS.index(name);raw=struct.pack('<Q',value)
        assert self.ask(f'P{number:x}={raw.hex()}')=='OK'
    def read(self,address,size):
        reply=self.ask(f'm{address:x},{size:x}')
        if reply.startswith('E'):raise RuntimeError('RSP memory read '+reply)
        raw=bytes.fromhex(reply);assert len(raw)==size
        return raw
    def write(self,address,data):
        assert self.ask(f'M{address:x},{len(data):x}:{data.hex()}')=='OK'
    def breakpoint(self,address,kind=0,size=1,remove=False):
        assert self.ask(f'{"z" if remove else "Z"}{kind},{address:x},{size:x}')=='OK'
    def interrupt(self):
        self.socket.sendall(b'\x03');return self.receive()
    def close(self):self.socket.close()

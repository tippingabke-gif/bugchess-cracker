"""Run native startup checks, then enable SDE at the next unsupported opcode."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import faulthandler,hashlib,json,re,runpy,struct,subprocess,sys,threading,time
ROOT=Path(r'C:\Lab\BugChess20260627')
sys.path.insert(0,str(ROOT))
from guest_avx512_sde_runtime_v104 import LateProbe,SDE,Rsp,mainmod
from guest_avx512_native_core_v104 import NativeInitProbe
from guest_native_firmware_trace import Code
previous_write_bytes=Path.write_bytes
def compact_evidence(path,data):
    if path.parent.name=='firmware-scanner-avx512-hybrid-v105' and path.name in ('scanner-entry-image.bin','framing-image.bin','exit-image.bin'):
        path.with_suffix('.sha256.json').write_text(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'storage':'digest-only; full earlier snapshots retained'}),encoding='utf-8')
        return len(data)
    return previous_write_bytes(path,data)
Path.write_bytes=compact_evidence

class HybridProbe(NativeInitProbe,LateProbe):
    def attach_after_native(self,record,raw):
        base=int(self.report['base'],16)
        ip=struct.unpack_from('<Q',raw,0x1f8)[0]
        context=struct.unpack_from('<Q',raw,0x48)[0]
        if self.read(context+0xf8,8)!=struct.pack('<Q',ip):raise RuntimeError('Native handoff context mismatch')
        self.restore_page()
        info=self.report['lateAttach']={'events':[],'faultRva':hex(ip-base),'nativeStartupChecksExecuted':True}
        trampoline=self.k.VirtualAllocEx(self.handle,None,0x2000,0x3000,4)
        if not trampoline:raise C.WinError(C.get_last_error())
        ready=trampoline+0x1000
        code=Code();code.emit('9c5051524150415141524153534889e34883e4f0')
        code.emit(bytes.fromhex('4881ec')+struct.pack('<I',0x220))
        for n in range(16):code.emit(bytes((0xc5,0xfe if n<8 else 0x7e,0x7f,0x84+(n%8)*8,0x24))+struct.pack('<I',32+n*32))
        code.label('wait');code.emit(b'\x48\xb8'+struct.pack('<Q',ready)+bytes.fromhex('803801'))
        code.branch('0f84','ready')
        code.emit(bytes.fromhex('b90100000048b8')+struct.pack('<Q',C.cast(self.k.Sleep,C.c_void_p).value)+bytes.fromhex('ffd0'))
        code.branch('e9','wait');code.label('ready')
        for n in range(16):code.emit(bytes((0xc5,0xfe if n<8 else 0x7e,0x6f,0x84+(n%8)*8,0x24))+struct.pack('<I',32+n*32))
        code.emit(bytes.fromhex('4889dc5b415b415a415941585a59589dff2500000000')+struct.pack('<Q',ip))
        self.protected_write(trampoline,code.finish())
        prior=W.DWORD()
        if not self.k.VirtualProtectEx(self.handle,trampoline,4096,0x20,C.byref(prior)):raise C.WinError(C.get_last_error())
        self.k.FlushInstructionCache(self.handle,trampoline,4096)
        self.write(context+0xf8,struct.pack('<Q',trampoline))
        alloc_native=self.k.VirtualAllocEx
        pool=alloc_native(self.handle,None,0x300000,0x3000,0x40)
        if not pool:raise C.WinError(C.get_last_error())
        self.pool_used=0
        def mapped_alloc(handle,address,size,kind,protect):
            if hasattr(self,'rsp') and handle==self.handle and not address and size<=0x100000:
                offset=self.pool_used;self.pool_used+=(size+0xfff)&~0xfff
                if self.pool_used>0x300000:raise MemoryError('Instrumentation pool exhausted')
                return pool+offset
            return alloc_native(handle,address,size,kind,protect)
        self.k.VirtualAllocEx=mapped_alloc
        self.sde_streams=[(self.out/n).open('wb') for n in ('sde-stdout.txt','sde-stderr.txt')]
        self.sde=subprocess.Popen([str(SDE),'-spr','-use-host-cpuid','-debug','-attach-pid',str(self.process.pid)],cwd=self.out,
            stdin=subprocess.DEVNULL,stdout=self.sde_streams[0],stderr=self.sde_streams[1],creationflags=subprocess.CREATE_NO_WINDOW)
        info['launcherPid']=self.sde.pid
        time.sleep(.5)
        self.write(record+4,struct.pack('<I',0));self.write(record+0x18,raw[8:16])
        until=time.monotonic()+20
        while time.monotonic()<until:
            match=re.search(r'port\s+(\d+)',(self.out/'sde-stdout.txt').read_text(errors='replace'))
            if match:break
            if self.process.poll() is not None:raise RuntimeError('Target exited during native handoff')
            time.sleep(.05)
        else:raise TimeoutError('Native handoff debugger port')
        self.rsp=Rsp(int(match.group(1)));self.rsp.socket.settimeout(8)
        self.rsp_owner=threading.get_ident();self.rsp_running=False
        info['initialStop']=self.rsp.ask('?');info['initialRegisters']=self.rsp.regs()
        self.rsp.write(ready,b'\x01')
        self.continue_rsp();self.rsp_control_ready=True;self.sde_attaching=False
        self.save()

mainmod.MainProbe=HybridProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-hybrid-v105','AVX512','v62']
with (ROOT/'evidence/avx512-hybrid-v105-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

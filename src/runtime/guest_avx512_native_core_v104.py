"""Isolate native startup from SDE using one verified vector-fill equivalent."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,runpy,struct,sys,threading,time,traceback
import capstone
ROOT=Path(r'C:\Lab\BugChess20260627')
original_write_bytes=Path.write_bytes
def small_evidence(path,data):
    if path.parent.name=='firmware-scanner-avx512-nativeinit-v103' and path.name in ('scanner-entry-image.bin','framing-image.bin','exit-image.bin'):
        path.with_suffix('.sha256.json').write_text(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'storage':'digest-only; full earlier snapshots retained'}),encoding='utf-8')
        return len(data)
    return original_write_bytes(path,data)
Path.write_bytes=small_evidence
sys.path.insert(0,str(ROOT/'adapters/avx512-v62'))
import guest_main_execute_probe as mainmod
NATIVE_BASE=mainmod.MainProbe
from guest_firmware_guard import GuardTrace,make_handler,make_registration

def fill_code():
    # Only volatile YMM0 changes; GPRs and flags retain their incoming values.
    return bytes.fromhex('c4e1f96ec7 c4e27d59c0 c5fe7f03 c5fe7f4320 c5fe7f4340 c5fe7f4360')

def selftest(k):
    body=bytes.fromhex('53574889cb4889d7')+fill_code()+bytes.fromhex('c5f8775f5bc3')
    mem=k.VirtualAlloc(None,4096,0x3000,4)
    if not mem:raise C.WinError(C.get_last_error())
    try:
        C.memmove(mem,body,len(body));old=W.DWORD()
        if not k.VirtualProtect(mem,4096,0x20,C.byref(old)):raise C.WinError(C.get_last_error())
        fn=C.CFUNCTYPE(None,C.c_void_p,C.c_uint64)(mem)
        for value in (0,1,0xffffffffffffffff,0x1122334455667788):
            buffer=C.create_string_buffer(128);fn(C.addressof(buffer),value)
            if buffer.raw!=struct.pack('<Q',value)*16:raise RuntimeError('Vector-fill equivalence failed')
        return {'patterns':4,'bytesEach':128,'passed':True}
    finally:k.VirtualFree(mem,0,0x8000)

class NativeInitProbe(mainmod.MainProbe):
    def arm_exit(self):
        NATIVE_BASE.arm_exit(self);self.pause()
        self.k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,W.DWORD];self.k.VirtualAlloc.restype=C.c_void_p
        self.k.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]
        self.k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,W.DWORD]
        self.report['nativeFillSelftest']=selftest(self.k)
        saved_alloc,saved_record=self.allocation,self.record
        try:
            mem=self.k.VirtualAllocEx(self.handle,None,0x3000,0x3000,4)
            if not mem:raise C.WinError(C.get_last_error())
            record=mem+0x1000
            code=make_handler(record).replace(bytes.fromhex('813a01000080'),bytes.fromhex('813a1d0000c0'))
            code=code.replace(bytes.fromhex('4c8b4228'),bytes.fromhex('4c8b4210'))
            code=code.replace(bytes.fromhex('4c894348'),bytes.fromhex('4c895348'))
            self.write(mem,code);old=W.DWORD()
            self.k.VirtualProtectEx(self.handle,mem,4096,0x20,C.byref(old))
            self.k.FlushInstructionCache(self.handle,mem,4096)
            self.allocation,self.record=mem,record
            api=C.cast(self.n.RtlAddVectoredExceptionHandler,C.c_void_p).value
            GuardTrace.register_on_existing_thread(self,make_registration(mem,record,api))
            base=int(self.report['base'],16)
            self.write(record+0x20,struct.pack('<4Q',base,base+0x2b70000,base,base+0x2b70000))
            self.write(record+4,struct.pack('<I',1))
        finally:self.allocation,self.record=saved_alloc,saved_record;self.resume()
        self.report['nativeInit']={'events':[]}
        def observe():
            info=self.report['nativeInit'];until=time.monotonic()+65;last_sequence=0
            try:
                while self.process.poll() is None and time.monotonic()<until:
                    if self.read(record+0x10,4)!=b'\x01\0\0\0':time.sleep(.002);continue
                    raw=self.read(record,0x700);context=struct.unpack_from('<Q',raw,0x48)[0]
                    sequence=struct.unpack_from('<Q',raw,8)[0]
                    if sequence==last_sequence:time.sleep(.001);continue
                    last_sequence=sequence
                    ip=struct.unpack_from('<Q',raw,0x1f8)[0]
                    code=self.read(ip,32)
                    row={'rva':hex(ip-base),'bytes':code.hex(),'instructions':[i.mnemonic+' '+i.op_str for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(code,ip)]}
                    info['events'].append(row)
                    replacement=None;length=0;direct=False
                    if ip==base+0x215e6 and code[:19]==bytes.fromhex('62f2fd487cc762f1fe487f430162f1fe487f03'):
                        replacement=fill_code();length=19;row['fillSubstitution']=True
                    elif code[:6] in (bytes.fromhex('62f1fe0878c0'),bytes.fromhex('62f1fe0878d0')):
                        value=struct.unpack_from('<f',raw,0x2a0)[0];row['floatInput']=value
                        if 0<=value<2**63:
                            replacement=bytes.fromhex('c4e1fa2c')+code[5:6];length=6
                    elif code[:7]==bytes.fromhex('62f1ee087b4607'):
                        rsi=struct.unpack_from('<Q',raw,0x1a8)[0]
                        value=struct.unpack('<Q',self.read(rsi+0x38,8))[0];row['integerInput']=value
                        if value<2**63:replacement=bytes.fromhex('c4e1ea2a4638');length=7
                    elif code[:5]==bytes.fromhex('62f17c4811') and code[5] in (5,13,21,29):
                        register=(code[5]-5)//8
                        zeros=[bytes((0xc5,0xf8-register*8+wide,0x57,0xc0+register*9)) for wide in (0,4)]
                        row['preceding16']=self.read(ip-16,16).hex()
                        if self.read(ip-4,4) not in zeros or raw[0x2a0+register*16:0x2b0+register*16]!=bytes(16):
                            raise RuntimeError('Zero-store proof did not match')
                        target=ip+10+struct.unpack_from('<i',code,6)[0]
                        self.write(target,bytes(64));self.write(context+0xf8,struct.pack('<Q',ip+10))
                        row['zeroStore']={'target':hex(target),'bytes':64,'precedingVexZeroVerified':True};direct=True
                    if replacement is not None:
                        trampoline=mem+0x900
                        self.protected_write(trampoline,replacement+bytes.fromhex('ff2500000000')+struct.pack('<Q',ip+length))
                        self.write(context+0xf8,struct.pack('<Q',trampoline));row['equivalentInstruction']=replacement.hex()
                    elif not direct:
                        if hasattr(self,'attach_after_native') and any(x['name']=='second-result' for x in self.report['startupCheckpoints']):
                            row['handedToSdeAfterNativeStartup']=True
                            self.sde_attaching=True
                            self.attach_after_native(record,raw)
                            return
                        self.write(record+4,struct.pack('<I',0));row['unhandled']=True
                    self.save();self.write(record+0x18,raw[8:16])
                    if row.get('unhandled'):return
            except Exception:
                info['error']=traceback.format_exc();self.save()
                if self.process.poll() is None:
                    self.write(record+4,struct.pack('<I',0))
                    self.write(record+0x14,struct.pack('<I',1))
        threading.Thread(target=observe,daemon=True).start()


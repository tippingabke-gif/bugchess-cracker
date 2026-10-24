"""Preserve AVX512 mask semantics in a bounded native startup diagnostic."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_select_v122.py').read_text().rsplit('\nmainmod.MainProbe=NativeSelectBothProbe',1)[0]
source=source.replace('avx512-nativeselect-v122','avx512-nativemask-v125')
exec(compile(source,str(ROOT/'guest_native_select_v122.py'),'exec'))

def ternary(a,b,c,immediate):
    return bytes(sum(((immediate>>((((x>>bit)&1)<<2)|(((y>>bit)&1)<<1)|((z>>bit)&1)))&1)<<bit
                     for bit in range(8)) for x,y,z in zip(a,b,c))

def vector_load(register,value):
    assert 0<=register<16 and len(value)==16
    # VEX.128 load also clears the native upper YMM half; flags and GPRs unchanged.
    return bytes([0xc5,0xfa if register<8 else 0x7a,0x6f,0x05+((register&7)<<3)])+struct.pack('<i',2)+b'\xeb\x10'+value

def verify_loads():
    k=C.WinDLL('kernel32',use_last_error=True)
    k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,W.DWORD];k.VirtualAlloc.restype=C.c_void_p
    k.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]
    k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,W.DWORD]
    mem=k.VirtualAlloc(None,4096,0x3000,4)
    if not mem:raise C.WinError(C.get_last_error())
    try:
        for register in [2,3,4]:
            value=hashlib.sha256(bytes([register])).digest()[:16]
            body=vector_load(register,value)+bytes([0xc5,0xfe,0x7f,0x01+(register<<3)])+b'\xc3'
            prior=W.DWORD();k.VirtualProtect(mem,4096,0x40,C.byref(prior));C.memmove(mem,body,len(body))
            output=C.create_string_buffer(32)
            C.CFUNCTYPE(None,C.c_void_p)(mem)(C.addressof(output))
            assert output.raw==value+bytes(16)
        for n in range(8):
            bits=[bytes([255 if n&(1<<j) else 0])*16 for j in [2,1,0]]
            assert ternary(*bits,0xd8)==bytes((x&(~z&255))|(y&z) for x,y,z in zip(*bits))
        return {'passed':True,'nativeLoadCases':3,'truthTableCases':8,'upperYmmCleared':True}
    finally:k.VirtualFree(mem,0,0x8000)

class MaskProbe(NativeSelectBothProbe):
    def mask_step(self,ip,code,raw,context,row):
        base=int(self.report['base'],16)
        if ip==base+0xad7e7 and code[:4]==bytes.fromhex('c5fb92ca'):
            if self.read(ip-4,4)!=bytes.fromhex('66ba2400'):raise RuntimeError('Mask setup changed')
            self.shadow_k1=struct.unpack_from('<Q',raw,0x188)[0]&0xffffffff
            assert self.shadow_k1&0xffff==0x24
            self.write(context+0xf8,struct.pack('<Q',ip+4))
            row['maskRegisterWrite']={'register':'k1','value':self.shadow_k1}
            return b'',4,True
        if code[:7] in [bytes.fromhex('62f3650825d6d8'),bytes.fromhex('62f35d0825dfd8')]:
            dest=2 if code[5]==0xd6 else 3
            middle,third=(3,6) if dest==2 else (4,7)
            a,b,c=(raw[0x2a0+i*16:0x2b0+i*16] for i in [dest,middle,third])
            value=ternary(a,b,c,0xd8)
            row['ternary128']={'dest':dest,'inputs':[a.hex(),b.hex(),c.hex()],'output':value.hex()}
            return vector_load(dest,value),7,False
        if ip==base+0xad851 and code[:6]==bytes.fromhex('62f17f096fe2'):
            assert hasattr(self,'shadow_k1')
            before=raw[0x2e0:0x2f0];value=raw[0x2c0:0x2d0]
            result=bytes(value[i] if (self.shadow_k1>>i)&1 else before[i] for i in range(16))
            row['maskedByteMove']={'mask':self.shadow_k1&0xffff,'before':before.hex(),'source':value.hex(),'result':result.hex()}
            return vector_load(4,result),6,False
        return None

    def attach_after_native(self,record,raw):
        # Never lose virtual K state at a simulator handoff; save next opcode and stop.
        base=int(self.report['base'],16);ip=struct.unpack_from('<Q',raw,0x1f8)[0]
        self.report['nativeStop']={'rva':hex(ip-base),'bytes':self.read(ip,128).hex(),
            'instructions':[{'rva':hex(i.address-base),'asm':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()}
                            for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(self.read(ip,128),ip)]}
        self.save()
        self.process.terminate()

    def arm_exit(self):
        self.k.SetThreadExecutionState(0x80000001)
        self.report['maskEquivalentSelftest']=verify_loads()
        return namespace125['NativeInitProbe'].arm_exit(self)

first="                    if code[:7] in (bytes.fromhex('62f3550825e2d8'),bytes.fromhex('62f3550825e3d8')):"
assert combined.count(first)==1
expanded=combined.replace(first,"                    mask_result=self.mask_step(ip,code,raw,context,row)\n                    if mask_result is not None:\n                        replacement,length,direct=mask_result\n                        if direct:replacement=None\n                    elif code[:7] in (bytes.fromhex('62f3550825e2d8'),bytes.fromhex('62f3550825e3d8')):")
namespace125={'__name__':'native_mask_core_v125'}
exec(compile(native_source.replace(needle,expanded).replace('time.monotonic()+65','time.monotonic()+180'),str(ROOT/'guest_avx512_native_core_v104.py'),'exec'),namespace125)
mainmod.MainProbe=MaskProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativemask-v125','AVX512','v62']
with (ROOT/'evidence/avx512-nativemask-v125-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

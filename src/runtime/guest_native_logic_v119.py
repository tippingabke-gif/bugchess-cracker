"""Add an exact AVX2 equivalent for the observed 128-bit ternary logic instruction."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_zeros_v118.py').read_text().rsplit('\nmainmod.MainProbe=HybridProbe',1)[0]
source=source.replace('avx512-nativezeros-v118','avx512-nativelogic-v119')
exec(compile(source,str(ROOT/'guest_native_zeros_v118.py'),'exec'))

def ternary_body():
    # VPTERNLOGQ imm F6 is A OR (B XOR C). Preserve YMM15 and RFLAGS.
    return bytes.fromhex('488d6424d8 c57e7f3c24 c44171eff8 c4c179ebc7 c57e6f3c24 488d642428')

def verify_ternary():
    k=C.WinDLL('kernel32',use_last_error=True)
    k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,W.DWORD];k.VirtualAlloc.restype=C.c_void_p
    k.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]
    k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,W.DWORD]
    body=ternary_body()
    dis=[i.mnemonic+' '+i.op_str for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(body,0)]
    assert dis[2]=='vpxor xmm15, xmm1, xmm8' and dis[3]=='vpor xmm0, xmm0, xmm15'
    code=bytes.fromhex('488d6424d8 c57e7f0424 c5fa6f01 c5fa6f4910 c57a6f4120')+body+bytes.fromhex('c5fa7f02 c57e6f0424 488d642428 c3')
    address=k.VirtualAlloc(None,4096,0x3000,4)
    if not address:raise C.WinError(C.get_last_error())
    try:
        C.memmove(address,code,len(code));prior=W.DWORD()
        if not k.VirtualProtect(address,4096,0x20,C.byref(prior)):raise C.WinError(C.get_last_error())
        fn=C.CFUNCTYPE(None,C.c_void_p,C.c_void_p)(address)
        patterns=[tuple(bytes([255 if n&(1<<bit) else 0])*16 for bit in (2,1,0)) for n in range(8)]
        patterns += [tuple(hashlib.sha256(f'{n}:{j}'.encode()).digest()[:16] for j in range(3)) for n in range(8)]
        for a,b,c in patterns:
            inputs=C.create_string_buffer(a+b+c);output=C.create_string_buffer(16)
            fn(C.addressof(inputs),C.addressof(output))
            expected=bytes(x|(y^z) for x,y,z in zip(a,b,c))
            if output.raw!=expected:raise RuntimeError('Ternary instruction equivalence failed')
        return {'passed':True,'cases':len(patterns),'truthTable':'F6','semantics':'A OR (B XOR C)','instructions':dis}
    finally:k.VirtualFree(address,0,0x8000)

equivalence=verify_ternary()
new_replacement="""                    if code[:7]==bytes.fromhex('62d3f50825c0f6'):
                        replacement=bytes.fromhex('488d6424d8 c57e7f3c24 c44171eff8 c4c179ebc7 c57e6f3c24 488d642428')
                        length=7;row['ternaryEquivalent']='xmm0 OR (xmm1 XOR xmm8); scratch YMM15 and flags preserved'
                    elif self.zero_stack_group(ip,raw,context,row):
                        direct=True
                    elif ip==base+0x215e6 and code[:19]==bytes.fromhex('62f2fd487cc762f1fe487f430162f1fe487f03'):"""
namespace={'__name__':'native_logic_core_v119'}
exec(compile(native_source.replace(needle,new_replacement).replace('time.monotonic()+65','time.monotonic()+120'),str(ROOT/'guest_avx512_native_core_v104.py'),'exec'),namespace)
class NativeLogicProbe(HybridProbe):
    def arm_exit(self):
        self.report['ternaryEquivalence']=equivalence
        return namespace['NativeInitProbe'].arm_exit(self)

mainmod.MainProbe=NativeLogicProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativelogic-v119','AVX512','v62']
with (ROOT/'evidence/avx512-nativelogic-v119-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

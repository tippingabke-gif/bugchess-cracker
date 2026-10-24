"""Add the next observed ternary operation, a 128-bit bitwise select."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_logic_v119.py').read_text().rsplit('\nmainmod.MainProbe=NativeLogicProbe',1)[0]
source=source.replace('avx512-nativelogic-v119','avx512-nativeselect-v121')
exec(compile(source,str(ROOT/'guest_native_logic_v119.py'),'exec'))

select_body=bytes.fromhex('488d6424d8 c57e7f3c24 c46159effd c46101dbfa c4c159efe7 c57e6f3c24 488d642428')
def verify_select():
    k=C.WinDLL('kernel32',use_last_error=True)
    k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,W.DWORD];k.VirtualAlloc.restype=C.c_void_p
    k.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,C.POINTER(W.DWORD)]
    k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,W.DWORD]
    dis=[i.mnemonic+' '+i.op_str for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(select_body,0)]
    assert dis[2:5]==['vpxor xmm15, xmm4, xmm5','vpand xmm15, xmm15, xmm2','vpxor xmm4, xmm4, xmm15']
    code=bytes.fromhex('c5fa6f21 c5fa6f6910 c5fa6f5120')+select_body+bytes.fromhex('c5fa7f22 c3')
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
            expected=bytes((x&(~z&255))|(y&z) for x,y,z in zip(a,b,c))
            if output.raw!=expected:raise RuntimeError('Bit-select instruction equivalence failed')
        return {'passed':True,'cases':len(patterns),'truthTable':'D8','semantics':'C ? B : A per bit','instructions':dis}
    finally:k.VirtualFree(address,0,0x8000)
select_equivalence=verify_select()
pattern="                    if code[:7]==bytes.fromhex('62d3f50825c0f6'):"
addition="""                    if code[:7]==bytes.fromhex('62f3550825e2d8'):
                        replacement=bytes.fromhex('488d6424d8 c57e7f3c24 c46159effd c46101dbfa c4c159efe7 c57e6f3c24 488d642428')
                        length=7;row['ternaryEquivalent']='xmm2 ? xmm5 : xmm4 per bit; scratch YMM15 and flags preserved'
                    elif code[:7]==bytes.fromhex('62d3f50825c0f6'):"""
assert new_replacement.count(pattern)==1
namespace={'__name__':'native_select_core_v121'}
exec(compile(native_source.replace(needle,new_replacement.replace(pattern,addition)).replace('time.monotonic()+65','time.monotonic()+120'),str(ROOT/'guest_avx512_native_core_v104.py'),'exec'),namespace)
class NativeSelectProbe(HybridProbe):
    def arm_exit(self):
        self.report['ternaryEquivalence']=[equivalence,select_equivalence]
        return namespace['NativeInitProbe'].arm_exit(self)
mainmod.MainProbe=NativeSelectProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativeselect-v121','AVX512','v62']
with (ROOT/'evidence/avx512-nativeselect-v121-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

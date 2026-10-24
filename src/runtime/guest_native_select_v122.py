"""Handle the adjacent bit-select using XMM3, with the same verified semantics."""
from pathlib import Path
import inspect,textwrap
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_select_v121.py').read_text().rsplit('\nmainmod.MainProbe=NativeSelectProbe',1)[0]
source=source.replace('avx512-nativeselect-v121','avx512-nativeselect-v122')
exec(compile(source,str(ROOT/'guest_native_select_v121.py'),'exec'))
select_body=select_body.replace(bytes.fromhex('c46101dbfa'),bytes.fromhex('c46101dbfb'))
test_source=textwrap.dedent(inspect.getsource(verify_select)).replace('xmm15, xmm15, xmm2','xmm15, xmm15, xmm3').replace('c5fa6f5120','c5fa6f5920')
exec(test_source,globals())
select3_equivalence=verify_select()
combined=new_replacement.replace(pattern,addition)
combined=combined.replace("if code[:7]==bytes.fromhex('62f3550825e2d8'):","if code[:7] in (bytes.fromhex('62f3550825e2d8'),bytes.fromhex('62f3550825e3d8')):")
combined=combined.replace("                        length=7;row['ternaryEquivalent']='xmm2 ? xmm5 : xmm4 per bit; scratch YMM15 and flags preserved'",
"                        if code[5]==0xe3:replacement=replacement.replace(bytes.fromhex('c46101dbfa'),bytes.fromhex('c46101dbfb'))\n                        length=7;row['ternaryEquivalent']='selected mask xmm'+str(code[5]&15)+'; scratch YMM15 and flags preserved'")
namespace={'__name__':'native_select_core_v122'}
exec(compile(native_source.replace(needle,combined).replace('time.monotonic()+65','time.monotonic()+180'),str(ROOT/'guest_avx512_native_core_v104.py'),'exec'),namespace)
class NativeSelectBothProbe(HybridProbe):
    def arm_exit(self):
        self.report['ternaryEquivalence']=[equivalence,select_equivalence,select3_equivalence]
        return namespace['NativeInitProbe'].arm_exit(self)
mainmod.MainProbe=NativeSelectBothProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativeselect-v122','AVX512','v62']
with (ROOT/'evidence/avx512-nativeselect-v122-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

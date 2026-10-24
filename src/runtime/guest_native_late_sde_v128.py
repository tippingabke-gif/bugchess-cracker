"""Transfer the real virtual mask before a later simulator handoff at vector initialization."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_zero_groups_v127.py').read_text().rsplit('\nmainmod.MainProbe=MaskProbe',1)[0]
source=source.replace('avx512-nativezero-groups-v127','avx512-latesde-v128')
exec(compile(source,str(ROOT/'guest_native_zero_groups_v127.py'),'exec'))
import inspect,textwrap
handoff=textwrap.dedent(inspect.getsource(HybridProbe.attach_after_native))
old="code.emit(bytes.fromhex('4889dc5b415b415a415941585a59589dff2500000000')+struct.pack('<Q',ip))"
new="""assert ip==base+0xf1a5 and self.read(ip,10)==bytes.fromhex('62727d48222d513d1400')
    mask=getattr(self,'shadow_k1',0)
    code.emit(bytes.fromhex('4889dc5b415b415a415941585a59589d50b8')+struct.pack('<I',mask)+bytes.fromhex('c5fb92c858ff2500000000')+struct.pack('<Q',ip))
    info['transferredK1']=mask"""
assert handoff.count(old)==1
exec(handoff.replace(old,new),globals())
MaskProbe.attach_after_native=attach_after_native
mainmod.MainProbe=MaskProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-latesde-v128','AVX512','v62']
with (ROOT/'evidence/avx512-latesde-v128-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

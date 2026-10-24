"""Repeat v130 without the ExitProcess observer; require a natural quit."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_model_exit_control_v130.py').read_text().rsplit('\nmainmod.MainProbe=ExitControlProbe',1)[0]
source=source.replace('avx512-model-exit-control-v130','avx512-model-cleanquit-v131')
exec(compile(source,str(ROOT/'guest_model_exit_control_v130.py'),'exec'))

def unobserved_exit(self):
    # Keep the existing poll field mapped and zero, with no ExitProcess detour.
    self.exit_record=self.allocation+0x2100
    assert self.read(self.exit_record,8)==bytes(8)
    self.report['exitObservationArmed']=False
    self.report['quitValidation']={'exitApiUnmodified':True,
        'purpose':'distinguish original quit from SDE/observer interaction'}

mainmod.ScannerProbe.arm_exit=unobserved_exit
mainmod.MainProbe=ExitControlProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-model-cleanquit-v131','AVX512','v62']
with (ROOT/'evidence/avx512-model-cleanquit-v131-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

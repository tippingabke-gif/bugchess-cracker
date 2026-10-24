"""Single-call counterfactual at the observed model-phase exit; preserve normal quit."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_late_sde_v128.py').read_text().rsplit('\nmainmod.MainProbe=MaskProbe',1)[0]
source=source.replace('avx512-latesde-v128','avx512-model-exit-control-v130')
exec(compile(source,str(ROOT/'guest_native_late_sde_v128.py'),'exec'))
import select

class ExitControlProbe(MaskProbe):
    def continue_rsp(self,command='c'):
        if not getattr(self,'model_exit_bp_set',False):
            self.model_exit_bp_set=True
            base=int(self.report['base'],16)
            self.model_exit_bp=base+0x118850
            assert self.read(self.model_exit_bp,3)==bytes.fromhex('4533c0')
            self.rsp.breakpoint(self.model_exit_bp)
        return super().continue_rsp(command)

    def poll_rsp(self):
        if not getattr(self,'rsp_control_ready',False) or not getattr(self,'rsp_running',False):return
        if b'$' not in getattr(self.rsp,'_buffer',b'') and not select.select([self.rsp.socket],[],[],0)[0]:return
        packet=self.rsp.receive();self.rsp_running=False
        row={'packet':packet};self.report['lateAttach']['events'].append(row)
        if packet.startswith(('W','X')):self.save();return
        if not packet.startswith(('T','S')):raise RuntimeError('Unexpected model control stop: '+packet)
        regs=self.rsp.regs();row['registers']=regs
        site=getattr(self,'model_exit_bp',None)
        if site is not None and regs['rip'] in (site,site+1):
            base=int(self.report['base'],16)
            ret=struct.unpack('<Q',self.read(regs['rsp'],8))[0]
            self.rsp.breakpoint(site,remove=True);self.model_exit_bp=None
            self.rsp.setreg('rip',site)
            assert ret==base+0x15349b3 and regs['rcx']==0, ('Unexpected exit caller',hex(ret),regs['rcx'])
            assert not self.report.get('modelExitControl')
            self.report['modelExitControl']={'siteRva':'0x118850','callerReturnRva':'0x15349b3',
                'exitArgument':regs['rcx'],'counterfactual':'single exit call returns; normal quit remains intact',
                'registersBefore':regs,'sourceExeModified':False}
            self.rsp.setreg('rsp',regs['rsp']+8)
            self.rsp.setreg('rip',ret)
            self.save();self.continue_rsp();return
        self.save();self.continue_rsp('C'+packet[1:3])

mainmod.MainProbe=ExitControlProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-model-exit-control-v130','AVX512','v62']
with (ROOT/'evidence/avx512-model-exit-control-v130-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

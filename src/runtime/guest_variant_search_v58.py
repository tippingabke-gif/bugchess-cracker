"""AVX2 isolated startup, exact model hashing, and bounded real searches."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import traceback

ROOT=Path(r'C:\Lab\BugChess20260627')
label=sys.argv[1] if len(sys.argv)>1 else 'avx2-weights-v58'
variant=sys.argv[2] if len(sys.argv)>2 else 'AVX2'
adapter=sys.argv[3] if len(sys.argv)>3 else 'v57'
assert variant in ('AVX2','BMI2','AVX512')
sys.path.insert(0,str(ROOT/'adapters'/(variant.lower()+'-'+adapter)))
import guest_login_flow_probe as flow
import guest_login_network_trace as network
from guest_main_execute_probe import MainProbe

class VariantFlow(flow.FlowTrace):
    def add_gate(self,name,rva,checkpoint=False):
        if name in ('login-init','init-values'):
            return
        return super().add_gate(name,rva,checkpoint)

    def __init__(self,probe):
        super().__init__(probe)
        if variant=='AVX2':self.add_gate('embedded-prefix',0x65be0)
        self.add_gate('read-weights',{'AVX2':0x65c80,'BMI2':0x65a50,'AVX512':0x64160}[variant])

    def snapshot_call(self,item,regs,stage):
        super().snapshot_call(item,regs,stage)
        if stage!='return' or item['name'] not in ('primary-data','embedded-prefix','read-weights'):
            return
        p=self.p
        output_register='rdx' if item['name']=='read-weights' else 'rcx'
        raw=p.read(item['entryRegs'][output_register],32)
        if len(raw)!=32:return
        length,capacity=struct.unpack_from('<QQ',raw,16)
        row=self.flow['calls'][-1]
        row['fullOutputValidation']={'length':length,'capacity':capacity,'outputRegister':output_register}
        if not 16<=length<=capacity<=512*1024*1024:return
        pointer=struct.unpack_from('<Q',raw)[0]
        digest=hashlib.sha256()
        for start in range(0,length,1048576):
            size=min(1048576,length-start)
            block=p.read(pointer+start,size)
            if len(block)!=size:raise RuntimeError('Incomplete variant output hash read')
            digest.update(block)
        row['fullOutputValidation'].update(bytesHashed=length,sha256=digest.hexdigest())

out=ROOT/'evidence'/('firmware-scanner-'+label)
out.mkdir(exist_ok=False)
sys.argv=[__file__,label,'--pass-second','--login-probe','--network-trace',
 '--account-only','--network-early','--local-transport','--session-layout','--layout-tail',
 '--reply-clock','--reply-version','--parent-gates','--second-data','--primary-observe',
 '--model-parser-inspect','--search-check','--uci-check','--search-depth=12','--capture-seconds=60']
network.LoginNetworkTrace=VariantFlow
account=ROOT/'cases'/(variant.lower()+'-original-offline-v47')/'account.txt'
cache=account.parent/'login.txt'
lifecycle={'variant':variant,'created':False,'sourceExeModified':False}
try:
    if account.exists() or cache.exists():raise RuntimeError('Preserve pre-existing case login files')
    probe=MainProbe(out)
    account.write_text('00000000\nxtprobe0\n',encoding='ascii')
    lifecycle['created']=True
    probe.run_probe()
except Exception:lifecycle['error']=traceback.format_exc()
finally:
    if lifecycle['created']:
        if account.exists():account.replace(out/'synthetic-account-input.txt')
        if cache.exists():cache.replace(out/'generated-login-cache.txt')
    lifecycle['accountFileAbsentAfterCleanup']=not account.exists()
    (out/'input-lifecycle.json').write_text(json.dumps(lifecycle,indent=2),encoding='utf-8')

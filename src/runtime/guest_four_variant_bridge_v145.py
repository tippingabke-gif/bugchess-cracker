"""VM-only four-variant loading entries, gated on exact original/model hashes."""
from pathlib import Path
import ctypes as C
import hashlib,json,os,queue,re,struct,sys,threading,time,traceback
ROOT=Path(r'C:\Lab\BugChess20260627')
variant=sys.argv[1]
assert variant in ('SSE4','AVX2','BMI2','AVX512')
label='gui-'+variant.lower()+'-v145-'+str(time.time_ns())
entry_variant=variant
entry_label=label
sys.path.insert(0,str(ROOT))
if variant=='AVX512':
    setup=(ROOT/'guest_model_cleanquit_v131.py').read_text().split('\nmainmod.MainProbe=ExitControlProbe',1)[0]
    setup=setup.replace('avx512-model-cleanquit-v131',label)
    exec(compile(setup,str(ROOT/'guest_model_cleanquit_v131.py'),'exec'))
    class InteractiveProbe(ExitControlProbe):
        def capture_exit(self,base,image_size):
            return mainmod.capture_exit(self,base,image_size)
    Probe=InteractiveProbe
else:
    if variant!='SSE4':sys.path.insert(0,str(ROOT/'adapters'/({'AVX2':'avx2-v57','BMI2':'bmi2-v61'}[variant])))
    import guest_main_execute_probe as mainmod
    Probe=mainmod.MainProbe
variant=entry_variant;label=entry_label
import guest_login_flow_probe as flow
import guest_login_network_trace as network
if variant=='SSE4':
    import guest_native_firmware_trace as native
    import guest_heap_firmware_compare as heap
    native.CASE=ROOT/'cases/sse4-threads-v143';heap.CASE=native.CASE
case=ROOT/'cases'/('sse4-threads-v143' if variant=='SSE4' else variant.lower()+'-original-offline-v47')
engine=case/('BugChessNN_20260627_release_'+variant+'.exe')
profile={
    'SSE4':(0x654d0,0xa47498,'823ba67b56f18e9ea49ffeb18858410fa96f970008807e936b771f2372bfce9d'),
    'AVX2':(0x65c80,0xa39fc8,'20d0d7ff2cb83c9387649b495db126247e0ad1489d9364234e222ceae770d082'),
    'BMI2':(0x65a50,0xa38fc8,'11d1de3f2d17cfe5ac754d59ff2247a2b74eff1d65ee77ce6b1dcf1fb12931a0'),
    'AVX512':(0x64160,0xa37fc8,'073dbe80801a9228d62cc84d0577c04cd1a87d7c6b7d7a4b598e2100efb563f8'),
}[variant]
EXPECTED={'read-weights':(29088362,'2b024924171c0f0712c1a8649e7c9c11725db3d7cb3c842983366830a137f9d7'),
    'primary-data':(95113409,'5586bcd2aed7ee7b96ddc9faee4c890c6706750c7f1f9e31b6504b475202a43a')}
incoming=queue.Queue();offset=0;pending=b'';quit_at=None
raw_write=Path.write_bytes
def small_evidence(path,data):
    if path.parent.name=='firmware-scanner-'+label and path.name in ('scanner-entry-image.bin','framing-image.bin','exit-image.bin'):
        path.with_suffix('.sha256.json').write_text(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}),encoding='utf-8');return len(data)
    return raw_write(path,data)
Path.write_bytes=small_evidence

def read_stdin():
    buffer=b''
    try:
        while True:
            data=os.read(0,4096)
            if not data:return
            buffer+=data
            if len(buffer)>65536:raise ValueError('Oversize UCI input')
            while b'\n' in buffer:
                line,buffer=buffer.split(b'\n',1)
                incoming.put(line+b'\n')
                if line.strip()==b'quit':return
    finally:incoming.put(None)

def output(probe,final=False):
    global offset,pending
    path=probe.out/'stdout.bin'
    if not path.exists():return
    with path.open('rb') as stream:
        stream.seek(offset);data=stream.read();offset+=len(data)
    pending+=data;lines=pending.split(b'\n');pending=lines.pop()
    if final and pending:lines.append(pending);pending=b''
    for raw in lines:
        line=raw.strip(b'\r')
        if not line:continue
        if not line.startswith((b'id ',b'option ',b'uciok',b'readyok',b'info ',b'bestmove ')):line=b'info string '+line
        if line.startswith(b'info '):line=re.sub(rb'\bscore (-?\d+)(?=\s|$)',rb'score cp \1',line)
        sys.stdout.buffer.write(line+b'\n')
    if lines:sys.stdout.buffer.flush()

class BridgeFlow(flow.FlowTrace):
    def add_gate(self,name,rva,checkpoint=False):
        if name in ('login-init','init-values'):return
        return super().add_gate(name,rva,checkpoint)
    def __init__(self,probe):
        super().__init__(probe);self.add_gate('read-weights',profile[0])
    def snapshot_call(self,item,regs,stage):
        super().snapshot_call(item,regs,stage)
        if stage!='return' or item['name'] not in EXPECTED:return
        p=self.p;register='rdx' if item['name']=='read-weights' else 'rcx'
        raw=p.read(item['entryRegs'][register],32);length,capacity=struct.unpack_from('<QQ',raw,16)
        wanted,sha=EXPECTED[item['name']]
        assert length==wanted and length<=capacity<=512*1024*1024
        pointer=struct.unpack_from('<Q',raw)[0];digest=hashlib.sha256()
        for start in range(0,length,1048576):
            size=min(1048576,length-start);data=p.read(pointer+start,size)
            assert len(data)==size;digest.update(data)
        assert digest.hexdigest()==sha,'Model/weights hash mismatch'
        p.report.setdefault('verifiedOutputs',{})[item['name']]={'bytes':length,'sha256':sha}
        if item['name']=='primary-data':
            cap=self.base+profile[1];assert p.read(cap,4)==bytes(4)
            # Keep the signed-int representation range; do not impose a test or CPU-count cap.
            p.write(cap,struct.pack('<I',0x7fffffff));assert p.read(cap,4)==struct.pack('<I',0x7fffffff)
            p.report['threadOptionIntegerMax']=0x7fffffff
    def poll(self):
        global quit_at
        super().poll();p=self.p;output(p)
        while not incoming.empty():
            line=incoming.get_nowait()
            if quit_at is not None:continue
            if line is None:line=b'quit\n'
            p.process.stdin.write(line);p.process.stdin.flush()
            if line.strip()==b'quit':quit_at=time.monotonic()
        if quit_at is not None and time.monotonic()-quit_at>15:
            p.report['bridgeQuitTimeout']=True;p.report['flowObservationComplete']=True

def main():
    out=ROOT/'evidence'/('firmware-scanner-'+label);out.mkdir()
    account=case/'account.txt';cache=case/'login.txt';lock=None;created=False;probe=None
    life={'variant':variant,'sourceExeModified':False,'scope':'VM loading entry, not portable package','exitCode':1}
    try:
        assert hashlib.sha256(engine.read_bytes()).hexdigest()==profile[2]
        assert hashlib.sha256((case/'weights_20260627.bin').read_bytes()).hexdigest()==EXPECTED['read-weights'][1]
        lock=os.open(str(case/'gui-v145.lock'),os.O_CREAT|os.O_EXCL|os.O_WRONLY)
        os.write(lock,str(os.getpid()).encode())
        if account.exists() or cache.exists():raise RuntimeError('Preserving existing account/login files')
        sys.argv=[__file__,label,'--pass-second','--login-probe','--network-trace','--account-only','--network-early',
            '--local-transport','--session-layout','--layout-tail','--reply-clock','--reply-version','--parent-gates',
            '--second-data','--primary-observe','--model-parser-inspect','--interactive-bridge']
        network.LoginNetworkTrace=BridgeFlow
        probe=Probe(out);account.write_text('00000000\nxtprobe0\n',encoding='ascii');created=True
        threading.Thread(target=read_stdin,daemon=True).start()
        probe.run_probe();output(probe,True)
        if probe.report.get('naturalExitCode')!=0:raise RuntimeError(probe.report.get('error','Abnormal engine exit'))
        if len(probe.report.get('verifiedOutputs',{}))!=2:raise RuntimeError('Weight verification incomplete')
        life['exitCode']=0
    except Exception:
        life['error']=traceback.format_exc();sys.stderr.write(life['error'])
    finally:
        if created:
            for path in (account,cache):
                if path.exists():path.replace(out/path.name)
        if lock is not None:os.close(lock);(case/'gui-v145.lock').unlink()
        life['accountAbsent']=not account.exists();life['cacheAbsent']=not cache.exists()
        (out/'input-lifecycle.json').write_text(json.dumps(life,indent=2),encoding='utf-8')
        (ROOT/'load-test-v145'/('last-run-'+variant+'.json')).write_text(json.dumps({'evidence':str(out),**life},indent=2),encoding='utf-8')
    return life['exitCode']
if __name__=='__main__':raise SystemExit(main())

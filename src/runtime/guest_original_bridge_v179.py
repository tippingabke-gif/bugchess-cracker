"""VM original-file bridge with an installed component or active helper session."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import inspect,json,os,subprocess,sys,textwrap,time
LAB=Path(r'C:\Lab\BugChess20260627')
if len(sys.argv)!=3 or sys.argv[1] not in ('--ifeo','--component'):raise SystemExit('Use the original-file entry')
componentMode=sys.argv[1]=='--component'
PERSISTENT_ACCOUNT=b'00000000\nhttps://github.com/tippingabke-gif\n'
engineArg=Path(sys.argv[2]).resolve(strict=True)
originalVariant=engineArg.stem.removeprefix('BugChessNN_20260627_release_')
if originalVariant not in ('SSE4','AVX2','BMI2','AVX512'):raise SystemExit('Unexpected engine file')
supportArg=engineArg.parent/'BugChessSupport-v148'/originalVariant
if componentMode:
    sys.path.insert(0,str(LAB))
    from guest_session_lock_v174 import process_state
    import hashlib
    componentMarker=supportArg/'installed-component.json'
    component=json.loads(componentMarker.read_text(encoding='utf-8-sig'))
    if component.get('schema')!=1 or Path(component['engine'])!=engineArg:raise SystemExit('Component installation path mismatch')
    nativeInfo=C.WinDLL('ntdll')
    nativeInfo.NtQueryInformationProcess.argtypes=[W.HANDLE,W.ULONG,C.c_void_p,W.ULONG,C.POINTER(W.ULONG)]
    basic=(C.c_void_p*6)();used=W.ULONG()
    if nativeInfo.NtQueryInformationProcess(W.HANDLE(-1),0,basic,C.sizeof(basic),C.byref(used))<0:raise SystemExit('Parent process query failed')
    parentState=process_state(int(basic[5]))
    if not parentState or Path(parentState['path'])!=Path(component['hook']):raise SystemExit('Unexpected component parent')
    if hashlib.sha256(Path(component['hook']).read_bytes()).hexdigest()!=component['hookSha256']:raise SystemExit('Component file checksum mismatch')
    state={**parentState,'engine':str(engineArg),'marker':str(componentMarker)}
else:
    state=json.loads((supportArg/'active-session.json').read_text(encoding='utf-8-sig'))
if Path(state['engine'])!=engineArg:raise SystemExit('Helper path mismatch')
ownerKernel=C.WinDLL('kernel32',use_last_error=True)
ownerKernel.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];ownerKernel.OpenProcess.restype=W.HANDLE
ownerKernel.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4
ownerKernel.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
ownerKernel.CloseHandle.argtypes=[W.HANDLE]
ownerHandle=ownerKernel.OpenProcess(0x101000,False,state['pid'])
if not ownerHandle:raise SystemExit('Helper is no longer running')
times=[W.FILETIME() for _ in range(4)]
if not ownerKernel.GetProcessTimes(ownerHandle,*(C.byref(x) for x in times)):raise C.WinError(C.get_last_error())
stamp=(times[0].dwHighDateTime<<32)|times[0].dwLowDateTime
ownerMarker=Path(state['marker'])
if str(stamp)!=state['startedFileTime'] or ownerMarker.parent!=supportArg or not ownerMarker.is_file():raise SystemExit('Helper session expired')

source=(LAB/'guest_four_variant_bridge_v145.py').read_text()
source=source.replace('variant=sys.argv[1]','variant=originalVariant')
old="""if variant=='SSE4':
    import guest_native_firmware_trace as native
    import guest_heap_firmware_compare as heap
    native.CASE=ROOT/'cases/sse4-threads-v143';heap.CASE=native.CASE
case=ROOT/'cases'/('sse4-threads-v143' if variant=='SSE4' else variant.lower()+'-original-offline-v47')"""
new="""import guest_native_firmware_trace as native
import guest_heap_firmware_compare as heap
case=engineArg.parent
native.CASE=case;heap.CASE=case"""
assert source.count(old)==1
source=source.replace(old,new).replace("'gui-'+variant.lower()+'-v145-'","'original-'+variant.lower()+'-v148-'")
source=source.replace("ROOT/'load-test-v145'/('last-run-'+variant+'.json')","supportArg/'last-run.json'")
legacy_lock="lock=os.open(str(case/'gui-v145.lock'),os.O_CREAT|os.O_EXCL|os.O_WRONLY)\n        os.write(lock,str(os.getpid()).encode())"
assert source.count(legacy_lock)==1
source=source.replace(legacy_lock,'lock=acquire_session(case,out,PERSISTENT_ACCOUNT if componentMode else None)')
legacy_close="if lock is not None:os.close(lock);(case/'gui-v145.lock').unlink()"
assert source.count(legacy_close)==1
source=source.replace(legacy_close,'if lock is not None:lock.close()')
legacy_error="life['error']=traceback.format_exc();sys.stderr.write(life['error'])"
assert source.count(legacy_error)==1
source=source.replace(legacy_error,"life['error']=traceback.format_exc();error=sys.exc_info()[1];sys.stderr.write(('BUGCHESS_HELPER_ERROR:'+str(error)+'\\n') if isinstance(error,SessionBusy) else life['error'])")
if componentMode:
    before="if account.exists() or cache.exists():raise RuntimeError('Preserving existing account/login files')"
    after="if cache.exists():raise RuntimeError('Preserving existing login cache')\n        if not account.is_file() or account.read_bytes().replace(b'\\r\\n',b'\\n')!=PERSISTENT_ACCOUNT:raise RuntimeError('account.txt is missing or changed; run BugChessCracker.exe once')"
    assert source.count(before)==1
    source=source.replace(before,after)
    before="probe=Probe(out);account.write_text('00000000\\nxtprobe0\\n',encoding='ascii');created=True"
    assert source.count(before)==1
    source=source.replace(before,"probe=Probe(out);created=True;life['persistentAccount']=True")
    assert source.count('for path in (account,cache):')==1
    source=source.replace('for path in (account,cache):','for path in (cache,):')
source=source.split("if __name__=='__main__':raise SystemExit(main())",1)[0]
exec(compile(source,str(LAB/'guest_four_variant_bridge_v145.py'),'exec'))
from guest_session_lock_v174 import acquire as acquire_session, SessionBusy
from guest_uci_output_stream_v171 import install as install_output_stream
install_output_stream(globals())

def verify_original_network(exe):
    checked=subprocess.run([str(supportArg/'BugChessNetwork.exe'),'verify',str(exe)],capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,timeout=20)
    if checked.returncode:raise RuntimeError('Exact executable network isolation is absent: '+checked.stderr.decode(errors='replace'))

init=textwrap.dedent(inspect.getsource(mainmod.MainProbe.__init__))
assert init.count('super().__init__(out,True,True)')==1
init=init.replace('super().__init__(out,True,True)','super(MainProbe,self).__init__(out,True,True)')
begin=init.index('        script="$rows = Get-NetFirewallRule')
end=init.index("        self.report['loginNetwork']=",begin)
init=init[:begin]+"        verify_original_network(self.engine)\n"+init[end:]
mainmod.__dict__['verify_original_network']=verify_original_network
exec(compile(init,'<original-helper-network-check>','exec'),mainmod.__dict__)
mainmod.MainProbe.__init__=mainmod.__init__

originalPopen=subprocess.Popen
def spawn_original(*args,**kwargs):
    command=args[0] if args else kwargs.get('args')
    if not isinstance(command,(list,tuple)) or not command or Path(command[0])!=engineArg:
        return originalPopen(*args,**kwargs)
    flags=kwargs.get('creationflags',0)
    if not flags&4:raise ValueError('Expected suspended original-engine launch')
    # Windows omits IFEO recursion for an explicitly debug-created child.
    # Detach while it is still suspended, before any engine instruction runs.
    kwargs['creationflags']=flags|2
    child=originalPopen(*args,**kwargs)
    ownerKernel.DebugSetProcessKillOnExit.argtypes=[W.BOOL]
    ownerKernel.DebugActiveProcessStop.argtypes=[W.DWORD]
    try:
        if not ownerKernel.DebugSetProcessKillOnExit(False):raise C.WinError(C.get_last_error())
        if not ownerKernel.DebugActiveProcessStop(child.pid):raise C.WinError(C.get_last_error())
    except Exception:
        child.kill();child.wait(timeout=5);raise
    return child
subprocess.Popen=spawn_original

class OwnedBridge(BridgeFlow):
    def poll(self):
        if quit_at is None and (ownerKernel.WaitForSingleObject(ownerHandle,0)!=258 or not ownerMarker.is_file()):
            incoming.put(b'quit\n')
        return super().poll()
BridgeFlow=OwnedBridge
try:raise SystemExit(main())
finally:ownerKernel.CloseHandle(ownerHandle)

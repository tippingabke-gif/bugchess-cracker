"""Native protection startup, attach SDE only at the first real AVX512 fault."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import faulthandler,hashlib,inspect,json,re,runpy,select,struct,subprocess,sys,textwrap,threading,time,traceback
ROOT=Path(r'C:\Lab\BugChess20260627')
sys.path.insert(0,str(ROOT/'adapters/avx512-v62'))
import guest_main_execute_probe as mainmod
from guest_firmware_guard import GuardTrace,make_handler,make_registration
from guest_native_firmware_trace import Code
sys.path.append(str(ROOT))
from guest_sde_rsp_v345 import Rsp
SDE=Path(r'C:\Lab\Tools\IntelSDE-10.13.1\sde-external-10.13.1-2026-07-28-win/sde.exe')
original_write_bytes=Path.write_bytes
def small_evidence(path,data):
    if path.parent.name=='firmware-scanner-avx512-hybrid-v104' and path.name in ('scanner-entry-image.bin','framing-image.bin','exit-image.bin'):
        path.with_suffix('.sha256.json').write_text(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'storage':'digest-only; full earlier snapshots retained'}),encoding='utf-8')
        return len(data)
    return original_write_bytes(path,data)
Path.write_bytes=small_evidence
import guest_login_flow_probe as flowmod
# Only this SDE diagnostic gets longer bounded timeouts. Native adapters remain
# unchanged; all requested depth-12 searches still use their original positions.
capture_source=textwrap.dedent(inspect.getsource(mainmod.MainProbe.capture_exit))
assert capture_source.count('not 1<=duration<=90')==1
capture_source=capture_source.replace('not 1<=duration<=90','not 1<=duration<=480').replace('super().capture_exit(base,image_size)','ScannerProbe.capture_exit(self,base,image_size)')
exec(capture_source,mainmod.__dict__)
mainmod.MainProbe.capture_exit=mainmod.capture_exit
search_source=textwrap.dedent(inspect.getsource(flowmod.FlowTrace.poll_search))
assert search_source.count('elapsed > 7')==1 and search_source.count('elapsed > 10')==1
exec(search_source.replace('elapsed > 7','elapsed > 60').replace('elapsed > 10','elapsed > 90'),flowmod.__dict__)
flowmod.FlowTrace.poll_search=flowmod.poll_search
original_flow_poll=flowmod.FlowTrace.poll
def cache_aware_poll(flow):
    if getattr(flow.p,'sde_attaching',False):return
    if hasattr(flow.p,'rsp') and not getattr(flow.p,'rsp_control_ready',False):return
    if hasattr(flow.p,'poll_rsp'):flow.p.poll_rsp()
    return original_flow_poll(flow)
flowmod.FlowTrace.poll=cache_aware_poll

class LateProbe(mainmod.MainProbe):
    def capture_exit(self,base,image_size):
        saved=list(sys.argv)
        sys.argv=[a for a in sys.argv if not a.startswith('--capture-seconds=')]+['--capture-seconds=480']
        self.report['simulationTestBounds']={'captureSeconds':480,'perCaseStopSeconds':60,'perCaseTimeoutSeconds':90,'depth':12}
        def watchdog():
            if self.process.poll() is None:
                self.report['boundedWatchdogExpired']=True
                self.process.terminate()
        timer=threading.Timer(500,watchdog);timer.daemon=True;timer.start()
        try:return super().capture_exit(base,image_size)
        finally:timer.cancel();sys.argv=saved

    def continue_rsp(self,command='c'):
        self.rsp.send(command)
        first=self.rsp.exact(1)
        if first!=b'+':self.rsp._buffer=bytearray(first)+self.rsp._buffer
        self.rsp_running=True

    def protected_write(self,address,data):
        if hasattr(self,'rsp') and self.process.poll() is None and (getattr(self,'rsp_control_ready',False) or getattr(self,'rsp_owner',None)==threading.get_ident()):
            resumed=getattr(self,'rsp_running',False)
            if resumed:
                packet=self.rsp.interrupt();self.rsp_running=False
                if packet.startswith(('W','X')):
                    self.report['lateAttach']['exitObservedDuringCodeWrite']=packet
                    return
                if not packet.startswith(('T02','S02')):raise RuntimeError('Unexpected stop while flushing code: '+packet)
            prior=W.DWORD()
            if not self.k.VirtualProtectEx(self.handle,address,len(data),0x40,C.byref(prior)):raise C.WinError(C.get_last_error())
            try:
                reply=self.rsp.ask(f'M{address:x},{len(data):x}:{data.hex()}')
                if reply!='OK':raise RuntimeError(f'RSP code write at {address:x} size {len(data)}: {reply}')
            finally:
                ignored=W.DWORD();self.k.VirtualProtectEx(self.handle,address,len(data),prior.value,C.byref(ignored))
            if self.rsp.read(address,len(data))!=data:raise RuntimeError('RSP code write verification failed')
            self.report['lateAttach']['debuggerCodeWrites']=self.report['lateAttach'].get('debuggerCodeWrites',0)+1
            if resumed:self.continue_rsp()
            return
        return super().protected_write(address,data)

    def poll_rsp(self):
        if not getattr(self,'rsp_control_ready',False) or not getattr(self,'rsp_running',False):return
        if b'$' not in getattr(self.rsp,'_buffer',b'') and not select.select([self.rsp.socket],[],[],0)[0]:return
        packet=self.rsp.receive();self.rsp_running=False
        row={'packet':packet};self.report['lateAttach']['events'].append(row)
        if packet.startswith(('W','X')):self.save();return
        if packet.startswith(('T','S')):
            regs=self.rsp.regs();row['registers']=regs
            row['stack']=[hex(x) for x in struct.unpack('<32Q',self.read(regs['rsp'],256))]
            row['instructionBytes']=self.read(regs['rip'],32).hex()
            self.save()
            self.continue_rsp('C'+packet[1:3])

    def arm_exit(self):
        # RSP owns main checkpoints; never install the competing page observer.
        mainmod.ScannerProbe.arm_exit(self)
        self.page_restored=True
        self.pause()
        saved_alloc,saved_record=self.allocation,self.record
        try:
            mem=self.k.VirtualAllocEx(self.handle,None,0x3000,0x3000,4)
            if not mem:raise C.WinError(C.get_last_error())
            record=mem+0x1000
            self.trace_record=record
            code=make_handler(record).replace(bytes.fromhex('813a01000080'),bytes.fromhex('813a1d0000c0'))
            code=code.replace(bytes.fromhex('4c8b4228'),bytes.fromhex('4c8b4210'))
            # Preserve the live CONTEXT pointer in the otherwise diagnostic
            # address field; same-length encoding keeps all branch offsets intact.
            assert code.count(bytes.fromhex('4c894348'))==1
            code=code.replace(bytes.fromhex('4c894348'),bytes.fromhex('4c895348'))
            self.write(mem,code);old=W.DWORD()
            self.k.VirtualProtectEx(self.handle,mem,4096,0x20,C.byref(old));self.k.FlushInstructionCache(self.handle,mem,4096)
            self.allocation,self.record=mem,record
            api=C.cast(self.n.RtlAddVectoredExceptionHandler,C.c_void_p).value
            GuardTrace.register_on_existing_thread(self,make_registration(mem,record,api))
            base=int(self.report['base'],16)
            # Observe only the already captured first unsupported opcode.
            self.write(record+0x20,struct.pack('<4Q',base+0x215e6,base+0x215e7,base+0x215e6,base+0x215e7))
            self.write(record+4,struct.pack('<I',1))
        finally:self.allocation,self.record=saved_alloc,saved_record;self.resume()
        self.report['lateAttach']={'events':[]}
        def attach():
            info=self.report['lateAttach'];until=time.monotonic()+25
            try:
                while self.process.poll() is None and time.monotonic()<until:
                    if self.read(record+0x10,4)==b'\x01\0\0\0':break
                    time.sleep(.005)
                else:raise RuntimeError('First AVX512 fault not observed')
                raw=self.read(record,0x700)
                ip=struct.unpack_from('<Q',raw,0x100+0xf8)[0]
                if ip!=base+0x215e6:raise RuntimeError('Unexpected fault address')
                info['faultRva']=hex(ip-base)
                # Restore before Pin snapshots application memory protections.
                # Changing protections externally after attach leaves its map stale.
                self.restore_page()
                # Leave native exception dispatch through an ordinary wait loop.
                # All GPRs, flags, and YMM registers survive this scheduling point.
                trampoline=self.k.VirtualAllocEx(self.handle,None,0x2000,0x3000,4)
                if not trampoline:raise C.WinError(C.get_last_error())
                ready=trampoline+0x1000
                code=Code();code.emit('9c5051524150415141524153534889e34883e4f0')
                code.emit(bytes.fromhex('4881ec')+struct.pack('<I',0x220))
                for n in range(16):
                    code.emit(bytes((0xc5,0xfe if n<8 else 0x7e,0x7f,0x84+(n%8)*8,0x24))+struct.pack('<I',32+n*32))
                code.label('wait');code.emit(b'\x48\xb8'+struct.pack('<Q',ready)+bytes.fromhex('803801'))
                code.branch('0f84','ready')
                code.emit(bytes.fromhex('b90100000048b8')+struct.pack('<Q',C.cast(self.k.Sleep,C.c_void_p).value)+bytes.fromhex('ffd0'))
                code.branch('e9','wait');code.label('ready')
                for n in range(16):
                    code.emit(bytes((0xc5,0xfe if n<8 else 0x7e,0x6f,0x84+(n%8)*8,0x24))+struct.pack('<I',32+n*32))
                code.emit(bytes.fromhex('4889dc5b415b415a415941585a59589dff2500000000')+struct.pack('<Q',ip))
                self.write(trampoline,code.finish());prior=W.DWORD()
                self.k.VirtualProtectEx(self.handle,trampoline,4096,0x20,C.byref(prior))
                self.k.FlushInstructionCache(self.handle,trampoline,4096)
                context=struct.unpack_from('<Q',raw,0x48)[0]
                if self.read(context+0xf8,8)!=struct.pack('<Q',ip):raise RuntimeError('Fault CONTEXT mismatch')
                self.write(context+0xf8,struct.pack('<Q',trampoline))
                info['contextRedirectedToWaitLoop']=True
                # Pin snapshots the application map at attachment. Register
                # future instrumentation storage before that snapshot occurs.
                alloc_native=self.k.VirtualAllocEx
                pool=alloc_native(self.handle,None,0x300000,0x3000,0x40)
                if not pool:raise C.WinError(C.get_last_error())
                self.pool_used=0
                def mapped_alloc(handle,address,size,kind,protect):
                    if hasattr(self,'rsp') and handle==self.handle and not address and size<=0x100000:
                        offset=self.pool_used;self.pool_used+=(size+0xfff)&~0xfff
                        if self.pool_used>0x300000:raise MemoryError('Pre-mapped instrumentation pool exhausted')
                        return pool+offset
                    return alloc_native(handle,address,size,kind,protect)
                self.k.VirtualAllocEx=mapped_alloc
                info['premappedInstrumentationBytes']=0x300000
                self.sde_streams=[(self.out/n).open('wb') for n in ('sde-stdout.txt','sde-stderr.txt')]
                self.sde=subprocess.Popen([str(SDE),'-spr','-use-host-cpuid','-debug','-attach-pid',str(self.process.pid)],cwd=self.out,
                    stdin=subprocess.DEVNULL,stdout=self.sde_streams[0],stderr=self.sde_streams[1],creationflags=subprocess.CREATE_NO_WINDOW)
                info['launcherPid']=self.sde.pid
                time.sleep(.5)
                # Retry this exact instruction through the OS exception return;
                # Pin's attach takes control at that transition.
                self.write(record+4,struct.pack('<I',0))
                self.write(record+0x18,raw[8:16])
                until=time.monotonic()+20
                while time.monotonic()<until:
                    match=re.search(r'port\s+(\d+)',(self.out/'sde-stdout.txt').read_text(errors='replace'))
                    if match:break
                    if self.process.poll() is not None:raise RuntimeError('Target exited during late attach')
                    time.sleep(.05)
                else:raise TimeoutError('Late attach debugger port')
                self.rsp=Rsp(int(match.group(1)));self.rsp.socket.settimeout(15)
                self.rsp_owner=threading.get_ident();self.rsp_running=False
                info['initialStop']=self.rsp.ask('?');info['initialRegisters']=self.rsp.regs()
                self.rsp.write(ready,b'\x01')
                # The native execute-page observer is not meaningful in Pin's
                # code cache. Use an exact application breakpoint instead.
                self.restore_page()
                second_call=base+0x532e9
                expected=(ROOT/'evidence/variants-resolved-v55/avx512/resolved-image.bin').read_bytes()[0x532e9:0x532ef]
                if self.rsp.read(second_call,6)!=expected or expected!=bytes.fromhex('e87e875c0190'):
                    raise RuntimeError('AVX512 second-check call bytes differ')
                self.rsp.breakpoint(second_call)
                checkpoints={base+0x532dd}
                for address in sorted(checkpoints):self.rsp.breakpoint(address)
                self.rsp.socket.settimeout(90);self.rsp.send('c');repeats={}
                for _ in range(60):
                    packet=self.rsp.receive();row={'packet':packet};info['events'].append(row)
                    if packet.startswith(('W','X')):return
                    if not packet.startswith(('T','S')):return
                    regs=self.rsp.regs();row['registers']=regs;signature=(packet[1:3],regs['rip'])
                    stack=self.rsp.read(regs['rsp'],256)
                    row['stack']=[hex(x) for x in struct.unpack('<32Q',stack)]
                    row['instructionBytes']=self.rsp.read(regs['rip'],32).hex()
                    address=next((a for a in checkpoints if regs['rip'] in (a,a+1)),None)
                    if address is not None:
                        row['checkpointRva']=hex(address-base)
                        self.rsp.breakpoint(address,remove=True);checkpoints.remove(address)
                        if address==base+0x532dd:
                            expected=bytes.fromhex('e89e9c050031c9e867550c00')
                            if self.rsp.read(address,len(expected))!=expected:raise RuntimeError('Startup rejection sequence changed')
                            info['startupRejectionDiagnostic']={'originalRax':regs['rax'],'fromRva':'0x532dd','toRva':'0x532e9','scope':'this isolated process only'}
                            self.rsp.setreg('rip',second_call)
                        else:self.rsp.setreg('rip',address)
                        self.save()
                        self.rsp.send('c');continue
                    if regs['rip'] in (second_call,second_call+1):
                        self.rsp.breakpoint(second_call,remove=True)
                        self.rsp.setreg('rip',second_call+6)
                        self.rsp.setreg('rax',regs['rax']&~255)
                        info['secondCheckCallSkipped']=True
                        from guest_login_network_trace import LoginNetworkTrace
                        self.network_trace=LoginNetworkTrace(self)
                        self.rsp.socket.settimeout(8)
                        self.continue_rsp()
                        self.rsp_control_ready=True
                        self.save()
                        return
                    repeats[signature]=repeats.get(signature,0)+1
                    if packet[1:3] not in ('0b','05','04') or repeats[signature]>3:return
                    self.rsp.send('C'+packet[1:3])
            except Exception:
                info['error']=traceback.format_exc();self.save()
                if self.process.poll() is None:
                    self.report['testAbortedByHarness']=True
                    self.process.terminate()
        threading.Thread(target=attach,daemon=True).start()

    def cleanup(self):
        # Closing a completed/timed-out test must not wait on a departed RSP
        # target or prevent the final summary from being persisted.
        self.rsp_control_ready=False;self.rsp_owner=None
        try:super().cleanup()
        except Exception:
            self.report['cleanupError']=traceback.format_exc()
            if self.process.poll() is None:self.process.terminate()
        if hasattr(self,'rsp'):
            try:self.rsp.close()
            except Exception:pass
        if hasattr(self,'sde'):
            try:self.sde.wait(timeout=8)
            except subprocess.TimeoutExpired:self.sde.kill();self.sde.wait(timeout=5)
            for stream in self.sde_streams:stream.close()
            self.report['lateAttach'].update(exitCode=self.sde.returncode,
                stdout=(self.out/'sde-stdout.txt').read_text(errors='replace'),stderr=(self.out/'sde-stderr.txt').read_text(errors='replace'))


"""Delay one byte checkpoint until the main code page actually executes.

Readable bytes are unchanged during early integrity checks. A process-local
temporary non-executable page is restored on its first access violation.
"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import json
import struct
import subprocess
import sys
import time

ROOT=Path(r'C:\Lab\BugChess20260627')
sys.path.insert(0,str(Path(__file__).resolve().parent))
from guest_firmware_scanner_probe import ScannerProbe,capture_stub,FIELDS
from guest_firmware_guard import GuardTrace,make_handler,make_registration
from guest_syscall_gate_trace import MBI

class MainProbe(ScannerProbe):
    def __init__(self,out):
        super().__init__(out,True,True)
        self.page=None
        self.page_prior=None
        self.page_restored=False
        self.cp=None
        self.prefix_mode='--prefix' in sys.argv
        self.prefix_done=False
        self.pass_second='--pass-second' in sys.argv
        self.login_probe='--login-probe' in sys.argv
        self.login_inputs=0
        self.network_trace=None
        self.report['loginInputs']=[]
        self.report['caseFileNamesBefore']=sorted(p.name for p in self.engine.parent.iterdir() if p.is_file())
        if self.login_probe:
            if not self.pass_second: raise ValueError('Login probe requires the established startup diagnostic')
            script="$rows = Get-NetFirewallRule -DisplayName 'Task-BugChess20260627-BMI2-v47-*' | ForEach-Object { $a = $_ | Get-NetFirewallApplicationFilter; [pscustomobject]@{Name=$_.DisplayName;Enabled=$_.Enabled.ToString();Action=$_.Action.ToString();Direction=$_.Direction.ToString();Program=$a.Program} }; @($rows) | ConvertTo-Json -Compress"
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW,timeout=20)
            if result.returncode: raise RuntimeError('Could not verify the scoped offline rules')
            rules=json.loads(result.stdout.decode('utf-8-sig'))
            if isinstance(rules,dict): rules=[rules]
            verified=[r for r in rules if r['Enabled']=='True' and r['Action']=='Block' and r['Program'].casefold()==str(self.engine).casefold()]
            if {r['Direction'] for r in verified}!={'Inbound','Outbound'}:
                raise RuntimeError('Both exact-executable offline rules must be active')
            self.report['loginNetwork']='verified exact-executable inbound/outbound block'
        self.report['startupCheckpoints']=[]
        self.report['protectionRearms']=[]

    def arm_exit(self):
        super().arm_exit()
        self.pause()
        saved_alloc,saved_record=self.allocation,self.record
        self.k.CloseHandle.argtypes=[W.HANDLE]
        try:
            self.trace_alloc=self.k.VirtualAllocEx(self.handle,None,0x3000,0x3000,4)
            if not self.trace_alloc: raise C.WinError(C.get_last_error())
            self.trace_record=self.trace_alloc+0x1000
            handler=make_handler(self.trace_record)
            # Reuse the validated bounded VEH layout, changing only the exception code.
            assert handler.count(bytes.fromhex('813a01000080'))==1
            handler=handler.replace(bytes.fromhex('813a01000080'),bytes.fromhex('813a050000c0'))
            api=C.cast(self.n.RtlAddVectoredExceptionHandler,C.c_void_p).value
            if self.read(api,16)!=C.string_at(api,16):
                raise RuntimeError('Unexpected handler registration mapping')
            registration=make_registration(self.trace_alloc,self.trace_record,api)
            self.write(self.trace_alloc,handler)
            old=W.DWORD()
            if not self.k.VirtualProtectEx(self.handle,self.trace_alloc,4096,0x20,C.byref(old)):
                raise C.WinError(C.get_last_error())
            self.k.FlushInstructionCache(self.handle,self.trace_alloc,4096)
            self.allocation,self.record=self.trace_alloc,self.trace_record
            GuardTrace.register_on_existing_thread(self,registration)
            if int.from_bytes(self.read(self.trace_record+0x60,8),'little')==0:
                raise RuntimeError('Handler registration did not return a token')
            self.page=int(self.report['base'],16)+0x54000
            self.write(self.trace_record+0x20,struct.pack('<4Q',self.page,self.page+4096,self.page,self.page+4096))
            self.write(self.trace_record+4,struct.pack('<I',1))
            prior=W.DWORD()
            if not self.k.VirtualProtectEx(self.handle,self.page,4096,2,C.byref(prior)):
                raise C.WinError(C.get_last_error())
            self.page_prior=prior.value
            self.report.update(executionPage=hex(self.page),executionOriginalProtect=hex(prior.value))
        finally:
            self.allocation,self.record=saved_alloc,saved_record
            self.resume()

    def restore_page(self):
        if self.page_prior is not None and not self.page_restored:
            old=W.DWORD()
            if not self.k.VirtualProtectEx(self.handle,self.page,4096,self.page_prior,C.byref(old)):
                raise C.WinError(C.get_last_error())
            self.page_restored=True

    def login_modules(self):
        k=self.k
        k.K32EnumProcessModulesEx.argtypes=[W.HANDLE,C.POINTER(W.HMODULE),W.DWORD,C.POINTER(W.DWORD),W.DWORD]
        k.K32GetModuleFileNameExW.argtypes=[W.HANDLE,W.HMODULE,W.LPWSTR,W.DWORD]
        modules=(W.HMODULE*1024)()
        needed=W.DWORD()
        rows=[]
        if k.K32EnumProcessModulesEx(self.handle,modules,C.sizeof(modules),C.byref(needed),3):
            for address in list(modules)[:min(1024,needed.value//C.sizeof(W.HMODULE))]:
                name=C.create_unicode_buffer(2048)
                if k.K32GetModuleFileNameExW(self.handle,address,name,2048):
                    rows.append({'name':Path(name.value).name,'base':hex(address)})
        self.report['loginModules']=rows

    def arm_result(self,base):
        entry=self.prefix_mode and not self.prefix_done
        rva=0x54be9 if entry else 0x54bef
        target=base+rva
        reference=Path('C:\\Lab\\BugChess20260627\\evidence\\variants-resolved-v55\\bmi2\\resolved-image.bin').read_bytes()[rva:rva+14]
        original=self.read(target,14)
        if original!=reference: raise RuntimeError('Second-result checkpoint bytes changed')
        record=self.allocation+(0x2400 if entry else 0x2500)
        code=self.allocation+(0xa00 if entry else 0xc00)
        self.protected_write(code,capture_stub(record,target))
        self.protected_write(target,b'\xff\x25\0\0\0\0'+struct.pack('<Q',code))
        self.cp={'target':target,'record':record,'original':original,'restored':False,'entry':entry}

    def capture_exit(self,base,image_size):
        duration=next((float(a.split('=',1)[1]) for a in sys.argv if a.startswith('--capture-seconds=')),10)
        if '--interactive-bridge' in sys.argv:
            duration=86400
        elif not 1<=duration<=90:
            raise ValueError('Capture duration must be between 1 and 90 seconds')
        deadline=time.monotonic()+duration
        try:
            while time.monotonic()<deadline and self.process.poll() is None:
                if self.network_trace:
                    self.network_trace.poll()
                    if self.report.get('flowObservationComplete'):
                        break
                if self.login_probe and '--account-only' not in sys.argv:
                    output=(self.out/'stdout.bin').read_bytes().lower()
                    text=None
                    if self.login_inputs==0 and b'login:' in output:
                        text='xtprobe01 # xTprobe02'
                        if '--documented-prefix' in sys.argv:
                            text='login: '+text
                    if text is not None:
                        self.login_modules()
                        if '--network-trace' in sys.argv and self.network_trace is None:
                            from guest_login_network_trace import LoginNetworkTrace
                            self.network_trace=LoginNetworkTrace(self)
                        image=b''.join(self.read(base+i,min(1024*1024,image_size-i)) for i in range(0,image_size,1024*1024))
                        (self.out/'login-image.bin').write_bytes(image)
                        self.report['loginImageBytes']=len(image)
                        self.process.stdin.write((text+'\n').encode('ascii'))
                        self.process.stdin.flush()
                        self.login_inputs+=1
                        self.report['loginInputs'].append({'kind':'synthetic-login-line','format':'username # password',
                            'literalLoginPrefix':'--documented-prefix' in sys.argv,
                            'elapsed':round(time.monotonic()-self.started,6)})
                        self.save()
                        deadline=time.monotonic()+15
                if not self.page_restored:
                    memory=MBI()
                    if self.k.VirtualQueryEx(self.handle,self.page,C.byref(memory),C.sizeof(memory)) and memory.protect&0xf0:
                        prior=W.DWORD()
                        if self.k.VirtualProtectEx(self.handle,self.page,4096,2,C.byref(prior)):
                            self.page_prior=prior.value
                            self.report['protectionRearms'].append({'from':hex(prior.value),'elapsed':round(time.monotonic()-self.started,6)})
                if not self.page_restored and self.read(self.trace_record+0x10,4)==b'\x01\0\0\0':
                    blob=self.read(self.trace_record,0x700)
                    seq=int.from_bytes(blob[8:16],'little')
                    context=blob[0x100:0x5d0]
                    names=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rip')
                    regs={n:struct.unpack_from('<Q',context,0x78+i*8)[0] for i,n in enumerate(names)}
                    operation=struct.unpack_from('<Q',blob,0x620)[0]
                    self.report['mainPageAccess']={'operation':operation,'rip':hex(regs['rip']),
                        'registers':{k:hex(v) for k,v in regs.items()},'elapsed':round(time.monotonic()-self.started,6)}
                    (self.out/'main-page-context.bin').write_bytes(context)
                    (self.out/'main-page-stack.bin').write_bytes(self.read(regs['rsp'],4096))
                    self.restore_page()
                    if operation==8:
                        self.arm_result(base)
                    self.write(self.trace_record+4,struct.pack('<I',0))
                    self.write(self.trace_record+0x18,struct.pack('<Q',seq))
                    self.save()
                if self.cp and not self.cp['restored'] and self.read(self.cp['record'],4)==b'\x01\0\0\0':
                    current=self.cp
                    raw=self.read(current['record'],0xa0)
                    regs={n:struct.unpack_from('<Q',raw,o)[0] for n,o in FIELDS.items()}
                    name='second-entry' if current['entry'] else 'second-result'
                    self.report['startupCheckpoints'].append({'name':name,'AL':regs['rax']&255,
                        **self.snapshot(regs,name,base)})
                    self.protected_write(current['target'],current['original'])
                    current['restored']=True
                    if self.pass_second and not current['entry']:
                        original_rax=struct.pack('<Q',regs['rax'])
                        saved_rax=regs['rsp']-16
                        if self.read(saved_rax,8)!=original_rax:
                            raise RuntimeError('Return gate saved RAX does not match the captured value')
                        changed=struct.pack('<Q',regs['rax']&~255)
                        self.write(saved_rax,changed)
                        if self.read(saved_rax,8)!=changed:
                            raise RuntimeError('Diagnostic result writeback failed')
                        self.report.update(returnValueChanged=True,controlFlowChanged=True,
                            secondResultDiagnostic={'originalAL':regs['rax']&255,'appliedAL':0,
                                'scope':'single owned child and this invocation only; original instruction bytes restored'})
                        if '--network-early' in sys.argv and self.network_trace is None:
                            from guest_login_network_trace import LoginNetworkTrace
                            self.network_trace=LoginNetworkTrace(self)
                    if current['entry']:
                        from guest_live_prefix_emulator import emulate
                        teb,tid=struct.unpack_from('<QQ',raw,0x90)
                        self.report['secondPrefix']=emulate(self,regs,current['target'],base+0x54bef,teb,tid)
                        self.prefix_done=True
                        self.arm_result(base)
                        deadline=time.monotonic()+10
                    self.save()
                    self.write(current['record']+4,struct.pack('<I',1))
                if self.read(self.exit_record,4)==b'\x01\0\0\0':
                    super().capture_exit(base,image_size)
                    return
                if '--interactive-bridge' in sys.argv:
                    time.sleep(.002)
            self.report['exitCaptured']=False
        finally:
            if self.process.poll() is None:
                try:
                    self.restore_page()
                    if self.cp and not self.cp['restored']:
                        self.protected_write(self.cp['target'],self.cp['original'])
                    if self.cp: self.write(self.cp['record']+4,struct.pack('<I',1))
                    self.write(self.trace_record+0x14,struct.pack('<I',1))
                except OSError as exc:
                    self.report['lateCleanupNote']=str(exc)

    def cleanup(self):
        if self.network_trace: self.network_trace.cleanup()
        super().cleanup()
        self.report['caseFileNamesAfter']=sorted(p.name for p in self.engine.parent.iterdir() if p.is_file())

if __name__=='__main__':
    label=sys.argv[1] if len(sys.argv)>1 else 'main-execute'
    if not label.replace('-','').isalnum(): raise ValueError('Invalid label')
    out=ROOT/'evidence'/('firmware-scanner-'+label)
    out.mkdir(exist_ok=False)
    MainProbe(out).run_probe()

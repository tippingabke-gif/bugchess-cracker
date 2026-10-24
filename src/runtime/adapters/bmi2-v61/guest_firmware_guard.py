"""Guest-only one-shot PAGE_GUARD observations on an exact firmware copy.

First run without --engine for a standalone read/write self-test. Target files,
firmware bytes, exception CONTEXT, and original exit calls are not modified.
"""
from pathlib import Path
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import re
import struct
import subprocess
import sys
import time
import traceback

ROOT=Path(r'C:\Lab\BugChess20260627')
sys.path.insert(0,str(Path(__file__).resolve().parent))
from guest_heap_firmware_compare import HeapCompare
from guest_native_firmware_trace import Code, CASE
import capstone


class ThreadEntry(C.Structure):
    _fields_=[('size',W.DWORD),('usage',W.DWORD),('tid',W.DWORD),('owner',W.DWORD),
              ('basePriority',W.LONG),('deltaPriority',W.LONG),('flags',W.DWORD)]


def make_handler(record):
    b=Code()
    b.emit('53 56 57')
    b.emit(b'\x48\xbb'+struct.pack('<Q',record))
    b.emit('837b0401')
    b.branch('0f85','search')
    b.emit('488b11 813a01000080')
    b.branch('0f85','search')
    b.emit('4c8b4228 4c3b4320')
    b.branch('0f82','search')
    b.emit('4c3b4328')
    b.branch('0f83','search')
    b.emit('4c8b5108')
    b.label('lock')
    b.emit('837b1400')
    b.branch('0f85','handled')
    b.emit('31c0 41b901000000 f0440fb10b')
    b.branch('0f85','spin')
    b.emit('4c894348 658b042548000000 894340')
    b.emit('488bf2 488dbb00060000 b913000000 fc f348a5')
    b.emit('498bf2 488dbb00010000 b99a000000 f348a5')
    b.emit('48ff4308 c7431001000000')
    b.label('gate')
    b.emit('837b1400')
    b.branch('0f85','release')
    b.emit('488b4308 48394318')
    b.branch('0f84','release')
    b.emit('f390')
    b.branch('e9','gate')
    b.label('release')
    b.emit('c7431000000000 c70300000000')
    b.label('handled')
    b.emit('b8ffffffff')
    b.branch('e9','done')
    b.label('search')
    b.emit('31c0')
    b.label('done')
    b.emit('5f 5e 5b c3')
    b.label('spin')
    b.emit('f390')
    b.branch('e9','lock')
    return b.finish()


def make_registration(handler,record,api):
    return (bytes.fromhex('4883ec28 b901000000 48ba')+struct.pack('<Q',handler)
        +b'\x48\xb8'+struct.pack('<Q',api)+bytes.fromhex('ffd0 48ba')+struct.pack('<Q',record)
        +bytes.fromhex('48894260 c7426801000000 31c0 4883c428 c3'))


class GuardTrace(HeapCompare):
    def __init__(self,out,engine_mode,context_registration=False):
        super().__init__(out,False,True)
        self.engine_mode=engine_mode
        self.context_registration=context_registration
        self.guards=[]
        self.guard_armed=False
        self.k.CreateRemoteThread.argtypes=[W.HANDLE,C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)]
        self.k.CreateRemoteThread.restype=W.HANDLE
        self.k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
        self.k.WaitForSingleObject.restype=W.DWORD
        self.k.CloseHandle.argtypes=[W.HANDLE]
        self.report.update(mode='firmware-page-access-observation',engineMode=engine_mode,
            controlFlowChanged=False,firmwareDataChanged=False,contextChanged=False,
            accesses=[],guardPages=[],
            limitations=['PAGE_GUARD is one-shot per page; only the first access to each armed page is captured.',
                         'Other heap objects can share boundary pages; exact payload-range classification is reported.',
                         'Remote handler registration and polling affect timing and may be detectable.',
                         'Finding a copy does not establish that its earlier consumption was observed.'])

    def register_on_existing_thread(self,registration):
        k=self.k
        k.CreateToolhelp32Snapshot.argtypes=[W.DWORD,W.DWORD]
        k.CreateToolhelp32Snapshot.restype=W.HANDLE
        k.Thread32First.argtypes=k.Thread32Next.argtypes=[W.HANDLE,C.POINTER(ThreadEntry)]
        k.OpenThread.argtypes=[W.DWORD,W.BOOL,W.DWORD]
        k.OpenThread.restype=W.HANDLE
        k.GetThreadTimes.argtypes=[W.HANDLE,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p]
        k.GetThreadContext.argtypes=k.SetThreadContext.argtypes=[W.HANDLE,C.c_void_p]
        snapshot=k.CreateToolhelp32Snapshot(4,0)
        if snapshot==C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        candidates=[]
        try:
            entry=ThreadEntry()
            entry.size=C.sizeof(entry)
            success=k.Thread32First(snapshot,C.byref(entry))
            while success:
                if entry.owner==self.process.pid:
                    thread=k.OpenThread(0x5a,False,entry.tid)
                    if thread:
                        times=[C.c_uint64() for _ in range(4)]
                        if k.GetThreadTimes(thread,*[C.byref(t) for t in times]):
                            candidates.append((times[0].value,entry.tid,thread))
                        else:
                            k.CloseHandle(thread)
                success=k.Thread32Next(snapshot,C.byref(entry))
        finally:
            k.CloseHandle(snapshot)
        if not candidates:
            raise RuntimeError('No owned thread available for bounded registration')
        candidates.sort()
        _,tid,thread=candidates[0]
        for _,_,other in candidates[1:]:
            k.CloseHandle(other)
        owner=C.create_string_buffer(1232+16)
        context=(C.addressof(owner)+15)&~15
        C.c_uint32.from_address(context+0x30).value=0x10001f
        saved=None
        diverted=False
        try:
            if not k.GetThreadContext(thread,context):
                raise C.WinError(C.get_last_error())
            saved=C.string_at(context,1232)
            scratch=k.VirtualAllocEx(self.handle,None,0x10000,0x3000,4)
            if not scratch:
                raise C.WinError(C.get_last_error())
            # Replace the helper's final RET by a gate; all original thread state
            # is restored externally after the completed API call, before resuming.
            self.protected_write(self.allocation+0x800,registration[:-1]+b'\xf3\x90\xeb\xfc')
            C.c_uint64.from_address(context+0x98).value=scratch+0x10000-8
            C.c_uint64.from_address(context+0xf8).value=self.allocation+0x800
            if not k.SetThreadContext(thread,context):
                raise C.WinError(C.get_last_error())
            diverted=True
            self.resume()
            until=time.monotonic()+2
            while time.monotonic()<until and self.process.poll() is None:
                if self.read(self.record+0x68,4)==b'\x01\0\0\0':
                    break
            else:
                raise RuntimeError('Existing-thread handler registration did not complete')
            self.pause()
            C.memmove(context,saved,1232)
            if not k.SetThreadContext(thread,context):
                raise C.WinError(C.get_last_error())
            diverted=False
            if not k.GetThreadContext(thread,context):
                raise C.WinError(C.get_last_error())
            restored=C.string_at(context,1232)
            matches=restored[0x78:0x100]==saved[0x78:0x100] and restored[0x100:0x300]==saved[0x100:0x300]
            if not matches:
                raise RuntimeError('Thread register/FP restoration readback mismatch')
            self.report['registrationContext']={'method':'oldest-owned-thread-temporary-context',
                'tid':tid,'originalRip':hex(struct.unpack_from('<Q',saved,0xf8)[0]),
                'originalRsp':hex(struct.unpack_from('<Q',saved,0x98)[0]),'readbackMatches':matches,
                'extendedAVXStateCaptured':False}
        finally:
            if diverted and saved is not None and self.process.poll() is None:
                self.pause()
                C.memmove(context,saved,1232)
                k.SetThreadContext(thread,context)
            k.CloseHandle(thread)

    def register(self):
        self.allocation=self.k.VirtualAllocEx(self.handle,None,0x3000,0x3000,4)
        if not self.allocation:
            raise C.WinError(C.get_last_error())
        self.record=self.allocation+0x1000
        handler=make_handler(self.record)
        api=C.cast(self.n.RtlAddVectoredExceptionHandler,C.c_void_p).value
        if self.read(api,16)!=C.string_at(api,16):
            raise RuntimeError('Remote handler-registration API does not match this guest mapping')
        registration=make_registration(self.allocation,self.record,api)
        self.write(self.allocation,handler)
        self.write(self.allocation+0x800,registration)
        old=W.DWORD()
        if not self.k.VirtualProtectEx(self.handle,self.allocation,0x1000,0x20,C.byref(old)):
            raise C.WinError(C.get_last_error())
        self.k.FlushInstructionCache(self.handle,self.allocation,0x1000)
        tid=W.DWORD()
        if self.context_registration:
            self.register_on_existing_thread(registration)
        else:
            thread=self.k.CreateRemoteThread(self.handle,None,0,self.allocation+0x800,None,0,C.byref(tid))
            if not thread:
                raise C.WinError(C.get_last_error())
            try:
                result=self.k.WaitForSingleObject(thread,1000)
                if result!=0:
                    raise RuntimeError(f'Handler registration thread did not finish while target paused: {result:#x}')
            finally:
                self.k.CloseHandle(thread)
        token=int.from_bytes(self.read(self.record+0x60,8),'little')
        done=int.from_bytes(self.read(self.record+0x68,4),'little')
        if not token or done!=1:
            raise RuntimeError('Vectored handler registration failed')
        self.report.update(handler=hex(self.allocation),handlerToken=hex(token),registrationTid=tid.value)
        self.report['handlerDisassembly']=[{'offset':hex(i.address),'asm':i.mnemonic+' '+i.op_str}
            for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(handler,0)]

    def arm(self,address,size):
        begin=address&~0xfff
        end=(address+size+0xfff)&~0xfff
        self.payload=(address,address+size)
        self.write(self.record+0x20,struct.pack('<4Q',begin,end,address,address+size))
        self.write(self.record+4,struct.pack('<I',1))
        self.guard_armed=True
        for page in range(begin,end,0x1000):
            old=W.DWORD()
            if not self.k.VirtualProtectEx(self.handle,page,0x1000,0x104,C.byref(old)):
                raise C.WinError(C.get_last_error())
            self.guards.append((page,old.value))
            self.report['guardPages'].append({'address':hex(page),'originalProtect':hex(old.value)})
        self.report.update(guardArmedAt=round(time.monotonic()-self.started,6),
                           payloadAddress=hex(address),payloadBytes=size,status='guard-armed')
        self.save()

    def capture(self,blob):
        seq=int.from_bytes(blob[8:16],'little')
        context=blob[0x100:0x5d0]
        ex=blob[0x600:0x698]
        rip=struct.unpack_from('<Q',context,0xf8)[0]
        fault=struct.unpack_from('<Q',ex,0x28)[0]
        operation=struct.unpack_from('<Q',ex,0x20)[0]
        names=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rip')
        regs={name:hex(struct.unpack_from('<Q',context,0x78+i*8)[0]) for i,name in enumerate(names)}
        code=self.read(rip,64)
        decoded=[{'address':hex(i.address),'asm':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()}
            for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(code,rip)]
        prefix=f'{seq:04d}'
        (self.out/(prefix+'-context.bin')).write_bytes(context)
        (self.out/(prefix+'-exception.bin')).write_bytes(ex)
        rsp=int(regs['rsp'],16)
        (self.out/(prefix+'-stack.bin')).write_bytes(self.read(rsp,2048))
        row={'sequence':seq,'tid':int.from_bytes(blob[0x40:0x44],'little'),
             'operation':{0:'read',1:'write',8:'execute'}.get(operation,str(operation)),
             'faultAddress':hex(fault),'withinPayload':self.payload[0]<=fault<self.payload[1],
             'payloadOffset':fault-self.payload[0],'registers':regs,'instructions':decoded[:16],
             'elapsed':round(time.monotonic()-self.started,6)}
        self.report['accesses'].append(row)
        self.save()
        self.write(self.record+0x18,struct.pack('<Q',seq))

    def cleanup(self):
        try:
            if self.process is not None and self.process.poll() is None:
                try:
                    self.pause()
                    for page,protect in self.guards:
                        previous=W.DWORD()
                        self.k.VirtualProtectEx(self.handle,page,0x1000,protect,C.byref(previous))
                    if self.record:
                        self.write(self.record+0x14,struct.pack('<I',1))
                        self.write(self.record+4,struct.pack('<I',0))
                    self.report['cleanup']['guardsRestored']=True
                except Exception as error:
                    self.report['cleanup']['guardRestoreError']=str(error)
                finally:
                    self.resume()
        finally:
            super().cleanup()

    def selftest_start(self):
        script=self.out/'child.py'
        script.write_text('''from pathlib import Path
import ctypes as C,json,time
from ctypes import wintypes as W
root=Path(__file__).parent
k=C.WinDLL('kernel32')
k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,W.DWORD,W.DWORD]
k.VirtualAlloc.restype=C.c_void_p
p=k.VirtualAlloc(None,8192,0x3000,4)
assert p
C.c_ubyte.from_address(p+128).value=42
(root/'ready.json').write_text(json.dumps({'address':p,'size':8192}))
for _ in range(1000):
    if (root/'go').exists():break
    time.sleep(.01)
else:raise RuntimeError('go deadline')
v=C.c_ubyte.from_address(p+128).value
C.c_ubyte.from_address(p+4096+128).value=77
print(json.dumps({'read':v,'written':C.c_ubyte.from_address(p+4096+128).value}),flush=True)
''',encoding='utf-8')
        return [sys.executable,'-I',str(script)]

    def run_guard(self):
        try:
            if self.engine_mode:
                proof_path='evidence/firmware-guard-selftest-context/summary.json' if self.context_registration else 'evidence/firmware-guard-selftest/summary.json'
                proof=json.loads((ROOT/proof_path).read_text())
                if not proof.get('selfTestPassed'):
                    raise RuntimeError('Successful guard self-test is required')
                args=[str(self.engine)]
            else:
                args=self.selftest_start()
            self.timer_active=self.winmm.timeBeginPeriod(1)==0
            with (self.out/'stdout.bin').open('xb') as stdout,(self.out/'stderr.bin').open('xb') as stderr:
                self.process=subprocess.Popen(args,cwd=CASE,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,
                    creationflags=subprocess.CREATE_NO_WINDOW|4)
                self.suspended=True
                info,used=(C.c_void_p*6)(),W.ULONG()
                if self.n.NtQueryInformationProcess(self.handle,0,info,C.sizeof(info),C.byref(used))<0:
                    raise RuntimeError('Process basic information failed')
                base=int.from_bytes(self.read(int(info[1])+0x10,8),'little')
                self.report['base']=hex(base)
                self.resume()
                deadline=self.started+25
                if self.engine_mode:
                    trigger=C.cast(self.k.TerminateProcess,C.c_void_p).value
                    while self.process.poll() is None and time.monotonic()<deadline:
                        raw=self.read(base+0xab025d,8)
                        if len(raw)==8 and (int.from_bytes(raw,'little')+0x2ca606a5)&0xffffffffffffffff==trigger:
                            self.pause()
                            break
                    else:
                        raise RuntimeError('Import trigger not reached')
                else:
                    ready=self.out/'ready.json'
                    while time.monotonic()<deadline and self.process.poll() is None:
                        if ready.exists():
                            data=json.loads(ready.read_text())
                            self.pause()
                            break
                        time.sleep(.01)
                    else:
                        raise RuntimeError('Selftest child not ready')
                self.register()
                if not self.engine_mode:
                    self.arm(data['address'],data['size'])
                    (self.out/'go').write_text('go')
                self.resume()
                seen=0
                while time.monotonic()<deadline and self.process.poll() is None:
                    if not self.guard_armed:
                        self.pause()
                        try:
                            found=None
                            for address,size in self.regions():
                                for start in range(address,address+size,1024*1024):
                                    memory=self.read(start,min(1024*1024+len(self.raw),address+size-start))
                                    offset=memory.find(self.raw)
                                    if offset>=0:
                                        candidate=start+offset
                                        if self.read(candidate,len(self.raw))==self.raw:
                                            found=candidate
                                            break
                                if found is not None:
                                    break
                            self.report['scans']+=1
                            if found is not None:
                                self.arm(found,len(self.raw))
                        finally:
                            self.resume()
                        time.sleep(.001)
                    else:
                        blob=self.read(self.record,0x700)
                        if len(blob)==0x700:
                            seq=int.from_bytes(blob[8:16],'little')
                            if int.from_bytes(blob[0x10:0x14],'little')==1 and seq!=seen:
                                self.capture(blob)
                                seen=seq
                self.report['naturalExitCode']=self.process.poll()
                self.report['status']='natural-exit' if self.process.poll() is not None else 'timeout'
        except Exception:
            self.report.update(status='error',error=traceback.format_exc())
        finally:
            try:
                self.cleanup()
            except Exception:
                self.report['cleanup']['error']=traceback.format_exc()
            if self.timer_active:
                self.winmm.timeEndPeriod(1)
            output=(self.out/'stdout.bin').read_bytes() if (self.out/'stdout.bin').exists() else b''
            self.report.update(stdoutPreview=output[:2000].decode(errors='replace'),stdoutBytes=len(output),
                loginPrompt=b'please input login name and password!' in output,elapsed=round(time.monotonic()-self.started,3))
            kinds={x['operation'] for x in self.report['accesses']}
            self.report['selfTestPassed']=bool(not self.engine_mode and self.report.get('naturalExitCode')==0
                and {'read','write'}<=kinds and b'"read": 42' in output and b'"written": 77' in output)
            self.save()
            self.events.close()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine',action='store_true')
    p.add_argument('--label')
    p.add_argument('--context-register',action='store_true')
    a=p.parse_args()
    label=a.label or ('engine' if a.engine else 'selftest')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',label):
        raise ValueError('Invalid label')
    out=ROOT/'evidence'/('firmware-guard-'+label)
    out.mkdir(exist_ok=False)
    GuardTrace(out,a.engine,a.context_register).run_guard()

"""Observe the dynamically confirmed firmware scanner at entry and return.

--fixture replaces only an exact complete guest RSMB buffer before its first
scanner instruction. The original function and its boolean return run unchanged.
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
sys.path.insert(0,str(ROOT))
from guest_heap_firmware_compare import HeapCompare
import capstone

FIELDS={'rcx':0x10,'rdx':0x18,'rbx':0x20,'rbp':0x28,'rsi':0x30,'rdi':0x38,
        **{'r'+str(i):0x40+(i-8)*8 for i in range(8,16)},'rax':8,'rsp':0x80,'rflags':0x88}


def capture_stub(record,target):
    code=bytearray(b'\x9c\x50\x48\xb8'+struct.pack('<Q',record))
    for modrm,offset in ((0x48,0x10),(0x50,0x18),(0x58,0x20),(0x68,0x28),(0x70,0x30),(0x78,0x38)):
        code+=bytes([0x48,0x89,modrm,offset])
    for index in range(8):
        code+=bytes([0x4c,0x89,0x40+index*8,0x40+index*8])
    code+=bytes.fromhex('488b0c2448894808488d4c241048898880000000488b4c240848898888000000')
    code+=bytes.fromhex('65488b0c253000000048898890000000658b0c254800000048898898000000')
    code+=bytes.fromhex('c70001000000f3908378040175f8488b4810589dff2500000000')+struct.pack('<Q',target)
    return bytes(code)


class ScannerProbe(HeapCompare):
    def __init__(self,out,fixture,observe_exit=False):
        super().__init__(out,fixture,True)
        self.original_code=None
        self.entry=None
        self.entry_restored=False
        self.return_record=None
        self.observe_exit=observe_exit
        self.exit_target=None
        self.exit_original=None
        self.exit_restored=False
        self.report.update(mode='confirmed-firmware-scanner-entry-return',
            sourceExeModified=False,returnValueChanged=False,firmwareDataChanged=False,
            scannerRva='0x240725c',entryCaptured=False,returnCaptured=False,
            limitations=['One scanner invocation is recorded; subsequent calls are unmodified and unobserved.',
                         'Temporary entry jump and return-address routing affect timing.',
                         'Register/context gates preserve original state; fixture mode changes only verified input data.'])

    def arm_exit(self):
        self.exit_target=C.cast(self.k.ExitProcess,C.c_void_p).value
        expected=C.string_at(self.exit_target,14)
        self.exit_original=self.read(self.exit_target,14)
        if self.exit_original!=expected:
            raise RuntimeError('Guest ExitProcess entry differs from the observer export')
        self.exit_record=self.allocation+0x2100
        self.protected_write(self.allocation+0x800,capture_stub(self.exit_record,self.exit_target))
        self.protected_write(self.exit_target,b'\xff\x25\0\0\0\0'+struct.pack('<Q',self.allocation+0x800))
        self.report['exitObservationArmed']=True

    def capture_exit(self,base,image_size):
        regs=self.wait_record(self.exit_record,8)
        if regs is None:
            self.report['exitCaptured']=False
            return
        self.report['exitCaptured']=True
        self.report['exit']=self.snapshot(regs,'exit',base)
        self.report['exitArgument']=hex(regs['rcx']&0xffffffff)
        stack=self.read(regs['rsp'],0x4000)
        (self.out/'exit-stack.bin').write_bytes(stack)
        self.report['exitStackCandidates']=[{'offset':hex(i),'rva':hex(struct.unpack_from('<Q',stack,i)[0]-base)}
            for i in range(0,len(stack)-7,8) if base<=struct.unpack_from('<Q',stack,i)[0]<base+image_size]
        image=b''.join(self.read(base+i,min(1024*1024,image_size-i)) for i in range(0,image_size,1024*1024))
        (self.out/'exit-image.bin').write_bytes(image)
        self.report['exitImage']={'bytes':len(image),'sha256':hashlib.sha256(image).hexdigest()}
        self.protected_write(self.exit_target,self.exit_original)
        self.exit_restored=True
        self.report['exitBytesRestored']=self.read(self.exit_target,14)==self.exit_original
        self.save()
        self.write(self.exit_record+4,struct.pack('<I',1))

    def wait_record(self,record,timeout):
        until=time.monotonic()+timeout
        while time.monotonic()<until and self.process.poll() is None:
            if self.read(record,4)==b'\x01\0\0\0':
                raw=self.read(record,0x90)
                if len(raw)==0x90:
                    return {name:struct.unpack_from('<Q',raw,off)[0] for name,off in FIELDS.items()}
        return None

    def snapshot(self,regs,name,base):
        stack=self.read(regs['rsp'],2048)
        (self.out/(name+'-stack.bin')).write_bytes(stack)
        row={'registers':{k:hex(v) for k,v in regs.items()},'elapsed':round(time.monotonic()-self.started,6)}
        if len(stack)>=8:
            row['stackTop']=hex(struct.unpack_from('<Q',stack)[0])
        return row

    def run_probe(self):
        try:
            saved=(ROOT/'evidence/probe-exit-defer-once/termination-image.bin').read_bytes()
            expected=saved[0x240725c:0x240725c+14]
            with (self.out/'stdout.bin').open('xb') as stdout,(self.out/'stderr.bin').open('xb') as stderr:
                self.process=subprocess.Popen([str(self.engine)],cwd=self.engine.parent,stdin=subprocess.PIPE,
                    stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW|4)
                self.suspended=True
                info,used=(C.c_void_p*6)(),W.ULONG()
                if self.n.NtQueryInformationProcess(self.handle,0,info,C.sizeof(info),C.byref(used))<0:
                    raise RuntimeError('Process basic information failed')
                base=int.from_bytes(self.read(int(info[1])+0x10,8),'little')
                self.entry=base+0x240725c
                self.report.update(base=hex(base),pid=self.process.pid)
                self.resume()
                trigger=C.cast(self.k.TerminateProcess,C.c_void_p).value
                until=time.monotonic()+8
                while time.monotonic()<until and self.process.poll() is None:
                    raw=self.read(base+0x15e6dc0,8)
                    if len(raw)==8 and (int.from_bytes(raw,'little')+0x558e6980)&0xffffffffffffffff==trigger:
                        self.pause()
                        break
                else:
                    raise RuntimeError('Import trigger not reached')
                self.original_code=self.read(self.entry,14)
                if self.original_code!=expected:
                    raise RuntimeError('Confirmed scanner entry bytes do not match saved runtime evidence')
                self.allocation=self.k.VirtualAllocEx(self.handle,None,0x3000,0x3000,4)
                if not self.allocation:
                    raise C.WinError(C.get_last_error())
                self.record=self.allocation+0x1000
                self.return_record=self.allocation+0x2000
                stub=capture_stub(self.record,self.entry)
                self.write(self.allocation,stub)
                old=W.DWORD()
                if not self.k.VirtualProtectEx(self.handle,self.allocation,0x1000,0x20,C.byref(old)):
                    raise C.WinError(C.get_last_error())
                self.k.FlushInstructionCache(self.handle,self.allocation,0x1000)
                self.protected_write(self.entry,b'\xff\x25\0\0\0\0'+struct.pack('<Q',self.allocation))
                self.report['armedAt']=round(time.monotonic()-self.started,6)
                self.resume()
                entry=self.wait_record(self.record,8)
                if entry is None:
                    raise RuntimeError('Scanner entry was not observed')
                self.report['entryCaptured']=True
                self.report['entry']=self.snapshot(entry,'entry',base)
                pointer,length=entry['rcx'],entry['rdx']
                if not 0<length<=4*1024*1024:
                    raise RuntimeError('Unexpected scanner input length')
                data=self.read(pointer,length)
                (self.out/'scanner-input.bin').write_bytes(data)
                self.report['input']={'address':hex(pointer),'length':length,'bytesRead':len(data),
                    'sha256':hashlib.sha256(data).hexdigest(),'exactGuestFirmware':data==self.raw}
                image=b''.join(self.read(base+i,min(1024*1024,len(saved)-i)) for i in range(0,len(saved),1024*1024))
                (self.out/'scanner-entry-image.bin').write_bytes(image)
                self.report['image']={'bytes':len(image),'sha256':hashlib.sha256(image).hexdigest()}
                original_return=int.from_bytes(self.read(entry['rsp'],8),'little')
                self.report['originalReturn']=hex(original_return)
                caller=self.read(original_return-64,256)
                (self.out/'caller-code.bin').write_bytes(caller)
                self.report['callerAfterReturn']=[{'address':hex(i.address),'asm':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()}
                    for i in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(caller[64:],original_return)]
                if self.fixture:
                    if data!=self.raw:
                        raise RuntimeError('Fixture requires an exact complete guest firmware match')
                    self.write(pointer,self.replaced)
                    if self.read(pointer,length)!=self.replaced:
                        raise RuntimeError('Fixture writeback mismatch')
                    self.report.update(firmwareDataChanged=True,fixtureAppliedBeforeScannerFirstInstruction=True)
                return_stub=capture_stub(self.return_record,original_return)
                self.protected_write(self.allocation+0x400,return_stub)
                self.write(entry['rsp'],struct.pack('<Q',self.allocation+0x400))
                self.protected_write(self.entry,self.original_code)
                self.entry_restored=True
                self.report['entryBytesRestored']=self.read(self.entry,14)==self.original_code
                self.save()
                self.write(self.record+4,struct.pack('<I',1))
                returned=self.wait_record(self.return_record,8)
                if returned is not None:
                    self.report['returnCaptured']=True
                    self.report['returned']=self.snapshot(returned,'return',base)
                    self.report['returnedAL']=returned['rax']&255
                    self.save()
                    if self.observe_exit:
                        self.arm_exit()
                    self.write(self.return_record+4,struct.pack('<I',1))
                    if self.observe_exit:
                        self.capture_exit(base,len(saved))
                else:
                    self.report['returnNotObserved']=True
                try:
                    self.process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    self.report['stillRunningAfterReturn']=True
                self.report['naturalExitCode']=self.process.poll()
                self.report['status']='observed' if self.report['returnCaptured'] else 'incomplete'
        except Exception:
            self.report.update(status='error',error=traceback.format_exc())
        finally:
            if self.process is not None and self.process.poll() is None:
                try:
                    if self.original_code is not None and not self.entry_restored:
                        self.protected_write(self.entry,self.original_code)
                    if self.exit_original is not None and not self.exit_restored:
                        self.protected_write(self.exit_target,self.exit_original)
                    if hasattr(self,'exit_record'):
                        self.write(self.exit_record+4,struct.pack('<I',1))
                    for record in (self.record,self.return_record):
                        if record:
                            self.write(record+4,struct.pack('<I',1))
                except Exception as error:
                    self.report['cleanup']['restoreError']=str(error)
            self.cleanup()
            output=(self.out/'stdout.bin').read_bytes() if (self.out/'stdout.bin').exists() else b''
            self.report.update(stdoutPreview=output[:3000].decode(errors='replace'),stdoutBytes=len(output),
                loginPrompt=b'please input login name and password!' in output,elapsed=round(time.monotonic()-self.started,3))
            self.save()
            self.events.close()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fixture',action='store_true')
    p.add_argument('--label')
    p.add_argument('--observe-exit',action='store_true')
    a=p.parse_args()
    label=a.label or ('fixture' if a.fixture else 'baseline')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',label):
        raise ValueError('Invalid label')
    out=ROOT/'evidence'/('firmware-scanner-'+label)
    out.mkdir(exist_ok=False)
    ScannerProbe(out,a.fixture,a.observe_exit).run_probe()

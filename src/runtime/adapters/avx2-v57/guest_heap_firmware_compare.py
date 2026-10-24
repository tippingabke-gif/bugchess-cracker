"""Guest-only bounded A/B of an exact complete firmware copy in target memory.

Baseline observes only. --fixture changes equal-length SMBIOS string data in the
owned child after exact byte verification; the EXE and host firmware are untouched.
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
from guest_native_firmware_trace import Trace, CASE
from guest_syscall_gate_trace import MBI
from firmware_fixture import mask_virtualization_strings


class HeapCompare(Trace):
    def __init__(self,out,fixture,resolved):
        super().__init__(out,CASE/'BugChessNN_20260627_release_AVX2.exe',True)
        self.fixture=fixture
        self.resolved=resolved
        self.winmm=C.WinDLL('winmm')
        self.timer_active=False
        self.k.VirtualQueryEx.argtypes=[W.HANDLE,C.c_void_p,C.POINTER(MBI),C.c_size_t]
        self.k.VirtualQueryEx.restype=C.c_size_t
        self.k.GetSystemFirmwareTable.argtypes=[W.DWORD,W.DWORD,C.c_void_p,W.DWORD]
        self.k.GetSystemFirmwareTable.restype=W.UINT
        size=self.k.GetSystemFirmwareTable(0x52534d42,0,None,0)
        if not 8<=size<=1024*1024:
            raise RuntimeError('Unexpected firmware size')
        raw=C.create_string_buffer(size)
        got=self.k.GetSystemFirmwareTable(0x52534d42,0,raw,size)
        if got!=size:
            raise RuntimeError('Incomplete guest firmware')
        self.raw=raw.raw
        replaced,changes=mask_virtualization_strings(struct.pack('<4I',0x52534d42,1,0,size)+self.raw)
        self.replaced=replaced[16:]
        self.report.update(mode='exact-complete-heap-firmware-comparison',fixtureRequested=fixture,
            firmwareDataChanged=False,sourceExeModified=False,matches=[],scans=0,
            referenceBytes=size,referenceSha256=hashlib.sha256(self.raw).hexdigest(),
            fixtureSha256=hashlib.sha256(self.replaced).hexdigest(),changedStringSets=changes,
            limitations=['Polling may observe a copy after it has already been consumed.',
                         'Only readable private allocations up to 16 MiB per region are searched.',
                         'Suspension and memory reads change timing; baseline is required for comparison.'])

    def regions(self):
        rows=[]
        cursor=0x10000
        while cursor<0x7fffffff0000:
            m=MBI()
            if not self.k.VirtualQueryEx(self.handle,cursor,C.byref(m),C.sizeof(m)):
                break
            end=(m.base or 0)+m.size
            if end<=cursor:
                break
            if m.state==0x1000 and m.kind==0x20000 and not m.protect&0x101 and m.protect&0xee:
                if len(self.raw)<=m.size<=16*1024*1024:
                    rows.append((m.base,m.size))
            cursor=end
        return rows

    def run_compare(self):
        try:
            self.timer_active=self.winmm.timeBeginPeriod(1)==0
            self.report['oneMillisecondTimer']=self.timer_active
            self.report['sourceSha256']=hashlib.sha256(self.engine.read_bytes()).hexdigest()
            with (self.out/'stdout.bin').open('xb') as stdout,(self.out/'stderr.bin').open('xb') as stderr:
                self.process=subprocess.Popen([str(self.engine)],cwd=CASE,stdin=subprocess.PIPE,
                    stdout=stdout,stderr=stderr,creationflags=subprocess.CREATE_NO_WINDOW|4)
                self.suspended=True
                self.resume()
                deadline=self.started+12
                if self.resolved:
                    info,used=(C.c_void_p*6)(),W.ULONG()
                    s=self.n.NtQueryInformationProcess(self.handle,0,info,C.sizeof(info),C.byref(used))
                    if s<0:
                        raise RuntimeError('Basic process information unavailable')
                    base=int.from_bytes(self.read(int(info[1])+0x10,8),'little')
                    trigger=C.cast(self.k.TerminateProcess,C.c_void_p).value
                    while self.process.poll() is None and time.monotonic()<deadline:
                        raw=self.read(base+0xe3f69e,8)
                        if len(raw)==8 and (int.from_bytes(raw,'little')+-0x37790947)&0xffffffffffffffff==trigger:
                            break
                    else:
                        raise RuntimeError('Resolved import trigger was not reached')
                    self.report['triggerAt']=round(time.monotonic()-self.started,6)
                region_list=[]
                refresh=0
                seen=set()
                while time.monotonic()<deadline and self.process.poll() is None:
                    now=time.monotonic()
                    try:
                        self.pause()
                    except RuntimeError as error:
                        if '0xc000010a' in str(error):
                            self.process.wait(timeout=2)
                            self.report['terminationRaceObserved']=True
                            break
                        raise
                    try:
                        if now>=refresh:
                            region_list=self.regions()
                            refresh=now+0.01
                        for address,size in region_list:
                            # The inherited bounded RPM helper limits each request to 4 MiB.
                            for start in range(address,address+size,1024*1024):
                                data=self.read(start,min(1024*1024+len(self.raw),address+size-start))
                                offset=data.find(self.raw)
                                while offset>=0:
                                    target=start+offset
                                    if target not in seen and self.read(target,len(self.raw))==self.raw:
                                        row={'address':hex(target),'elapsed':round(time.monotonic()-self.started,6),
                                             'exactMatch':True,'bytes':len(self.raw),'dataChanged':False}
                                        if self.fixture:
                                            self.write(target,self.replaced)
                                            if self.read(target,len(self.replaced))!=self.replaced:
                                                raise RuntimeError('Fixture writeback mismatch')
                                            row['dataChanged']=True
                                            self.report['firmwareDataChanged']=True
                                        self.report['matches'].append(row)
                                        seen.add(target)
                                    offset=data.find(self.raw,offset+len(self.raw))
                    finally:
                        self.resume()
                    self.report['scans']+=1
                    if self.report['matches']:
                        self.save()
                    if (self.out/'stdout.bin').stat().st_size>0:
                        output=(self.out/'stdout.bin').read_bytes()
                        if b'please input login name and password!' in output:
                            self.report['status']='login-prompt-reached'
                            break
                    time.sleep(0.001)
                self.report['naturalExitCode']=self.process.poll()
                if self.report['status']!='login-prompt-reached':
                    self.report['status']='natural-exit' if self.process.poll() is not None else 'timeout'
        except Exception:
            self.report.update(status='error',error=traceback.format_exc())
        finally:
            self.cleanup()
            if self.timer_active:
                self.winmm.timeEndPeriod(1)
                self.timer_active=False
            if self.report.get('naturalExitCode') is None and not self.report['cleanup'].get('forcedStop'):
                self.report['naturalExitCode']=self.process.poll() if self.process is not None else None
            output=(self.out/'stdout.bin').read_bytes() if (self.out/'stdout.bin').exists() else b''
            self.report.update(stdoutBytes=len(output),stdoutPreview=output[:2000].decode(errors='replace'),
                loginPrompt=b'please input login name and password!' in output,
                elapsed=round(time.monotonic()-self.started,3))
            self.save()
            self.events.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',action='store_true')
    parser.add_argument('--resolved',action='store_true')
    parser.add_argument('--label')
    args=parser.parse_args()
    if args.label and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',args.label):
        raise ValueError('Invalid label')
    out=ROOT/'evidence'/(('heap-firmware-fixture' if args.fixture else 'heap-firmware-baseline')+('-'+args.label if args.label else ''))
    out.mkdir(exist_ok=False)
    HeapCompare(out,args.fixture,args.resolved).run_compare()

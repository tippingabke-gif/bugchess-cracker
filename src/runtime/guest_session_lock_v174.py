"""Process-lifetime directory mutex, with conservative legacy-lock recovery."""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib,json,os

k=C.WinDLL('kernel32',use_last_error=True)
k.CreateMutexW.argtypes=[C.c_void_p,W.BOOL,W.LPCWSTR];k.CreateMutexW.restype=W.HANDLE
k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.WaitForSingleObject.restype=W.DWORD
k.ReleaseMutex.argtypes=[W.HANDLE];k.CloseHandle.argtypes=[W.HANDLE]
k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE
k.GetProcessTimes.argtypes=[W.HANDLE]+[C.POINTER(W.FILETIME)]*4
k.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
k.CreateToolhelp32Snapshot.argtypes=[W.DWORD,W.DWORD];k.CreateToolhelp32Snapshot.restype=W.HANDLE

class ProcessEntry(C.Structure):
    _fields_=[('size',W.DWORD),('usage',W.DWORD),('pid',W.DWORD),('heap',C.c_size_t),
        ('module',W.DWORD),('threads',W.DWORD),('parent',W.DWORD),('priority',W.LONG),
        ('flags',W.DWORD),('exe',W.WCHAR*260)]
k.Process32FirstW.argtypes=[W.HANDLE,C.POINTER(ProcessEntry)]
k.Process32NextW.argtypes=[W.HANDLE,C.POINTER(ProcessEntry)]

class SessionBusy(RuntimeError):
    pass

def process_state(pid):
    h=k.OpenProcess(0x101000,False,pid)
    if not h:
        error=C.get_last_error()
        if error==87:
            return None
        raise C.WinError(error)
    try:
        if k.WaitForSingleObject(h,0)!=258:
            return None
        stamps=[W.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(h,*(C.byref(x) for x in stamps)):
            raise C.WinError(C.get_last_error())
        size=W.DWORD(32768);path=C.create_unicode_buffer(size.value)
        if not k.QueryFullProcessImageNameW(h,0,path,C.byref(size)):
            raise C.WinError(C.get_last_error())
        return {'pid':pid,'startedFileTime':str((stamps[0].dwHighDateTime<<32)|stamps[0].dwLowDateTime),'path':path.value}
    finally:k.CloseHandle(h)

def active_engine(folder):
    snap=k.CreateToolhelp32Snapshot(2,0)
    if snap==C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        entry=ProcessEntry();entry.size=C.sizeof(entry)
        more=k.Process32FirstW(snap,C.byref(entry))
        while more:
            if entry.exe.startswith('BugChessNN_20260627_release_'):
                state=process_state(entry.pid)
                if state and Path(state['path']).parent==folder:
                    return state
            more=k.Process32NextW(snap,C.byref(entry))
        return None
    finally:k.CloseHandle(snap)

class DirectorySession:
    def __init__(self,folder,evidence,persistent_account=None):
        self.folder=Path(folder).resolve();self.evidence=Path(evidence)
        self.marker=self.folder/'gui-v145.lock';self.handle=None;self.owned=False;self.record=None
        digest=hashlib.sha256(str(self.folder).casefold().encode('utf-8')).hexdigest()
        self.handle=k.CreateMutexW(None,False,'Local\\BugChessDirectory_'+digest)
        if not self.handle:raise C.WinError(C.get_last_error())
        try:
            result=k.WaitForSingleObject(self.handle,0)
            if result not in (0,128):
                raise SessionBusy('当前目录已有引擎正在运行或启动。请先在鲨鱼中卸载当前引擎，再加载所选版本。')
            self.owned=True
            if self.marker.exists():
                text=self.marker.read_text(encoding='utf-8')
                try:
                    old=json.loads(text)
                    if isinstance(old,int):old={'pid':old}
                    state=process_state(int(old['pid']))
                except (ValueError,KeyError,TypeError):
                    raise SessionBusy('目录锁记录格式异常，已保留现场。请查看组件诊断记录。')
                if state and ('startedFileTime' not in old or state['startedFileTime']==old['startedFileTime']):
                    raise SessionBusy('当前目录的引擎仍在运行。请先在鲨鱼中卸载，再切换版本；无需另行双击 EXE。')
                running=active_engine(self.folder)
                if running:
                    raise SessionBusy('当前目录仍有 '+Path(running['path']).name+' 运行。请先卸载当前引擎。')
                account=self.folder/'account.txt';cache=self.folder/'login.txt'
                account_data=account.read_bytes().replace(b'\r\n',b'\n') if account.exists() else None
                preserve_account=persistent_account is not None and account_data==persistent_account
                if account_data is not None and account_data!=b'00000000\nxtprobe0\n' and not preserve_account:
                    raise SessionBusy('发现已有账号文件，已保留。请先检查目录中的 account.txt。')
                if cache.exists() and not account.exists():
                    raise SessionBusy('发现来源未确认的 login.txt，已保留，请先检查。')
                for p in ((cache,self.marker) if preserve_account else (account,cache,self.marker)):
                    if p.exists():p.replace(self.evidence/('recovered-'+p.name))
            self.record=process_state(os.getpid())
            self.record['evidence']=str(self.evidence)
            self.marker.write_text(json.dumps(self.record),encoding='utf-8')
        except Exception:
            self.close(remove_marker=False)
            raise

    def close(self,remove_marker=True):
        try:
            if remove_marker and self.record and self.marker.exists():
                if json.loads(self.marker.read_text(encoding='utf-8'))==self.record:
                    self.marker.unlink()
        finally:
            if self.handle:
                if self.owned:k.ReleaseMutex(self.handle)
                k.CloseHandle(self.handle);self.handle=None;self.owned=False

def acquire(folder,evidence,persistent_account=None):
    return DirectorySession(folder,evidence,persistent_account)

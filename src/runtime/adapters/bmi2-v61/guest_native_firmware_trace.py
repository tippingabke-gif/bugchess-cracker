"""Guest-only, class-76 NtQuerySystemInformation observation without a debug object.

python.exe -I guest_native_firmware_trace.py [--label run-name]
The hook records entry/return gates, then releases the original syscall result.
Requires capstone; does not import or apply any firmware fixture.
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
import time
import traceback

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


ROOT = Path(r'C:\Lab\BugChess20260627')
CASE = ROOT / 'cases/bmi2-original-offline-v47'
TIMEOUT = 30.0
MAX_BUFFER = 4 * 1024 * 1024
MASK64 = (1 << 64) - 1
FIELDS = {'sequence': 0x18, 'class': 0x30, 'buffer': 0x38, 'capacity': 0x40,
          'returnLengthPointer': 0x48, 'rsp': 0x50, 'caller': 0x58,
          'status': 0x60, 'returnFlags': 0x68, 'entryFlags': 0x70}


class Code:
    def __init__(self):
        self.data, self.labels, self.fixups = bytearray(), {}, []

    def emit(self, data):
        self.data += bytes.fromhex(data) if isinstance(data, str) else data

    def label(self, name):
        self.labels[name] = len(self.data)

    def branch(self, opcode, label):
        self.emit(opcode)
        self.fixups.append((len(self.data), label))
        self.emit(bytes(4))

    def finish(self):
        for offset, label in self.fixups:
            struct.pack_into('<i', self.data, offset, self.labels[label] - (offset + 4))
        return bytes(self.data)


def make_stub(record, original):
    """Only RAX/R10/R11 and flags are borrowed; their live values are stacked.

    class != 76: restore flags and tail-jump to the unmodified syscall stub.
    class == 76: serialize records, entry gate, original call, return gate, ret.
    LEA adjusts shadow space without changing pre/post-syscall flags.
    """
    b = Code()
    b.emit('9c 83f94c')                       # pushfq; cmp ecx,76
    b.branch('0f85', 'passthrough')
    b.emit('50 4152 4153')                    # save rax,r10,r11
    b.emit(b'\x49\xba' + struct.pack('<Q', record))
    b.label('lock')
    b.emit('41837a0400')                      # stop flag?
    b.branch('0f85', 'unwind')
    b.emit('31c0 41bb01000000 f0450fb11a')    # lock cmpxchg [r10],r11d
    b.branch('0f85', 'lock_pause')
    b.emit('49ff4208 4d8b5a08 4d895a18')      # next sequence -> published sequence
    b.emit('49894a30 49895238 4d894240 4d894a48')  # rcx,rdx,r8,r9
    b.emit('4c8d5c2420 4d895a50 498b03 49894258')  # original rsp and caller
    b.emit('658b042548000000 41894214')        # current TEB thread id
    b.emit('488b442418 49894270')              # original flags
    b.emit('41c7421001000000')                # stage = entry (1), published last
    b.label('entry_gate')
    b.emit('41837a0400')
    b.branch('0f85', 'original_call')
    b.emit('498b4218 49394220')               # entry_ack == sequence
    b.branch('0f84', 'original_call')
    b.emit('f390')
    b.branch('e9', 'entry_gate')
    b.label('original_call')
    b.emit('415b 415a 58 9d')                 # exact original borrowed state
    b.emit('488d6424d8')                      # rsp -= 40: alignment + shadow space
    b.branch('e8', 'trampoline')
    b.emit('488d642428')                      # rsp += 40, preserve result flags
    b.emit('9c 50 4152 4153')                 # preserve returned state
    b.emit(b'\x49\xba' + struct.pack('<Q', record))
    b.emit('488b442410 49894260 488b442418 49894268')  # NTSTATUS, post flags
    b.emit('41c7421002000000')                # stage = return (2)
    b.label('return_gate')
    b.emit('41837a0400')
    b.branch('0f85', 'release')
    b.emit('498b4218 49394228')               # return_ack == sequence
    b.branch('0f84', 'release')
    b.emit('f390')
    b.branch('e9', 'return_gate')
    b.label('release')
    b.emit('41c7421000000000 41c70200000000') # idle, release lock
    b.emit('415b 415a 58 9d c3')              # return original syscall result
    b.label('lock_pause')
    b.emit('f390')
    b.branch('e9', 'lock')
    b.label('unwind')
    b.emit('415b 415a 58 9d')
    b.branch('e9', 'trampoline')
    b.label('passthrough')
    b.emit('9d')
    b.branch('e9', 'trampoline')
    used = len(b.data)
    if used > 0x800:
        raise RuntimeError('Probe exceeds its reserved code area')
    b.emit(b'\x90' * (0x800 - used))
    b.label('trampoline')
    b.emit(original)
    return b.finish(), used, dict(b.labels)


def validate_syscall_stub(raw, address):
    if len(raw) != 32:
        raise RuntimeError('Exactly 32 original syscall-stub bytes are required')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(raw, address))
    if sum(i.size for i in instructions) != 32:
        raise RuntimeError('Original 32-byte stub does not decode completely')
    starts = {i.address for i in instructions}
    for instruction in instructions:
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                raise RuntimeError('RIP-relative memory requires relocation; probe stopped')
        if instruction.group(capstone.CS_GRP_CALL):
            raise RuntimeError('Unexpected call in syscall stub; probe stopped')
        if instruction.group(capstone.CS_GRP_JUMP):
            if (len(instruction.operands) != 1 or instruction.operands[0].type != X86_OP_IMM
                    or instruction.operands[0].imm not in starts):
                raise RuntimeError('Stub branch leaves the copied instruction region')
    # Deliberately narrow: accept the observed AMD64 Windows syscall/int-2e
    # selector, including its two RETs. An unfamiliar prologue is not relocated.
    if (raw[:4] != bytes.fromhex('4c8bd1b8')
            or raw[8:24] != bytes.fromhex('f604250803fe7f0175030f05c3cd2ec3')):
        raise RuntimeError('Unrecognized native syscall template; probe stopped')
    if any(i.mnemonic not in ('nop', 'int3') for i in instructions if i.address >= address + 24):
        raise RuntimeError('Unexpected instructions after syscall return paths')
    return [{'offset': hex(i.address - address), 'bytes': i.bytes.hex(),
             'instruction': i.mnemonic + ' ' + i.op_str} for i in instructions]


def firmware_header(data):
    if len(data) < 16:
        return None
    provider, action, table_id, length = struct.unpack_from('<4I', data)
    return {'provider': hex(provider), 'providerFourCC': provider.to_bytes(4, 'big').decode('ascii', errors='replace'),
            'action': action, 'tableId': table_id, 'bufferLength': length}


class Trace:
    def __init__(self, out, engine, early=False):
        self.out, self.engine = out, engine
        self.early = early
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.n = C.WinDLL('ntdll', use_last_error=True)
        for name in ('ReadProcessMemory', 'WriteProcessMemory'):
            function = getattr(self.k, name)
            function.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
            function.restype = W.BOOL
        self.k.VirtualAllocEx.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, W.DWORD]
        self.k.VirtualAllocEx.restype = C.c_void_p
        self.k.VirtualProtectEx.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, C.POINTER(W.DWORD)]
        self.k.VirtualProtectEx.restype = W.BOOL
        self.k.FlushInstructionCache.argtypes = [W.HANDLE, C.c_void_p, C.c_size_t]
        self.k.FlushInstructionCache.restype = W.BOOL
        self.k.TerminateProcess.argtypes, self.k.TerminateProcess.restype = [W.HANDLE, W.UINT], W.BOOL
        self.n.NtQueryInformationProcess.argtypes = [W.HANDLE, W.ULONG, C.c_void_p, W.ULONG, C.POINTER(W.ULONG)]
        self.n.NtQueryInformationProcess.restype = W.LONG
        for name in ('NtSuspendProcess', 'NtResumeProcess'):
            function = getattr(self.n, name)
            function.argtypes, function.restype = [W.HANDLE], W.LONG
        self.process = None
        self.suspended = False
        self.allocation = self.record = self.target = None
        self.original = None
        self.hooked = False
        self.started = time.monotonic()
        self.report = {'mode': 'native-firmware-class76-observation', 'status': 'preparing',
                       'argumentsChanged': False, 'returnValueChanged': False,
                       'firmwareDataChanged': False, 'sourceExeModified': False,
                       'debugObjectUsed': False, 'timeoutSeconds': TIMEOUT,
                       'calls': [], 'naturalExitCode': None, 'cleanup': {},
                       'limitations': ['Class-76 calls are serialized while observed.',
                                       'Polling, gates and the temporary API-entry patch affect timing.',
                                       'Buffer snapshots are bounded by the original capacity and 4 MiB.']}
        self.events = (out / 'events.jsonl').open('x', encoding='utf-8')

    @property
    def handle(self):
        # Keep the full-access handle from our own CreateProcess/Popen lifetime.
        return int(self.process._handle)

    def read(self, address, size):
        if not address or not 0 < size <= MAX_BUFFER:
            return b''
        buffer, done = C.create_string_buffer(size), C.c_size_t()
        self.k.ReadProcessMemory(self.handle, address, buffer, size, C.byref(done))
        return buffer.raw[:done.value]

    def write(self, address, data):
        buffer, done = C.create_string_buffer(data), C.c_size_t()
        if not self.k.WriteProcessMemory(self.handle, address, buffer, len(data), C.byref(done)) or done.value != len(data):
            raise C.WinError(C.get_last_error())

    def protected_write(self, address, data):
        prior = W.DWORD()
        if not self.k.VirtualProtectEx(self.handle, address, len(data), 0x40, C.byref(prior)):
            raise C.WinError(C.get_last_error())
        try:
            self.write(address, data)
            if not self.k.FlushInstructionCache(self.handle, address, len(data)):
                raise C.WinError(C.get_last_error())
        finally:
            ignored = W.DWORD()
            if not self.k.VirtualProtectEx(self.handle, address, len(data), prior.value, C.byref(ignored)):
                raise C.WinError(C.get_last_error())

    def pause(self):
        if not self.suspended:
            status = self.n.NtSuspendProcess(self.handle)
            if status < 0:
                raise RuntimeError(f'NtSuspendProcess failed: {status & 0xffffffff:#x}')
            self.suspended = True

    def resume(self):
        if self.suspended:
            status = self.n.NtResumeProcess(self.handle)
            if status < 0:
                raise RuntimeError(f'NtResumeProcess failed: {status & 0xffffffff:#x}')
            self.suspended = False

    def save(self):
        temporary = self.out / 'summary.json.tmp'
        temporary.write_text(json.dumps(self.report, indent=2), encoding='utf-8')
        temporary.replace(self.out / 'summary.json')

    def event(self, kind, **values):
        self.events.write(json.dumps({'kind': kind, 'elapsed': round(time.monotonic() - self.started, 6), **values}) + '\n')
        self.events.flush()

    def install(self, deadline):
        info, returned = (C.c_void_p * 6)(), W.ULONG()
        status = self.n.NtQueryInformationProcess(self.handle, 0, info, C.sizeof(info), C.byref(returned))
        if status < 0 or not info[1]:
            raise RuntimeError('Process basic information unavailable')
        image_base = struct.unpack('<Q', self.read(int(info[1]) + 0x10, 8))[0]
        slot = image_base + 0xab025d
        trigger = C.cast(self.k.TerminateProcess, C.c_void_p).value
        self.target = C.cast(self.n.NtQuerySystemInformation, C.c_void_p).value
        self.report.update(pid=self.process.pid, base=hex(image_base), slot=hex(slot),
                           observedAPI='ntdll!NtQuerySystemInformation', target=hex(self.target))
        if not self.early:
            self.resume()
        previous = None
        while time.monotonic() < deadline and self.process.poll() is None:
            raw = self.read(slot, 8)
            if len(raw) != 8:
                continue
            value = int.from_bytes(raw, 'little')
            if self.early or (value + 0x2ca606a5) & MASK64 == trigger:
                self.pause()  # suspend before any output or allocation on the match
                break
            if value != previous:
                previous = value
                self.event('pointer-change', raw=hex(value))
        else:
            raise RuntimeError('Pointer-resolution trigger not reached within observation deadline')
        self.report['armedAt'] = round(time.monotonic() - self.started, 6)
        self.report['probeTrigger'] = 'initial suspended process' if self.early else 'resolved import pointer'
        self.original = self.read(self.target, 32)
        self.report['originalAPIBytes'] = self.original.hex()
        self.report['originalStubDisassembly'] = validate_syscall_stub(self.original, self.target)
        if self.original != C.string_at(self.target, 32):
            raise RuntimeError('Remote syscall entry differs from current guest ntdll; probe stopped')
        self.report['syscallNumber'] = struct.unpack_from('<I', self.original, 4)[0]
        self.allocation = self.k.VirtualAllocEx(self.handle, None, 0x2000, 0x3000, 0x4)
        if not self.allocation:
            raise C.WinError(C.get_last_error())
        self.record = self.allocation + 0x1000
        code, used, labels = make_stub(self.record, self.original)
        self.write(self.allocation, code)
        previous_protect = W.DWORD()
        if not self.k.VirtualProtectEx(self.handle, self.allocation, 0x1000, 0x20, C.byref(previous_protect)):
            raise C.WinError(C.get_last_error())
        if not self.k.FlushInstructionCache(self.handle, self.allocation, len(code)):
            raise C.WinError(C.get_last_error())
        (self.out / 'probe-code.bin').write_bytes(code)
        self.report.update(stub=hex(self.allocation), record=hex(self.record), trampoline=hex(self.allocation + 0x800),
                           stubLabels={name: hex(self.allocation + offset) for name, offset in labels.items()})
        self.report['stubDisassembly'] = [{'offset': hex(i.address - self.allocation), 'bytes': i.bytes.hex(),
                                         'instruction': i.mnemonic + ' ' + i.op_str}
                                        for i in capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64).disasm(code[:used], self.allocation)]
        patch = b'\xff\x25\0\0\0\0' + struct.pack('<Q', self.allocation)
        # Mark before writing, so cleanup also restores a partial failed patch.
        self.hooked = True
        self.protected_write(self.target, patch)
        if self.read(self.target, len(patch)) != patch:
            raise RuntimeError('API patch readback mismatch')
        self.report['status'] = 'observing'
        self.save()
        self.resume()

    def capture_gate(self, blob, stage):
        fields = {name: struct.unpack_from('<Q', blob, offset)[0] for name, offset in FIELDS.items()}
        sequence = fields['sequence']
        phase = 'enter' if stage == 1 else 'return'
        prefix = f'{sequence:06d}-{phase}'
        capacity = fields['capacity'] & 0xffffffff
        data = self.read(fields['buffer'], min(capacity, MAX_BUFFER)) if capacity else b''
        header = firmware_header(data)
        status = fields['status'] & 0xffffffff if stage == 2 else None
        returned = self.read(fields['returnLengthPointer'], 4) if fields['returnLengthPointer'] else b''
        row = {'sequence': sequence, 'phase': phase, 'tid': struct.unpack_from('<I', blob, 0x14)[0],
               'elapsed': round(time.monotonic() - self.started, 6),
               'arguments': {name: hex(fields[name]) for name in ('class', 'buffer', 'capacity', 'returnLengthPointer')},
               'rsp': hex(fields['rsp']), 'caller': hex(fields['caller']),
               'header': header, 'NTSTATUS': hex(status) if status is not None else None,
               'NTSTATUSsigned': C.c_int32(status).value if status is not None else None,
               'returnLength': struct.unpack('<I', returned)[0] if len(returned) == 4 else None,
               'buffer': {'file': prefix + '.buffer.bin', 'capacity': capacity, 'bytesRead': len(data),
                          'truncatedByLimit': capacity > MAX_BUFFER, 'sha256': hashlib.sha256(data).hexdigest()}}
        (self.out / row['buffer']['file']).write_bytes(data)
        (self.out / (prefix + '.record.bin')).write_bytes(blob)
        if stage == 2 and header is not None:
            available = max(0, len(data) - 16)
            payload = data[16:16 + min(available, header['bufferLength'])]
            filename = prefix + '.firmware.bin'
            (self.out / filename).write_bytes(payload)
            row['firmware'] = {'file': filename, 'reportedLength': header['bufferLength'],
                               'bytesRead': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                               'syscallSucceeded': C.c_int32(status).value >= 0}
        (self.out / (prefix + '.json')).write_text(json.dumps(row, indent=2), encoding='utf-8')
        self.report['calls'].append(row)
        self.event('query-' + phase, sequence=sequence, header=header, NTSTATUS=row['NTSTATUS'], bytesRead=len(data))
        self.save()
        # Data and evidence are saved before releasing this exact sequence.
        self.write(self.record + (0x20 if stage == 1 else 0x28), struct.pack('<Q', sequence))

    def cleanup(self):
        if self.process is None:
            return
        cleanup = self.report['cleanup']
        if self.process.poll() is None:
            try:
                self.pause()
                if self.hooked:
                    self.protected_write(self.target, self.original[:14])
                    cleanup['originalAPIBytesRestored'] = self.read(self.target, 32) == self.original
                    self.hooked = False
                if self.record:
                    self.write(self.record + 4, struct.pack('<I', 1))
                    cleanup['gatesReleased'] = True
            except Exception as error:
                cleanup['restoreError'] = str(error)
            finally:
                try:
                    self.resume()
                except Exception as error:
                    cleanup['resumeError'] = str(error)
            try:
                self.process.wait(timeout=2)
                cleanup['exitDuringRestoreGrace'] = hex(self.process.returncode & 0xffffffff)
            except subprocess.TimeoutExpired:
                cleanup['forcedStop'] = True
                cleanup['requestedExitCode'] = '0x5854434c'
                if not self.k.TerminateProcess(self.handle, 0x5854434c):
                    cleanup['terminateError'] = C.get_last_error()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    cleanup['waitTimedOut'] = True
        else:
            cleanup['targetExitedBeforeRestore'] = bool(self.hooked)
        # Remote code/record pages are never freed while a caller might still
        # hold a trampoline return address. Process termination reclaims them.
        if self.process.stdin:
            self.process.stdin.close()
        code = self.process.poll()
        self.report['finalExitCode'] = hex(code & 0xffffffff) if code is not None else None
        self.report['ownedSuspendAtEnd'] = self.suspended

    def run(self):
        try:
            self.report['sourceSha256'] = hashlib.sha256(self.engine.read_bytes()).hexdigest()
            with (self.out / 'stdout.bin').open('xb') as stdout, (self.out / 'stderr.bin').open('xb') as stderr:
                self.process = subprocess.Popen([str(self.engine)], cwd=CASE, stdin=subprocess.PIPE,
                    stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
                self.suspended = True
                deadline = self.started + TIMEOUT
                self.install(deadline)
                seen = set()
                last_api = None
                self.report['observedAPIBytes'] = []
                while time.monotonic() < deadline:
                    exited = self.process.poll()
                    if exited is not None:
                        self.report.update(status='natural-exit', naturalExitCode=hex(exited & 0xffffffff))
                        break
                    api_bytes = self.read(self.target,32)
                    if api_bytes != last_api:
                        last_api = api_bytes
                        row = {'elapsed':round(time.monotonic()-self.started,6),'bytes':api_bytes.hex(),
                               'originalRestored':api_bytes==self.original}
                        self.report['observedAPIBytes'].append(row)
                        self.event('api-byte-change',**row)
                    blob = self.read(self.record, 0x80)
                    if len(blob) != 0x80:
                        continue
                    stage = struct.unpack_from('<I', blob, 0x10)[0]
                    sequence = struct.unpack_from('<Q', blob, 0x18)[0]
                    identity = (sequence, stage)
                    if stage in (1, 2) and sequence and identity not in seen:
                        self.capture_gate(blob, stage)
                        seen.add(identity)
                else:
                    self.report['status'] = 'timeout'
        except Exception:
            self.report.update(status='error', error=traceback.format_exc())
        finally:
            try:
                self.cleanup()
            except Exception:
                self.report['cleanup']['error'] = traceback.format_exc()
            self.report['elapsed'] = round(time.monotonic() - self.started, 6)
            self.save()
            self.events.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label')
    parser.add_argument('--early',action='store_true')
    args = parser.parse_args()
    if args.label and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args.label):
        parser.error('--label must use 1-64 ASCII letters/digits/underscores/hyphens')
    if C.sizeof(C.c_void_p) != 8:
        parser.error('64-bit guest Python is required')
    engines = [p for p in CASE.glob('*.exe') if 'sse4' in p.name.casefold()]
    if len(engines) != 1:
        raise RuntimeError('Expected exactly one SSE4 executable in ' + str(CASE))
    out = ROOT / 'evidence' / ('native-firmware-trace' + ('-' + args.label if args.label else ''))
    out.mkdir(parents=True, exist_ok=False)
    trace = Trace(out, engines[0], early=args.early)
    trace.run()
    print(json.dumps({'output': str(out), 'status': trace.report['status'],
                      'gatesCaptured': len(trace.report['calls']),
                      'naturalExitCode': trace.report['naturalExitCode'], 'cleanup': trace.report['cleanup']}))


if __name__ == '__main__':
    main()

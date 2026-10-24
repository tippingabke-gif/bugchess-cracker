"""Guest-only observation of the actual NtQuerySystemInformation[Ex] SYSCALL gates.

Keep guest_native_firmware_trace.py beside this script. Requires 64-bit guest
Python and capstone. Run: python.exe -I guest_syscall_gate_trace.py [--label NAME]
Use --observed-gates to also validate gates from this guest boot's kernel-return
summary. A donor's template SSN never restricts the actual query SSNs recorded.
No debug object, firmware fixture, login alteration or syscall-result replacement.
"""

from pathlib import Path
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import time
import traceback

import capstone


HELPER = Path(__file__).resolve().with_name('guest_native_firmware_trace.py')
spec = importlib.util.spec_from_file_location('firmware_gate_helpers', HELPER)
if spec is None or spec.loader is None:
    raise RuntimeError('Missing helper: ' + str(HELPER))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
APIS = ('NtQuerySystemInformation', 'NtQuerySystemInformationEx')


class MBI(C.Structure):
    _fields_ = [('base', C.c_void_p), ('allocationBase', C.c_void_p),
                ('allocationProtect', W.DWORD), ('partition', W.WORD),
                ('size', C.c_size_t), ('state', W.DWORD), ('protect', W.DWORD), ('kind', W.DWORD)]


def make_gate_stub(record, gate, origin, ssns):
    """Execute the saved SYSCALL with the original RSP, RAX and R10.

    The runtime service number is never replaced. Only the two verified query
    SSNs with R10D == 76 enter the recorder. Every other call executes the same
    SYSCALL at unchanged stack depth. RCX is restored to the original gate+2
    return PC after SYSCALL; all other returned state is preserved by the gates.
    """
    b = helper.Code()

    def return_to_original_ret():
        b.emit(b'\x48\xb9' + struct.pack('<Q', gate + 2))

    def jump_original_ret():
        displacement = gate + 2 - (origin + len(b.data) + 5)
        if not -(1 << 31) <= displacement < 1 << 31:
            raise RuntimeError('Original RET is outside rel32 reach')
        b.emit(b'\xe9' + struct.pack('<i', displacement))

    b.emit('9c 4183fa4c')                       # pushfq; cmp r10d,76
    b.branch('0f85', 'passthrough')
    b.emit(b'\x3d' + struct.pack('<I', ssns[0]))
    b.branch('0f84', 'matched')
    b.emit(b'\x3d' + struct.pack('<I', ssns[1]))
    b.branch('0f85', 'passthrough')
    b.label('matched')
    b.emit('50 4152 4153')                      # rax,r10,r11; original RSP is +32
    b.emit(b'\x49\xba' + struct.pack('<Q', record))
    b.label('lock')
    b.emit('41837a0400')
    b.branch('0f85', 'unwind')
    b.emit('31c0 41bb01000000 f0450fb11a')       # lock cmpxchg [record],r11d
    b.branch('0f85', 'lock_pause')
    b.emit('49ff4208 4d8b5a08 4d895a18')        # increment and publish sequence
    b.emit('4c8b5c2408 4d895a30')               # original R10 -> class
    b.emit('49895238 4d894240 4d894a48 49894a78')  # raw RDX,R8,R9,RCX
    b.emit('488b442410 49898280000000')         # original RAX, including SSN
    b.emit('4c8d5c2420 4d895a50 498b03 49894258')  # original RSP, caller
    b.emit('658b042548000000 41894214')          # TEB thread id
    b.emit('488b442418 49894270')                # entry flags
    b.emit('41c7421001000000')
    b.label('entry_gate')
    b.emit('41837a0400')
    b.branch('0f85', 'original_syscall')
    b.emit('498b4218 49394220')
    b.branch('0f84', 'original_syscall')
    b.emit('f390')
    b.branch('e9', 'entry_gate')
    b.label('original_syscall')
    b.emit('415b 415a 58 9d 0f05')             # exact original stack/registers at syscall
    return_to_original_ret()                   # same RCX as the unpatched syscall
    b.emit('9c 50 4152 4153')
    b.emit(b'\x49\xba' + struct.pack('<Q', record))
    b.emit('488b442410 49894260 488b442418 49894268')
    b.emit('41c7421002000000')
    b.label('return_gate')
    b.emit('41837a0400')
    b.branch('0f85', 'release')
    b.emit('498b4218 49394228')
    b.branch('0f84', 'release')
    b.emit('f390')
    b.branch('e9', 'return_gate')
    b.label('release')
    b.emit('41c7421000000000 41c70200000000 415b 415a 58 9d')
    jump_original_ret()
    b.label('lock_pause')
    b.emit('f390')
    b.branch('e9', 'lock')
    b.label('unwind')
    b.emit('415b 415a 58 9d')
    b.branch('e9', 'raw_syscall')
    b.label('passthrough')
    b.emit('9d')
    b.label('raw_syscall')
    b.emit('0f05')
    return_to_original_ret()
    jump_original_ret()
    code = b.finish()
    if len(code) > 0x1000:
        raise RuntimeError('Gate probe exceeds one page')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = list(decoder.disasm(code, origin))
    if sum(i.size for i in instructions) != len(code):
        raise RuntimeError('Generated gate stub does not fully decode')
    return code, b.labels, [{'offset': hex(i.address - origin), 'bytes': i.bytes.hex(),
                            'instruction': i.mnemonic + ' ' + i.op_str} for i in instructions]


class GateTrace(helper.Trace):
    def __init__(self, out, engine, observed_gates=False):
        super().__init__(out, engine, early=True)
        self.k.VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MBI), C.c_size_t]
        self.k.VirtualQueryEx.restype = C.c_size_t
        self.probes = []
        self.entries = {}
        self.api_by_ssn = {}
        self.observed_gates = observed_gates
        self.report.update(mode='native-syscall-gate-class76-observation', probeTrigger='initial suspended process',
                           observedGatesEnabled=observed_gates,
                           coverage={'mandatoryRequested': 2, 'sourceRows': 0, 'syscallReturnRows': 0,
                                     'validatedProbeCount': 0, 'installedProbeCount': 0,
                                     'mandatoryInstalledCount': 0, 'donorInstalledCount': 0,
                                     'skippedCount': 0, 'skippedReasonCounts': {}, 'skipped': []},
                           helperSha256=hashlib.sha256(HELPER.read_bytes()).hexdigest(),
                           probeSpecification={'gateOffset': '0x12', 'relayOffset': '0x18',
                                               'filter': 'R10D == 76 and EAX in verified query SSNs'},
                           limitations=['Only successfully installed SYSCALL addresses listed in gates are observed.',
                                        'Unlisted gates, temporary mappings, private stubs and the preserved INT 2E path are outside coverage.',
                                        'The observed-return list is partial evidence, not proof of complete syscall coverage.',
                                        'NtQuerySystemInformationEx class 76 support is unknown until an observed return establishes it.',
                                        'Each observed gate serializes matching queries while entry/return evidence is saved.',
                                        'No stack unwind metadata is supplied for the temporary observer code.'])

    def skip_candidate(self, reason, detail, **identity):
        coverage = self.report['coverage']
        coverage['skipped'].append({'reason': reason, 'detail': str(detail), **identity})
        coverage['skippedCount'] += 1
        counts = coverage['skippedReasonCounts']
        counts[reason] = counts.get(reason, 0) + 1

    def image_region(self, address):
        region = MBI()
        if not self.k.VirtualQueryEx(self.handle, address, C.byref(region), C.sizeof(region)):
            raise C.WinError(C.get_last_error())
        if (region.state != 0x1000 or region.kind != 0x1000000
                or region.protect & 0x100 or (region.protect & 0xFF) not in (0x10, 0x20, 0x40, 0x80)
                or not (region.base or 0) <= address < address + 32 <= (region.base or 0) + region.size):
            raise RuntimeError('Candidate is not wholly inside a committed executable image region')
        return {'allocationBase': hex(region.allocationBase or 0), 'base': hex(region.base or 0),
                'size': region.size, 'protect': hex(region.protect)}

    def observed_candidates(self, required):
        source = helper.ROOT / 'evidence' / 'kernel-return-engine' / 'summary.json'
        provenance = {'file': str(source), 'entryDerivation': 'return PC - 20 (0x14)',
                      'capturedStubSlice': '[12:44] of 64 bytes beginning at PC - 32'}
        self.report['observedGateSource'] = provenance
        try:
            raw = source.read_bytes()
            self.k.GetTickCount64.argtypes = []
            self.k.GetTickCount64.restype = C.c_ulonglong
            now = time.time()
            boot_time = now - self.k.GetTickCount64() / 1000.0
            modified = source.stat().st_mtime
            provenance.update(sha256=hashlib.sha256(raw).hexdigest(), modifiedUnix=modified,
                              estimatedBootUnix=boot_time,
                              bootCheck='file time since this guest boot, plus exact current address/byte validation')
            # Old absolute PCs are not rebased or reused after a guest reboot.
            # Clock changes can conservatively reject evidence; never relax the check.
            if modified < boot_time or modified > now + 5:
                self.skip_candidate('source-not-current-boot', 'Source timestamp is outside this boot', source=str(source))
                return []
            rows = json.loads(raw)['uniqueReturns']
            if not isinstance(rows, list):
                raise ValueError('uniqueReturns must be a list')
        except Exception as error:
            self.skip_candidate('source-unavailable', error, source=str(source))
            return []
        self.report['coverage']['sourceRows'] = len(rows)
        candidates, seen = [], {p['address'] for p in required}
        for index, row in enumerate(rows):
            if not isinstance(row, dict) or row.get('precedingInstruction') != '0f05':
                continue
            self.report['coverage']['syscallReturnRows'] += 1
            identity, validation = {'sourceRow': index, 'returnPC': row.get('pc')}, 'candidate-format'
            try:
                pc = int(row['pc'], 0) if isinstance(row['pc'], str) else int(row['pc'])
                address = pc - 20
                identity.update(returnPC=hex(pc), entry=hex(address))
                if not 0x10000 <= address <= 0x7FFFFFFFFFFF - 32:
                    raise ValueError('Derived entry is outside the user address space')
                if address in seen:
                    self.skip_candidate('duplicate-entry', 'Entry is already represented', **identity)
                    continue
                captured = bytes.fromhex(row['bytes'])
                if len(captured) != 64 or captured[30:32] != b'\x0f\x05':
                    raise ValueError('Expected a 64-byte PC-32 window ending SYSCALL at PC')
                expected = captured[12:44]
                validation = 'captured-template'
                helper.validate_syscall_stub(expected, address)
                validation = 'current-address-space'
                region = self.image_region(address)
                validation = 'current-bytes-mismatch'
                original = self.read(address, 32)
                if original != expected:
                    raise RuntimeError('Current remote bytes differ from captured bytes (stale or changed entry)')
                validation = 'current-template'
                decoded = helper.validate_syscall_stub(original, address)
                # The donor SSN is metadata only, including win32u service numbers.
                candidates.append({'name': f'observed_{address:x}', 'address': address,
                    'gate': address + 0x12, 'relay': address + 0x18, 'original': original,
                    'ssn': struct.unpack_from('<I', original, 4)[0], 'mandatory': False,
                    'patched': False, 'disassembly': decoded, 'region': region, 'source': identity})
                seen.add(address)
            except Exception as error:
                self.skip_candidate(validation, error, **identity)
        return candidates

    def allocate_near(self, center, size):
        lower = max(0x10000, center - 0x7F000000)
        upper = min(0x7FFFFFFFFFFF, center + 0x7F000000)
        cursor = lower
        while cursor < upper:
            region = MBI()
            if not self.k.VirtualQueryEx(self.handle, cursor, C.byref(region), C.sizeof(region)):
                raise C.WinError(C.get_last_error())
            end = (region.base or 0) + region.size
            if end <= cursor:
                raise RuntimeError('VirtualQueryEx did not advance')
            candidate = (max(cursor, region.base or 0) + 0xFFFF) & ~0xFFFF
            if region.state == 0x10000 and candidate + size <= min(end, upper):
                address = self.k.VirtualAllocEx(self.handle, candidate, size, 0x3000, 0x04)
                if address:
                    if address != candidate:
                        raise RuntimeError('Near allocation address differs from requested address')
                    return address
            cursor = end
        raise RuntimeError('No free near allocation for five-byte relay jumps')

    def install(self, deadline):
        info, returned = (C.c_void_p * 6)(), W.ULONG()
        status = self.n.NtQueryInformationProcess(self.handle, 0, info, C.sizeof(info), C.byref(returned))
        if status < 0 or not info[1]:
            raise RuntimeError('Process basic information unavailable')
        self.report.update(pid=self.process.pid, base=hex(struct.unpack('<Q', self.read(int(info[1]) + 0x10, 8))[0]))
        # Validate both exports before any target instruction is changed.
        required = []
        for name in APIS:
            address = C.cast(getattr(self.n, name), C.c_void_p).value
            original = self.read(address, 32)
            decoded = helper.validate_syscall_stub(original, address)
            if original != C.string_at(address, 32):
                raise RuntimeError('Remote/local guest syscall entry mismatch: ' + name)
            ssn = struct.unpack_from('<I', original, 4)[0]
            if not 0 < ssn < 0x1000:
                raise RuntimeError('Unexpected syscall number: ' + name)
            required.append({'name': name, 'address': address, 'gate': address + 0x12,
                                'relay': address + 0x18, 'original': original, 'ssn': ssn,
                                'patched': False, 'mandatory': True, 'disassembly': decoded,
                                'region': self.image_region(address)})
        if len({p['ssn'] for p in required}) != 2 or len({p['address'] for p in required}) != 2:
            raise RuntimeError('Expected distinct query syscall entries and SSNs')
        self.api_by_ssn = {p['ssn']: p['name'] for p in required}
        ssns = list(self.api_by_ssn)
        candidates = required + (self.observed_candidates(required) if self.observed_gates else [])
        coverage = self.report['coverage']
        coverage['validatedProbeCount'] = len(candidates)
        allocation_size = len(candidates) * 0x2000
        records_offset = len(candidates) * 0x1000
        self.allocation = self.allocate_near(required[0]['gate'], allocation_size)
        self.report['allocation'] = {'address': hex(self.allocation), 'size': allocation_size,
                                     'codePages': len(candidates), 'recordPages': len(candidates)}
        self.report['syscallNumbers'] = {p['name']: p['ssn'] for p in required}
        self.report['actualAPIBySSN'] = {hex(ssn): api for ssn, api in self.api_by_ssn.items()}
        self.report['gates'] = []
        for index, probe in enumerate(candidates):
            probe['stub'] = self.allocation + index * 0x1000
            probe['record'] = self.allocation + records_offset + index * 0x1000
            validation = 'rel32-or-generated-stub'
            try:
                displacement = probe['stub'] - (probe['relay'] + 5)
                if not -(1 << 31) <= displacement < 1 << 31:
                    raise RuntimeError('Near relay outside rel32 range')
                # Also validates each generated jump from the observer to original RET.
                code, labels, decoded = make_gate_stub(probe['record'], probe['gate'], probe['stub'], ssns)
                relay = b'\xe9' + struct.pack('<i', displacement) + b'\x90' * 3
                expected = bytearray(probe['original'])
                expected[0x12:0x14] = b'\xeb\x04'
                expected[0x18:0x20] = relay
                probe['expected'] = bytes(expected)
                validation = 'observer-install'
                self.write(probe['stub'], code)
                prior = W.DWORD()
                if not self.k.VirtualProtectEx(self.handle, probe['stub'], 0x1000, 0x20, C.byref(prior)):
                    raise C.WinError(C.get_last_error())
                if not self.k.FlushInstructionCache(self.handle, probe['stub'], len(code)):
                    raise C.WinError(C.get_last_error())
                (self.out / (probe['name'] + '.probe.bin')).write_bytes(code)
                validation = 'prepatch-bytes-mismatch'
                if self.read(probe['address'], 32) != probe['original']:
                    raise RuntimeError('Original bytes changed before patching')
                validation = 'gate-install'
                # EB 04 replaces only SYSCALL; RET and INT 2E/RET remain identical.
                probe['patched'] = True
                self.protected_write(probe['relay'], relay)
                self.protected_write(probe['gate'], b'\xeb\x04')
                if self.read(probe['address'], 32) != probe['expected']:
                    raise RuntimeError('Syscall gate patch readback mismatch: ' + probe['name'])
            except Exception as error:
                if probe['patched']:
                    try:
                        self.protected_write(probe['address'], probe['original'])
                        if self.read(probe['address'], 32) != probe['original']:
                            raise RuntimeError('Partial gate patch rollback readback mismatch')
                        probe['patched'] = False
                    except Exception:
                        # Cleanup must retry this gate; never resume after silently
                        # skipping an optional probe whose original bytes are uncertain.
                        self.probes.append(probe)
                        raise
                if probe['mandatory']:
                    raise
                self.skip_candidate(validation, error, name=probe['name'], entry=hex(probe['address']))
                continue
            self.probes.append(probe)
            coverage['installedProbeCount'] += 1
            coverage['mandatoryInstalledCount' if probe['mandatory'] else 'donorInstalledCount'] += 1
            self.report['gates'].append({'name': probe['name'], 'entry': hex(probe['address']),
                'gate': hex(probe['gate']), 'relay': hex(probe['relay']), 'stub': hex(probe['stub']),
                'record': hex(probe['record']), 'donorTemplateSSN': probe['ssn'],
                'mandatory': probe['mandatory'], 'region': probe['region'], 'source': probe.get('source'),
                'originalBytes': probe['original'].hex(), 'patchedBytes': probe['expected'].hex(),
                'originalDisassembly': probe['disassembly'], 'stubDisassembly': decoded,
                'stubLabels': {name: hex(probe['stub'] + offset) for name, offset in labels.items()}})
        self.report.update(status='observing', armedAt=round(time.monotonic() - self.started, 6))
        self.save()
        self.resume()

    def capture(self, probe, blob, stage):
        fields = {name: struct.unpack_from('<Q', blob, offset)[0] for name, offset in helper.FIELDS.items()}
        ssn = struct.unpack_from('<Q', blob, 0x80)[0] & 0xFFFFFFFF
        api = self.api_by_ssn.get(ssn)
        if api is None or fields['class'] & 0xFFFFFFFF != 76:
            raise RuntimeError('Recorder SSN/class filter invariant failed')
        sequence = fields['sequence']
        phase = 'enter' if stage == 1 else 'return'
        key = (probe['name'], sequence)
        prefix = f"{probe['name']}-{sequence:06d}-{phase}"
        is_ex = api.endswith('Ex')
        if stage == 1:
            if is_ex:
                stack_args = self.read(fields['rsp'] + 0x28, 16)
                if len(stack_args) != 16:
                    raise RuntimeError('Ex stack arguments unavailable to external reader')
                output_size, return_pointer = struct.unpack('<QQ', stack_args)
                arguments = {'inputBuffer': fields['buffer'], 'inputLength': fields['capacity'] & 0xFFFFFFFF,
                             'outputBuffer': fields['returnLengthPointer'], 'outputLength': output_size & 0xFFFFFFFF,
                             'returnLengthPointer': return_pointer}
            else:
                arguments = {'inputBuffer': None, 'inputLength': None,
                             'outputBuffer': fields['buffer'], 'outputLength': fields['capacity'] & 0xFFFFFFFF,
                             'returnLengthPointer': fields['returnLengthPointer']}
            self.entries[key] = arguments
        elif key not in self.entries:
            raise RuntimeError('Return gate arrived without an entry record')
        arguments = self.entries[key]
        length = arguments['outputLength']
        data = self.read(arguments['outputBuffer'], min(length, helper.MAX_BUFFER)) if length else b''
        returned = self.read(arguments['returnLengthPointer'], 4) if arguments['returnLengthPointer'] else b''
        status = fields['status'] & 0xFFFFFFFF if stage == 2 else None
        row = {'gateOwner': probe['name'], 'actualAPIBySSN': api, 'syscallNumber': ssn,
               'sequence': sequence, 'phase': phase, 'tid': struct.unpack_from('<I', blob, 0x14)[0],
               'elapsed': round(time.monotonic() - self.started, 6),
               'rawGateRegisters': {'rax': hex(struct.unpack_from('<Q', blob, 0x80)[0]),
                                    'rcx': hex(struct.unpack_from('<Q', blob, 0x78)[0]),
                                    'r10': hex(fields['class']), 'rdx': hex(fields['buffer']),
                                    'r8': hex(fields['capacity']), 'r9': hex(fields['returnLengthPointer']),
                                    'rsp': hex(fields['rsp'])},
               'arguments': {name: hex(value) if value is not None else None for name, value in arguments.items()},
               'caller': hex(fields['caller']), 'headerCandidate': helper.firmware_header(data),
               'NTSTATUS': hex(status) if status is not None else None,
               'NTSTATUSsigned': C.c_int32(status).value if status is not None else None,
               'returnLength': struct.unpack('<I', returned)[0] if len(returned) == 4 else None,
               'output': {'file': prefix + '.output.bin', 'capacity': length, 'bytesRead': len(data),
                          'sha256': hashlib.sha256(data).hexdigest(), 'truncatedByLimit': length > helper.MAX_BUFFER}}
        (self.out / row['output']['file']).write_bytes(data)
        (self.out / (prefix + '.record.bin')).write_bytes(blob)
        if is_ex:
            input_length = arguments['inputLength']
            input_data = self.read(arguments['inputBuffer'], min(input_length, helper.MAX_BUFFER)) if input_length else b''
            filename = prefix + '.input.bin'
            (self.out / filename).write_bytes(input_data)
            row['input'] = {'file': filename, 'capacity': input_length, 'bytesRead': len(input_data),
                            'sha256': hashlib.sha256(input_data).hexdigest()}
            row['class76SupportConclusion'] = 'not inferred; inspect NTSTATUS and both raw buffers'
        elif stage == 2 and row['headerCandidate'] is not None:
            reported = row['headerCandidate']['bufferLength']
            payload = data[16:16 + min(max(0, len(data) - 16), reported)]
            filename = prefix + '.firmware.bin'
            (self.out / filename).write_bytes(payload)
            row['firmware'] = {'file': filename, 'reportedLength': reported, 'bytesRead': len(payload),
                               'sha256': hashlib.sha256(payload).hexdigest(), 'syscallSucceeded': C.c_int32(status).value >= 0}
        (self.out / (prefix + '.json')).write_text(json.dumps(row, indent=2), encoding='utf-8')
        self.report['calls'].append(row)
        self.event('query-' + phase, gateOwner=probe['name'], actualAPIBySSN=api,
                   sequence=sequence, NTSTATUS=row['NTSTATUS'], bytesRead=len(data))
        self.save()
        self.write(probe['record'] + (0x20 if stage == 1 else 0x28), struct.pack('<Q', sequence))
        if stage == 2:
            del self.entries[key]

    def cleanup(self):
        if self.process is None:
            return
        cleanup = self.report['cleanup']
        if self.process.poll() is None:
            try:
                self.pause()
                cleanup['restoredGates'] = []
                for probe in self.probes:
                    if probe['patched']:
                        self.protected_write(probe['address'], probe['original'])
                        if self.read(probe['address'], 32) != probe['original']:
                            raise RuntimeError('Gate restore readback mismatch: ' + probe['name'])
                        probe['patched'] = False
                        cleanup['restoredGates'].append(probe['name'])
                    if probe.get('record'):
                        self.write(probe['record'] + 4, struct.pack('<I', 1))
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
                cleanup['exitDuringRestoreGrace'] = hex(self.process.returncode & 0xFFFFFFFF)
            except subprocess.TimeoutExpired:
                cleanup.update(forcedStop=True, requestedExitCode='0x5854434c')
                if not self.k.TerminateProcess(self.handle, 0x5854434C):
                    cleanup['terminateError'] = C.get_last_error()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    cleanup['waitTimedOut'] = True
        else:
            cleanup['targetExitedBeforeRestore'] = any(p['patched'] for p in self.probes)
        # Keep all relay/trampoline pages until the process exits; threads can
        # already be inside them when the original syscall bytes are restored.
        if self.process.stdin:
            self.process.stdin.close()
        code = self.process.poll()
        self.report['finalExitCode'] = hex(code & 0xFFFFFFFF) if code is not None else None
        self.report['ownedSuspendAtEnd'] = self.suspended

    def run(self):
        try:
            self.report['sourceSha256'] = hashlib.sha256(self.engine.read_bytes()).hexdigest()
            with (self.out / 'stdout.bin').open('xb') as stdout, (self.out / 'stderr.bin').open('xb') as stderr:
                self.process = subprocess.Popen([str(self.engine)], cwd=helper.CASE, stdin=subprocess.PIPE,
                    stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW | 4)
                self.suspended = True
                deadline = self.started + helper.TIMEOUT
                self.install(deadline)
                seen, previous = set(), {}
                self.report['observedGateBytes'] = []
                while time.monotonic() < deadline:
                    exited = self.process.poll()
                    if exited is not None:
                        self.report.update(status='natural-exit', naturalExitCode=hex(exited & 0xFFFFFFFF))
                        break
                    for probe in self.probes:
                        raw = self.read(probe['address'], 32)
                        if raw != previous.get(probe['name']):
                            previous[probe['name']] = raw
                            row = {'api': probe['name'], 'elapsed': round(time.monotonic() - self.started, 6),
                                   'bytes': raw.hex(), 'patchIntact': raw == probe['expected']}
                            self.report['observedGateBytes'].append(row)
                            self.event('gate-byte-change', **row)
                        blob = self.read(probe['record'], 0x90)
                        if len(blob) != 0x90:
                            continue
                        stage = struct.unpack_from('<I', blob, 0x10)[0]
                        sequence = struct.unpack_from('<Q', blob, 0x18)[0]
                        identity = (probe['name'], sequence, stage)
                        if stage in (1, 2) and sequence and identity not in seen:
                            self.capture(probe, blob, stage)
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
    parser.add_argument('--observed-gates', action='store_true',
                        help='Validate additional syscall gates from this boot\'s kernel-return-engine summary')
    args = parser.parse_args()
    if args.label and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args.label):
        parser.error('--label must use 1-64 ASCII letters/digits/underscores/hyphens')
    if C.sizeof(C.c_void_p) != 8 or C.sizeof(MBI) != 48:
        parser.error('64-bit Windows guest Python is required')
    engines = [p for p in helper.CASE.glob('*.exe') if 'sse4' in p.name.casefold()]
    if len(engines) != 1:
        raise RuntimeError('Expected exactly one SSE4 executable')
    prefix = 'syscall-gate-trace-observed' if args.observed_gates else 'syscall-gate-trace'
    out = helper.ROOT / 'evidence' / (prefix + ('-' + args.label if args.label else ''))
    out.mkdir(parents=True, exist_ok=False)
    trace = GateTrace(out, engines[0], observed_gates=args.observed_gates)
    trace.run()
    print(json.dumps({'output': str(out), 'status': trace.report['status'],
                      'gatesCaptured': len(trace.report['calls']),
                      'installedProbeCount': trace.report['coverage']['installedProbeCount'],
                      'skippedCount': trace.report['coverage']['skippedCount'],
                      'naturalExitCode': trace.report['naturalExitCode'], 'cleanup': trace.report['cleanup']}))


if __name__ == '__main__':
    main()

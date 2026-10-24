"""Record the first native framing calls, preserving their inputs and results.

Runs only the existing guest case, with synthetic credentials and a loopback
recorder. Startup diagnostics are inherited and reported, not authorization.
"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import struct
import sys
import time
import traceback

ROOT = Path(r'C:\Lab\BugChess20260627')
sys.path.insert(0, str(Path(__file__).resolve().parent))
import guest_login_network_trace as network
from guest_firmware_scanner_probe import capture_stub, FIELDS
from guest_main_execute_probe import MainProbe


class FlowTrace(network.LoginNetworkTrace):
    def __init__(self, probe):
        super().__init__(probe)
        self.gates = []
        self.flow = probe.report['nativeFraming'] = {'calls': [], 'originalResultsPreserved': True}
        self.reply_type = next((int(arg.split('=', 1)[1], 0) for arg in sys.argv
                                if arg.startswith('--empty-reply=')), None)
        self.reply_fixture = None
        fixture_name = next((arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--reply-fixture=')), None)
        if fixture_name:
            if not fixture_name.replace('-', '').isalnum():
                raise ValueError('Invalid fixture name')
            self.reply_fixture = (ROOT/'evidence/reply-fixtures'/(fixture_name+'.bin')).read_bytes()
            if len(self.reply_fixture)>65536:
                raise ValueError('Oversize fixture')
        self.reply_sent = False
        self.second_reply_sent = False
        self.edge_active = False
        self.edge_count = 0
        self.edge_limit = next((int(a.split('=',1)[1]) for a in sys.argv if a.startswith('--max-edges=')),48)
        if not 1<=self.edge_limit<=220:
            raise ValueError('Edge limit outside diagnostic bounds')
        self.edge_stop = None
        self.sample_at = time.monotonic()+8
        self.search_stage = 'waiting-ready'
        self.model_guard = None
        self.search_index = 0
        self.search_offset = 0
        self.search_started = None
        self.search_depth = next((int(a.split('=',1)[1]) for a in sys.argv if a.startswith('--search-depth=')),8)
        if not 1<=self.search_depth<=18:
            raise ValueError('Search depth outside bounded test range')
        self.search_cases = [
            ('startpos', 'position startpos'),
            ('central-cannons', 'position startpos moves h2e2 h7e7'),
            ('rook-ending', 'position fen 4k4/9/9/9/4p4/9/9/9/4R4/3K5 w - - 0 1'),
        ]
        self.base = int(probe.report['base'], 16)
        self.reference = Path('C:\\Lab\\BugChess20260627\\evidence\\variants-resolved-v55\\avx512\\resolved-image.bin').read_bytes()
        self.mem = probe.k.VirtualAllocEx(probe.handle, None, 0x80000, 0x3000, 4)
        if not self.mem:
            raise C.WinError(C.get_last_error())
        prior = W.DWORD()
        if not probe.k.VirtualProtectEx(probe.handle, self.mem, 0x40000, 0x20, C.byref(prior)):
            raise C.WinError(C.get_last_error())
        targets = [('frame-send', 0x8fd30), ('frame-recv', 0x8fe70)]
        if '--parent-gates' in sys.argv:
            targets += [('login-init', 0x10f60), ('init-values', 0x11210), ('request-parent', 0x90090)]
        if '--load-gates' in sys.argv:
            targets += [('board-init',0xf0d0),('network-init',0x50c70),('file-mapping',0x22ce0)]
        if '--validation-edges' in sys.argv:
            targets += [('board-validation',0x11d30)]
        if '--primary-edges' in sys.argv or '--primary-observe' in sys.argv:
            targets += [('primary-data',0xa9250)]
        if '--after-init-check' in sys.argv and not any(rva==0xf0d0 for _,rva in targets):
            targets += [('board-init',0xf0d0)]
        for name, rva in targets:
            self.add_gate(name, rva)
        for argument in sys.argv:
            if argument.startswith('--checkpoint-rva='):
                self.add_gate('selected-checkpoint',int(argument.split('=',1)[1],0),checkpoint=True)

    def add_gate(self, name, rva, checkpoint=False):
        probe = self.p
        target = self.base + rva
        if any(g['target']==target and g['stage']!='done' for g in self.gates):
            self.flow.setdefault('edgeNotes', []).append('Existing gate at '+hex(rva))
            return
        if len(self.gates)>=240:
            self.flow['edgeLimitReached'] = True
            return
        original = probe.read(target, 14)
        if original != self.reference[rva:rva+14]:
            raise RuntimeError(name + ' differs from saved runtime bytes')
        index = len(self.gates)
        code, record = self.mem + index * 0x400, self.mem + 0x40000 + index * 0x400
        probe.protected_write(code, capture_stub(record, target))
        probe.protected_write(target, b'\xff\x25\0\0\0\0' + struct.pack('<Q', code))
        self.gates.append(dict(name=name, target=target, original=original,
                              code=code, record=record, stage='entry', restored=False, checkpoint=checkpoint))

    def follow_edge(self, item, regs, raw, start):
        from guest_live_prefix_emulator import emulate
        p = self.p
        self.edge_count += 1
        if self.edge_count > self.edge_limit:
            self.flow['edgeLimitReached'] = True
            return
        saved_out = p.out
        label = f'parser-edge-{self.edge_count:02d}'
        try:
            p.out = saved_out / label
            p.out.mkdir(exist_ok=False)
            teb, tid = struct.unpack_from('<QQ', raw, 0x90)
            row = emulate(p, regs, start, self.edge_stop, teb, tid)
            row.update(label=label, after=item['name'])
            self.flow.setdefault('parserEdges', []).append(row)
        finally:
            p.out = saved_out
        if row.get('stopReason') == 'native-function-boundary':
            self.add_gate(label, int(row['nextFunctionRva'], 16))
        elif row.get('stopReason') == 'external-code' and '--follow-external-returns' in sys.argv:
            target = int(row.get('externalReturn','0'),16)
            if self.base<=target<self.base+len(self.reference) and target!=start:
                self.add_gate(label,target-self.base,checkpoint=True)
            elif target==start:
                self.flow.setdefault('edgeNotes',[]).append('Do not rearm the current checkpoint before it executes')

    def read_string(self, pointer, label):
        p = self.p
        raw = p.read(pointer, 32)
        if len(raw) != 32:
            return {'objectAddress': hex(pointer), 'readBytes': len(raw)}
        length, capacity = struct.unpack_from('<QQ', raw, 16)
        row = {'objectAddress': hex(pointer), 'objectHex': raw.hex(), 'length': length, 'capacity': capacity}
        if length <= capacity <= 1048576:
            address = pointer if capacity < 16 else struct.unpack_from('<Q', raw)[0]
            data = p.read(address, length)
            (p.out / (label + '.bin')).write_bytes(data)
            row.update(dataAddress=hex(address), capturedBytes=len(data),
                       sha256=hashlib.sha256(data).hexdigest(), first64Hex=data[:64].hex())
        return row

    def snapshot_call(self, item, regs, stage):
        p = self.p
        label = item['name'] + '-' + stage
        stack = p.read(regs['rsp'], 0x4000)
        (p.out / (label + '-stack.bin')).write_bytes(stack)
        row = {'stage': stage, 'name': item['name'], 'elapsed': round(time.monotonic()-p.started, 6),
               'targetRva':hex(item['target']-self.base),
               'registers': {key: hex(value) for key, value in regs.items()},
               'stackBytes': len(stack)}
        if stage == 'entry':
            row['caller'] = hex(item['caller'])
            row['callerRva'] = hex(item['caller'] - self.base)
            row['callerBytes'] = p.read(item['caller'] - 32, 96).hex()
            item['entryRegs'] = regs
        for name in ('rcx', 'rdx', 'r8', 'r9', 'rbx', 'rsi', 'rdi'):
            address = regs[name]
            if 0x10000 <= address < 0x7fffffffffff:
                data = p.read(address, 128)
                if data:
                    row.setdefault('pointedBuffers', {})[name] = data.hex()
        if item['name'] == 'frame-send' and stage == 'entry':
            row['payload'] = self.read_string(regs['r8'], label + '-payload')
            if any(a in sys.argv for a in ('--session-marker','--session-fields','--session-layout')):
                from guest_reply_codec import decode_stored_key, encrypt_reply
                stored = self.read_string(regs['rcx']+0xb0, label+'-stored-key')
                der = decode_stored_key((p.out/(label+'-stored-key.bin')).read_bytes())
                marker = struct.pack('>II',0,0) if '--session-fields' in sys.argv else b'{"probe":"XT_LOCAL"}'
                if '--session-layout' in sys.argv:
                    version = 20260627 if '--reply-version' in sys.argv else 0
                    marker = struct.pack('>IQI',0,version,0) + (struct.pack('>I',1)+b'0')*3
                    if '--layout-tail' in sys.argv:
                        marker += struct.pack('>QQ',int(time.time()) if '--reply-clock' in sys.argv else 0,
                                              int(time.time())+86400 if '--reply-lifetime' in sys.argv else 0)
                self.reply_fixture = encrypt_reply(der, marker)
                row['sessionReply'] = {'method':'current connection key, local decoder fixture',
                    'storedKeyBytes':stored['length'],'decodedKeySha256':hashlib.sha256(der).hexdigest(),
                    'plaintextHex':marker.hex(),'replyBytes':len(self.reply_fixture),
                    'fixtureKind':'binary layout with synthetic values' if '--session-layout' in sys.argv else
                                  ('zero status and empty next field' if '--session-fields' in sys.argv else 'text marker'),
                    'authorizationResult':'not asserted'}
                (p.out/'session-reply.bin').write_bytes(self.reply_fixture)
        if item['name'] == 'frame-recv':
            for name in ('rdx', 'r8'):
                address = item['entryRegs'][name]
                row.setdefault('outputCandidates', {})[name] = self.read_string(address, label + '-' + name)
        if item['name'] == 'login-init':
            row['pointedIntegers'] = {n: p.read(item['entryRegs'][n], 4).hex() for n in ('rcx', 'rdx')}
        if item['name'] == 'primary-data':
            row['serverData'] = {'notCaptured':'variant global address not yet mapped'}
            row['outputString'] = self.read_string(item['entryRegs']['rcx'],label+'-output')
            raw_output = p.read(item['entryRegs']['rcx'],32)
            if len(raw_output)==32:
                length,capacity = struct.unpack_from('<QQ',raw_output,16)
                if 16<=length<=capacity<=512*1024*1024:
                    address = struct.unpack_from('<Q',raw_output)[0]
                    row['outputPrefix256Hex'] = p.read(address,min(length,256)).hex()
                    if stage=='return' and '--save-decoded' in sys.argv:
                        digest = hashlib.sha256()
                        with (p.out/'model-helper-output.bin').open('xb') as stream:
                            for start in range(0,length,1048576):
                                block = p.read(address+start,min(1048576,length-start))
                                if len(block)!=min(1048576,length-start):
                                    raise RuntimeError('Incomplete model helper output capture')
                                stream.write(block)
                                digest.update(block)
                        row['outputFullSha256'] = digest.hexdigest()
        if item['name'] == 'request-parent':
            row['inputStringCandidates'] = {n: self.read_string(item['entryRegs'][n], label+'-'+n)
                                            for n in ('rdx', 'r9')}
            state = p.read(item['entryRegs']['r9'], 0x200)
            (p.out/(label+'-result-structure.bin')).write_bytes(state)
            row['resultStructureSha256'] = hashlib.sha256(state).hexdigest()
        if item['name'].startswith('parser-edge-'):
            row['argumentStrings'] = {n: self.read_string(item['entryRegs'][n], label+'-'+n)
                                      for n in ('rcx','rdx','r8','r9')}
        if stage == 'entry' and item['name'] == 'frame-send':
            image = b''.join(p.read(self.base+i, min(1048576, len(self.reference)-i))
                             for i in range(0, len(self.reference), 1048576))
            (p.out / 'framing-image.bin').write_bytes(image)
            self.flow['imageBytes'] = len(image)
        self.flow['calls'].append(row)

    def poll(self):
        super().poll()
        p = self.p
        if self.model_guard is not None:
            self.model_guard.poll()
        if '--search-check' in sys.argv:
            self.poll_search()
        if '--thread-samples' in sys.argv and time.monotonic()>=self.sample_at:
            from guest_thread_sample import sample
            p.report.setdefault('threadSamples',[]).append(sample(p))
            self.sample_at = time.monotonic()+5
            p.save()
        second_type = next((int(a.split('=',1)[1],0) for a in sys.argv if a.startswith('--second-empty=')),None)
        if '--second-data' in sys.argv:
            second_type = 155
        if second_type is not None and self.reply_sent and not self.second_reply_sent and self.connection and len(self.received)>=8:
            second_at = struct.unpack_from('>I',self.received)[0]+8
            if len(self.received)>=second_at+8:
                size,kind,field = struct.unpack_from('>IHH',self.received,second_at)
                if len(self.received)>=second_at+8+size:
                    response = struct.pack('>IHH',0,second_type,0)
                    if '--second-data' in sys.argv:
                        from guest_reply_codec import cbc_encrypt
                        primary = b'XT_DATA_MARKER'
                        primary_hex = next((a.split('=',1)[1] for a in sys.argv if a.startswith('--primary-hex=')),None)
                        if primary_hex is not None:
                            primary = bytes.fromhex(primary_hex)
                            if not 1<=len(primary)<=256:
                                raise ValueError('Primary diagnostic input outside bounds')
                        pack_string = lambda b: struct.pack('>I',len(b))+b
                        primary_size = next((int(a.split('=',1)[1],0) for a in sys.argv if a.startswith('--primary-size=')),len(primary))
                        plain = (struct.pack('>I',0)+pack_string(b'XT_LOCAL')+pack_string(primary)+
                                 struct.pack('>Q',primary_size)+pack_string(hashlib.md5(primary).hexdigest().upper().encode())+
                                 pack_string(b'')+struct.pack('>Q',0)+pack_string(hashlib.md5(b'').hexdigest().upper().encode()))
                        encrypted = cbc_encrypt(plain,self.session_aes_key,bytes.fromhex('01020303030303030303010203030303'))
                        response = struct.pack('>IHH',len(encrypted),second_type,0)+encrypted
                        self.report['localRecorder']['secondDataFixture'] = {'plaintextHex':plain.hex(),
                            'purpose':'synthetic marker for downstream format observation, not model data'}
                    self.connection.sendall(response)
                    self.second_reply_sent = True
                    self.report['localRecorder']['secondExchange'] = {'requestType':kind,'requestBytes':size,
                        'responseHeaderHex':response[:8].hex(),'responseBytes':len(response),
                        'responseKind':'encrypted synthetic data fixture' if '--second-data' in sys.argv else 'empty local diagnostic frame'}
        if (self.reply_type is not None or self.reply_fixture is not None) and not self.reply_sent and self.connection and len(self.received) >= 8:
            length = struct.unpack_from('>I', self.received)[0]
            if len(self.received) >= length+8:
                response = self.reply_fixture if self.reply_fixture is not None else struct.pack('>IHH', 0, self.reply_type, 0)
                self.connection.sendall(response)
                self.reply_sent = True
                self.report['localRecorder'].update(serverResponseSent=True,
                    responseHeaderHex=response[:8].hex(), responseBytes=len(response),
                    responseSha256=hashlib.sha256(response).hexdigest(),
                    responseMeaning='synthetic decoder fixture; no successful authorization claimed')
        for item in self.gates:
            if item['stage'] == 'done':
                continue
            record = item['record'] + (0x100 if item['stage'] == 'return' else 0)
            if p.read(record, 4) != b'\x01\0\0\0':
                continue
            raw = p.read(record, 0xa0)
            regs = {n: struct.unpack_from('<Q', raw, off)[0] for n, off in FIELDS.items()}
            if item.get('checkpoint'):
                self.edge_active = True
                self.edge_stop = self.edge_stop or 0xffffffffffffffff
                item['caller'] = item['target']
                self.snapshot_call(item, regs, 'entry')
                p.protected_write(item['target'],item['original'])
                item['restored'] = True
                item['stage'] = 'done'
                self.follow_edge(item,regs,raw,item['target'])
                p.save()
                p.write(record+4,struct.pack('<I',1))
                continue
            if item['stage'] == 'entry':
                item['caller'] = int.from_bytes(p.read(regs['rsp'], 8), 'little')
                self.snapshot_call(item, regs, 'entry')
                retcode = item['code'] + 0x200
                p.protected_write(retcode, capture_stub(item['record']+0x100, item['caller']))
                p.write(regs['rsp'], struct.pack('<Q', retcode))
                p.protected_write(item['target'], item['original'])
                item['restored'] = True
                item['stage'] = 'return'
                if item['name']=='request-parent' and '--parser-edges' in sys.argv:
                    self.edge_active = True
                    self.edge_stop = item['caller']
                    self.follow_edge(item, regs, raw, item['target'])
                if item['name']=='init-values' and '--init-edges' in sys.argv:
                    self.edge_active = True
                    self.edge_stop = item['caller']
                    self.follow_edge(item, regs, raw, item['target'])
                if item['name']=='board-validation' and '--validation-edges' in sys.argv:
                    self.edge_active = True
                    self.edge_stop = item['caller']
                    self.follow_edge(item, regs, raw, item['target'])
                if item['name']=='primary-data' and '--primary-edges' in sys.argv:
                    self.edge_active = True
                    self.edge_stop = item['caller']
                    self.follow_edge(item, regs, raw, item['target'])
                if item['name']=='primary-data' and '--model-field-guard' in sys.argv:
                    from guest_model_guard import ModelGuard
                    self.model_guard = ModelGuard(self,raw)
            else:
                self.snapshot_call(item, regs, 'return')
                if item['name']=='primary-data' and '--model-parser-inspect' in sys.argv and not regs['rax']&255:
                    saved_rax = regs['rsp']-16
                    if p.read(saved_rax,8)!=struct.pack('<Q',regs['rax']):
                        raise RuntimeError('Model helper gate saved RAX mismatch')
                    p.write(saved_rax,struct.pack('<Q',(regs['rax']&~255)|1))
                    self.flow['originalResultsPreserved'] = False
                    p.report['modelParserDiagnostic'] = {'originalAL':0,'appliedAL':1,
                        'purpose':'observe independent downstream model parsing only; not a working-engine verification',
                        'sourceExeModified':False}
                # The function entry was restored before executing it; it can
                # now be observed again even while this return gate is waiting.
                item['stage'] = 'done'
                if item['name']=='request-parent':
                    self.edge_active = False
                    if regs['rax'] & 255:
                        self.session_aes_key = p.read(item['entryRegs']['rcx']+0x130,16)
                    if '--uci-check' in sys.argv and regs['rax'] & 255:
                        p.process.stdin.write(b'uci\nisready\n')
                        p.process.stdin.flush()
                        p.report['uciProbe'] = {'commands':['uci','isready'],
                            'submittedAfterParserReturn':True,'parserReturnAL':regs['rax']&255}
                    if '--stop-after-parser' in sys.argv:
                        p.report['flowObservationComplete'] = True
                    if '--parent-edges' in sys.argv:
                        self.edge_active = True
                        self.edge_stop = next(g['caller'] for g in self.gates if g['name']=='login-init')
                        self.follow_edge(item, regs, raw, item['caller'])
                if item['name']=='login-init' and '--stop-after-login' in sys.argv:
                    self.edge_active = False
                    p.report['flowObservationComplete'] = True
                if item['name']=='init-values' and '--stop-after-init' in sys.argv:
                    self.edge_active = False
                    p.report['flowObservationComplete'] = True
                if item['name']=='board-init' and '--post-board-edges' in sys.argv:
                    self.edge_active = True
                    self.edge_stop = 0xffffffffffffffff
                    self.follow_edge(item, regs, raw, item['caller'])
                if item['name']=='board-init' and '--after-init-check' in sys.argv:
                    self.add_gate('late-startup-check',0x532ef,checkpoint=True)
                if item['name'].startswith('parser-edge-') and self.edge_active:
                    self.follow_edge(item, regs, raw, item['caller'])
                elif '--trace-return' in sys.argv:
                    from guest_live_prefix_emulator import emulate
                    saved_out = p.out
                    try:
                        p.out = saved_out/(item['name']+'-return-trace')
                        p.out.mkdir(exist_ok=False)
                        teb, tid = struct.unpack_from('<QQ', raw, 0x90)
                        item['rowTrace'] = emulate(p, regs, item['caller'], self.base+0x103e9, teb, tid)
                        self.flow.setdefault('returnTraces', {})[item['name']] = item['rowTrace']
                    finally:
                        p.out = saved_out
                item['stage'] = 'done'
            p.save()
            p.write(record+4, struct.pack('<I', 1))

    def poll_search(self):
        """Run three bounded protocol checks after the real readyok arrives."""
        p = self.p
        if self.search_stage == 'done':
            return
        output = (p.out/'stdout.bin').read_bytes()
        report = p.report.setdefault('searchProbe', {
            'scope': 'bounded functional checks; not strength or authorization verification',
            'cases': [], 'completed': False,
        })
        def send(commands):
            p.process.stdin.write(('\n'.join(commands)+'\n').encode('ascii'))
            p.process.stdin.flush()
        if self.search_stage == 'waiting-ready':
            if b'\nreadyok' not in output:
                return
            self.search_stage = 'start-case'
        if self.search_stage == 'searching':
            current = output[self.search_offset:].decode('utf-8', errors='replace')
            lines = current.splitlines()
            best = next((s for s in lines if s.startswith('bestmove ')), None)
            elapsed = time.monotonic()-self.search_started
            if best is not None:
                report['cases'][-1].update(bestmove=best, elapsed=round(elapsed,3),
                    infoLines=[s for s in lines if s.startswith('info ')][-12:])
                self.search_index += 1
                self.search_stage = 'start-case'
            elif elapsed > 7 and not report['cases'][-1].get('stopSent'):
                send(['stop'])
                report['cases'][-1]['stopSent'] = True
            elif elapsed > 10:
                report['cases'][-1]['timedOut'] = True
                self.search_stage = 'done'
                send(['quit'])
                p.save()
                return
        if self.search_stage == 'start-case':
            if self.search_index == len(self.search_cases):
                report['completed'] = True
                self.search_stage = 'done'
                send(['quit'])
            else:
                name, position = self.search_cases[self.search_index]
                commands = ['ucinewgame', 'setoption name Hash value 64',
                            'setoption name Ponder value false', 'setoption name ShowInfoDepth value 10',
                            position, 'go depth '+str(self.search_depth)]
                self.search_offset = len(output)
                self.search_started = time.monotonic()
                report['cases'].append({'name':name, 'commands':commands})
                self.search_stage = 'searching'
                send(commands)
            p.save()

    def cleanup(self):
        p = self.p
        if self.model_guard is not None:
            self.model_guard.cleanup()
        if p.process is not None and p.process.poll() is None:
            for item in self.gates:
                try:
                    if not item['restored']:
                        p.protected_write(item['target'], item['original'])
                    p.write(item['record']+4, struct.pack('<I', 1))
                    p.write(item['record']+0x104, struct.pack('<I', 1))
                except OSError as exc:
                    self.flow.setdefault('cleanupNotes', []).append(str(exc))
        super().cleanup()


if __name__ == '__main__':
    label = sys.argv[1] if len(sys.argv)>1 else 'login-flow-v1'
    if not label.replace('-', '').isalnum():
        raise ValueError('Invalid label')
    extra = [a for a in sys.argv[2:] if a in ('--trace-return', '--native-cpuid', '--parent-gates', '--stop-native', '--parser-edges', '--session-marker', '--session-fields', '--session-layout', '--layout-tail', '--stop-after-parser', '--reply-clock', '--uci-check', '--parent-edges', '--stop-after-login', '--thread-samples', '--load-gates', '--init-edges', '--stop-after-init', '--validation-edges', '--second-data', '--post-board-edges', '--follow-external-returns', '--reply-lifetime', '--after-init-check', '--reply-version', '--primary-edges', '--primary-observe', '--save-decoded', '--model-parser-inspect')
             or a.startswith(('--empty-reply=', '--capture-seconds=', '--reply-fixture=', '--second-empty=', '--checkpoint-rva=', '--max-edges=', '--emulation-count=', '--primary-hex=', '--primary-size='))]
    if '--search-check' in sys.argv:
        extra.append('--search-check')
        if '--uci-check' not in extra:
            extra.append('--uci-check')
    extra += [a for a in sys.argv if a in ('--observe-model-fields','--emulate-clear-tf','--model-field-guard')]
    extra += [a for a in sys.argv if a.startswith('--search-depth=')]
    sys.argv = [__file__, label, '--pass-second', '--login-probe', '--network-trace',
                '--account-only', '--network-early', '--local-transport', *extra]
    out = ROOT / 'evidence' / ('firmware-scanner-'+label)
    out.mkdir(exist_ok=False)
    account = ROOT / 'cases/avx512-original-offline-v47/account.txt'
    lifecycle = {'syntheticInput': True, 'created': False}
    network.LoginNetworkTrace = FlowTrace
    try:
        cache = account.parent/'login.txt'
        if cache.exists():
            if (ROOT/'originals/login.txt').exists():
                raise RuntimeError('Original login cache must not be moved')
            cache.replace(out/'preexisting-login-cache.txt')
            lifecycle['preexistingCachePreserved'] = True
        probe = MainProbe(out)
        with account.open('x', encoding='ascii', newline='') as stream:
            stream.write('00000000\r\nxtprobe0\r\n')
        lifecycle['created'] = True
        probe.run_probe()
    except Exception:
        lifecycle['error'] = traceback.format_exc()
    finally:
        if lifecycle['created'] and account.exists():
            account.replace(out / 'synthetic-account-input.txt')
        if lifecycle['created'] and (account.parent/'login.txt').exists():
            (account.parent/'login.txt').replace(out/'generated-login-cache.txt')
            lifecycle['generatedCachePreserved'] = True
        lifecycle['accountFileAbsentAfterCleanup'] = not account.exists()
        (out/'input-lifecycle.json').write_text(json.dumps(lifecycle, indent=2), encoding='utf-8')

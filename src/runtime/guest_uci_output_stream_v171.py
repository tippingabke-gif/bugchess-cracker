"""Incremental UCI relay using one shared read handle per engine session."""
import re
import sys
import time


class OutputPump:
    def __init__(self, offset=0, pending=b'', sink=None):
        self.offset = offset
        self.pending = pending
        self.sink = sink if sink is not None else sys.stdout.buffer
        self.stream = None
        self.path = None
        self.stats = {'opens': 0, 'calls': 0, 'bytes': 0, 'lines': 0, 'maxCallSeconds': 0.0}

    def __call__(self, probe, final=False):
        started = time.monotonic()
        self.stats['calls'] += 1
        path = probe.out / 'stdout.bin'
        if self.path is not None and path != self.path:
            raise RuntimeError('Output reader belongs to a different engine session')
        try:
            if self.stream is None:
                try:
                    stream = path.open('rb', buffering=0)
                except FileNotFoundError:
                    return
                stream.seek(self.offset)
                self.stream, self.path = stream, path
                self.stats['opens'] += 1
            wrote = False
            while True:
                data = self.stream.read(65536)
                self.offset += len(data)
                self.stats['bytes'] += len(data)
                self.pending += data
                lines = self.pending.split(b'\n')
                self.pending = lines.pop()
                if final and not data and self.pending:
                    lines.append(self.pending)
                    self.pending = b''
                for raw in lines:
                    line = raw.strip(b'\r')
                    if not line:
                        continue
                    if not line.startswith((b'id ', b'option ', b'uciok', b'readyok', b'info ', b'bestmove ')):
                        line = b'info string ' + line
                    if line.startswith(b'info '):
                        line = re.sub(rb'\bscore (-?\d+)(?=\s|$)', rb'score cp \1', line)
                    self.sink.write(line+b'\n')
                    self.stats['lines'] += 1
                    wrote = True
                if not final or not data:
                    break
            if wrote:
                self.sink.flush()
        finally:
            self.stats['maxCallSeconds'] = max(self.stats['maxCallSeconds'], time.monotonic()-started)
            if final and self.stream is not None:
                self.stream.close()
                self.stream = None
            if hasattr(probe, 'report'):
                probe.report['outputRelay'] = dict(self.stats)


def install(namespace):
    """Lazy migration lets any already executing old output() call finish first."""
    if namespace.get('_stream_output_v171_installed'):
        return
    namespace['_stream_output_v171_previous'] = namespace['output']
    def output(probe, final=False):
        pump = namespace.get('_stream_output_v171_pump')
        if pump is None:
            pump = OutputPump(namespace.get('offset', 0), namespace.get('pending', b''))
            namespace['_stream_output_v171_pump'] = pump
        return pump(probe, final)
    namespace['output'] = output
    namespace['_stream_output_v171_installed'] = True

from pathlib import Path
import ast, json
root = Path(__file__).resolve().parents[1]
files = sorted((root / 'src/runtime').rglob('*.py'))
for path in files:
    ast.parse(path.read_text(encoding='utf-8-sig'), filename=str(path))
assert files
for name in ('README.md', '使用说明.md', '原理说明.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'):
    assert (root / name).is_file(), name
for name in ('board-analysis.png', 'engine-detail.png'):
    assert (root / 'assets' / name).is_file(), name
manifest = json.loads((root / 'src/payload-manifest.json').read_text())
assert all('sha256' in item and '..' not in Path(item['path']).parts for item in manifest)
print('Validated', len(files), 'Python sources and required documentation.')

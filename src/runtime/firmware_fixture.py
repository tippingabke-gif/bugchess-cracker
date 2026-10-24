"""Build a diagnostic firmware response variant, changing only SMBIOS strings.

The caller must provide a successful SystemFirmwareTableInformation response.
No operating-system firmware, files, UUID fields, or hardware are modified here.
"""
import hashlib
import re
import struct


def mask_virtualization_strings(response):
    if len(response) < 24:
        raise ValueError('Firmware response shorter than fixed headers')
    provider, action, table_id, length = struct.unpack_from('<IIII', response)
    if (provider, action, table_id) != (0x52534d42, 1, 0):
        raise ValueError('Expected RSMB get-table response')
    if not 8 <= length <= len(response)-16:
        raise ValueError('Invalid firmware buffer length')
    raw = response[16:16+length]
    table_length = struct.unpack_from('<I', raw, 4)[0]
    if table_length != len(raw)-8:
        raise ValueError('Raw SMBIOS table length mismatch')
    changes = []
    spans = []
    position = 8
    while position < len(raw):
        if position+4 > len(raw):
            raise ValueError('Truncated SMBIOS structure')
        kind, fixed_length = raw[position:position+2]
        if fixed_length < 4 or position+fixed_length+2 > len(raw):
            raise ValueError('Invalid SMBIOS formatted section length')
        strings_start = position+fixed_length
        strings_end = raw.find(b'\0\0', strings_start)
        if strings_end < 0:
            raise ValueError('Unterminated SMBIOS string set')
        spans.append((kind, strings_start, strings_end))
        position = strings_end+2
        if kind == 127:
            break
    transformed = bytearray(response)
    replacements = ((b'vmware',b'System'),(b'virtual',b'Generic'),(b'vmw',b'OEM'))
    for kind, start, end in spans:
        original = raw[start:end]
        updated = original
        for term, replacement in replacements:
            updated = re.sub(re.escape(term),replacement,updated,flags=re.IGNORECASE)
        if updated != original:
            assert len(updated) == len(original)
            transformed[16+start:16+end] = updated
            changes.append({'structureType':kind,'offset':16+start,'size':end-start,
                            'oldSHA256':hashlib.sha256(original).hexdigest(),
                            'newSHA256':hashlib.sha256(updated).hexdigest()})
    assert len(transformed) == len(response)
    return bytes(transformed), changes


if __name__ == '__main__':
    from pathlib import Path
    import ctypes as C
    from ctypes import wintypes as W
    import json
    k = C.WinDLL('kernel32')
    k.GetSystemFirmwareTable.argtypes = [W.DWORD,W.DWORD,C.c_void_p,W.DWORD]
    k.GetSystemFirmwareTable.restype = W.UINT
    count = k.GetSystemFirmwareTable(0x52534d42,0,None,0)
    buffer = C.create_string_buffer(count)
    got = k.GetSystemFirmwareTable(0x52534d42,0,buffer,count)
    original = struct.pack('<IIII',0x52534d42,1,0,got)+buffer.raw[:got]
    modified, changes = mask_virtualization_strings(original)
    repeated, second_changes = mask_virtualization_strings(modified)
    changed_offsets = [index for index,(a,b) in enumerate(zip(original,modified)) if a!=b]
    allowed_offsets = {index for change in changes for index in range(change['offset'],change['offset']+change['size'])}
    report = {'source':'guest firmware query; no target execution or system modifications',
              'bytes':len(original),'originalSHA256':hashlib.sha256(original).hexdigest(),
              'modifiedSHA256':hashlib.sha256(modified).hexdigest(),'changedStringSets':changes,
              'sameLength':len(original)==len(modified),'idempotent':modified==repeated and not second_changes,
              'changedByteOffsets':changed_offsets,'allChangesWithinStringSpans':set(changed_offsets)<=allowed_offsets,
              'nulPositionsUnchanged':[i for i,b in enumerate(original) if b==0]==[i for i,b in enumerate(modified) if b==0]}
    Path(r'C:\Lab\BugChess20260627\evidence\firmware-fixture-validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')

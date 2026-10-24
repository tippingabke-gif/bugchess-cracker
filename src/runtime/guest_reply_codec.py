"""Reproduce observed client-key storage and local RSA decoder fixtures."""
import hashlib
import json
import os
from pathlib import Path
import struct

def xtime(x):
    return ((x<<1)^((x>>7)*0x11b))&255

def multiply(a, b):
    answer = 0
    while b:
        if b&1:
            answer ^= a
        a, b = xtime(a), b>>1
    return answer

def inverse(x):
    if not x:
        return 0
    answer, power = 1, 254
    while power:
        if power&1:
            answer = multiply(answer, x)
        x, power = multiply(x, x), power>>1
    return answer

def rotate(x, bits):
    return ((x<<bits)|(x>>(8-bits)))&255

SBOX = []
for value in range(256):
    inv = inverse(value)
    SBOX.append(inv^rotate(inv,1)^rotate(inv,2)^rotate(inv,3)^rotate(inv,4)^0x63)

def expand(key):
    assert len(key)==16
    words = list(key)
    rcon = 1
    while len(words)<176:
        block = words[-4:]
        if len(words)%16 == 0:
            block = [SBOX[x] for x in block[1:]+block[:1]]
            block[0] ^= rcon
            rcon = xtime(rcon)
        for value in block:
            words.append(words[-16]^value)
    return words

def encrypt_block(block, schedule):
    state = [x^y for x,y in zip(block,schedule[:16])]
    for turn in range(1,11):
        state = [SBOX[x] for x in state]
        state = [state[4*((column+row)%4)+row] for column in range(4) for row in range(4)]
        if turn<10:
            for column in range(4):
                at = 4*column
                a,b,c,d = state[at:at+4]
                total = a^b^c^d
                state[at:at+4] = [a^total^xtime(a^b), b^total^xtime(b^c),
                                  c^total^xtime(c^d), d^total^xtime(d^a)]
        state = [x^y for x,y in zip(state,schedule[16*turn:16*turn+16])]
    return bytes(state)

def cfb128_decrypt(data, key, iv):
    schedule = expand(key)
    output = bytearray()
    feedback = iv
    for start in range(0,len(data),16):
        block = data[start:start+16]
        output.extend(a^b for a,b in zip(block, encrypt_block(feedback,schedule)))
        feedback = block
    return bytes(output)

def cbc_encrypt(data, key, iv, pad=True):
    if pad:
        count = 16-len(data)%16
        data += bytes([count])*count
    if len(data)%16:
        raise ValueError('CBC input requires complete blocks')
    schedule = expand(key)
    out = bytearray()
    for start in range(0,len(data),16):
        iv = encrypt_block(bytes(a^b for a,b in zip(data[start:start+16],iv)),schedule)
        out.extend(iv)
    return bytes(out)

def tlv(data, position):
    tag, size = data[position:position+2]
    position += 2
    if size&128:
        count = size&127
        assert 1<=count<=4
        size = int.from_bytes(data[position:position+count], 'big')
        position += count
    end = position+size
    assert end<=len(data)
    return tag, data[position:end], end

def parse_private(der):
    tag, sequence, end = tlv(der,0)
    assert tag==0x30 and end==len(der)
    values, position = [], 0
    while position<len(sequence):
        tag, raw, position = tlv(sequence,position)
        assert tag==2
        values.append(int.from_bytes(raw,'big'))
    assert len(values)==9 and values[0]==0
    _,n,e,d,p,q,dp,dq,iq = values
    assert p*q==n and d%(p-1)==dp and d%(q-1)==dq and iq*q%p==1
    return n,e,d

def decode_stored_key(stored):
    encrypted = bytes.fromhex(stored.decode('ascii'))
    plain = cfb128_decrypt(encrypted, bytes.fromhex('4537e684821578035774dd5476492786'),
                           bytes.fromhex('01020303030303030303010203030303'))
    der = bytes.fromhex(plain.decode('ascii'))
    parse_private(der)
    return der

def encrypt_reply(der, plain):
    n,e,d = parse_private(der)
    length = (n.bit_length()+7)//8
    encrypted = bytearray()
    for start in range(0,len(plain),length-11):
        block = plain[start:start+length-11]
        padding = bytearray()
        while len(padding)<length-len(block)-3:
            padding.extend(value for value in os.urandom(64) if value)
        encoded = b'\0\2'+bytes(padding[:length-len(block)-3])+b'\0'+block
        cipher = pow(int.from_bytes(encoded,'big'),e,n).to_bytes(length,'big')
        assert pow(int.from_bytes(cipher,'big'),d,n).to_bytes(length,'big')==encoded
        encrypted.extend(cipher)
    return struct.pack('>IHH',len(encrypted),151,0)+encrypted

if __name__=='__main__':
    assert encrypt_block(bytes.fromhex('00112233445566778899aabbccddeeff'),
                         expand(bytes(range(16)))).hex()=='69c4e0d86a7b0430d8cdb78070b4c55a'
    assert cbc_encrypt(bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
                       bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
                       bytes.fromhex('000102030405060708090a0b0c0d0e0f'),pad=False).hex()=='7649abac8119b246cee98e9b12e9197d'
    root = Path(r'C:\Lab\BugChess20260627/evidence')
    cases = []
    for label in ('login-parser-v4','login-rsa-marker-v5'):
        case = root/('firmware-scanner-'+label)
        recovered = decode_stored_key((case/'parser-edge-03-entry-rdx.bin').read_bytes())
        expected = (case/'parser-edge-07-entry-rdx.bin').read_bytes()
        assert recovered == expected
        cases.append({'case':label,'decodedKeyBytes':len(recovered),'matchesNativeDecoder':True,
                      'keySha256':hashlib.sha256(recovered).hexdigest()})
    (root/'reply-codec-selftest.json').write_text(json.dumps({'aesFipsVector':True,'cbcNistVector':True,'cases':cases,
        'storageCipher':'AES-128-CFB128; hex before and after',
        'differentKeyBetweenRuns':cases[0]['keySha256']!=cases[1]['keySha256']},indent=2),encoding='utf-8')

"""Extend only proven VEX-zero followed by unmasked stack stores; keep other opcodes unchanged."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_avx512_hybrid_v105.py').read_text().split('mainmod.MainProbe=HybridProbe')[0]
source=source.replace('avx512-hybrid-v105','avx512-nativezeros-v118')
exec(compile(source,str(ROOT/'guest_avx512_hybrid_v105.py'),'exec'))
import capstone
from capstone.x86_const import X86_OP_MEM,X86_OP_REG,X86_REG_RSP

def zero_stack_group(self,ip,raw,context,row):
    preceding=self.read(ip-4,4)
    if preceding not in tuple(bytes.fromhex(h) for h in ('c5f857c0','c5fc57c0','c5f9efc0','c5fdefc0')):return False
    if raw[0x2a0:0x2b0]!=bytes(16):return False
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    group=[]
    for ins in md.disasm(self.read(ip,128),ip):
        if ins.mnemonic not in ('vmovups','vmovdqu64','vmovdqu32') or len(ins.operands)!=2:break
        dst,src=ins.operands
        if dst.type!=X86_OP_MEM or dst.size!=64 or src.type!=X86_OP_REG or ins.reg_name(src.reg)!='zmm0':break
        if dst.mem.base!=X86_REG_RSP or dst.mem.index or not 0<=dst.mem.disp<=0x2000:break
        if '{' in ins.op_str:break
        group.append((ins.address,ins.size,dst.mem.disp))
    if not group:return False
    rsp=struct.unpack_from('<Q',raw,0x198)[0]
    for _,_,offset in group:self.write(rsp+offset,bytes(64))
    end=group[-1][0]+group[-1][1]
    self.write(context+0xf8,struct.pack('<Q',end))
    row['stackZeroGroup']={'stores':len(group),'bytes':len(group)*64,'precedingVexZero':preceding.hex(),'displacements':[offset for _,_,offset in group],'continuedRva':hex(end-int(self.report['base'],16))}
    return True

native_source=(ROOT/'guest_avx512_native_core_v104.py').read_text()
needle="                    if ip==base+0x215e6 and code[:19]==bytes.fromhex('62f2fd487cc762f1fe487f430162f1fe487f03'):"
replacement="""                    if self.zero_stack_group(ip,raw,context,row):
                        direct=True
                    elif ip==base+0x215e6 and code[:19]==bytes.fromhex('62f2fd487cc762f1fe487f430162f1fe487f03'):"""
assert native_source.count(needle)==1
namespace={'__name__':'native_zero_core_v118'}
exec(compile(native_source.replace(needle,replacement).replace('time.monotonic()+65','time.monotonic()+120'),str(ROOT/'guest_avx512_native_core_v104.py'),'exec'),namespace)
HybridProbe.arm_exit=namespace['NativeInitProbe'].arm_exit
HybridProbe.zero_stack_group=zero_stack_group
mainmod.MainProbe=HybridProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativezeros-v118','AVX512','v62']
with (ROOT/'evidence/avx512-nativezeros-v118-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

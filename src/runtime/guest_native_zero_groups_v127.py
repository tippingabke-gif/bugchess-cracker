"""Continue proven zero stores to image data as well as bounded stack slots."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_ternary_v126.py').read_text().rsplit('\nmainmod.MainProbe=MaskProbe',1)[0]
source=source.replace('avx512-nativeternary-v126','avx512-nativezero-groups-v127')
exec(compile(source,str(ROOT/'guest_native_ternary_v126.py'),'exec'))
from capstone.x86_const import X86_OP_MEM,X86_OP_REG,X86_REG_RSP,X86_REG_RIP

def zero_memory_group(self,ip,raw,context,row):
    preceding=self.read(ip-4,4)
    if preceding not in tuple(bytes.fromhex(h) for h in ('c5f857c0','c5fc57c0','c5f9efc0','c5fdefc0')):return False
    if raw[0x2a0:0x2b0]!=bytes(16):return False
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    base=int(self.report['base'],16);rsp=struct.unpack_from('<Q',raw,0x198)[0]
    group=[]
    for ins in md.disasm(self.read(ip,160),ip):
        if ins.mnemonic not in ('vmovups','vmovdqu64','vmovdqu32') or len(ins.operands)!=2 or '{' in ins.op_str:break
        dst,src=ins.operands
        if dst.type!=X86_OP_MEM or dst.size!=64 or src.type!=X86_OP_REG or ins.reg_name(src.reg)!='zmm0' or dst.mem.index:break
        if dst.mem.base==X86_REG_RSP and 0<=dst.mem.disp<=0x2000:target=rsp+dst.mem.disp
        elif dst.mem.base==X86_REG_RIP:
            target=ins.address+ins.size+dst.mem.disp
            if not base<=target<base+0x2b70000-64:break
        else:break
        group.append((ins.address,ins.size,target))
    if not group:return False
    for _,_,target in group:self.write(target,bytes(64))
    end=group[-1][0]+group[-1][1]
    self.write(context+0xf8,struct.pack('<Q',end))
    row['zeroStoreGroup']={'stores':len(group),'bytes':len(group)*64,'precedingVexZero':preceding.hex(),
        'continuedRva':hex(end-base)}
    return True

MaskProbe.zero_stack_group=zero_memory_group
prior_stop=MaskProbe.attach_after_native
def rich_stop(self,record,raw):
    ip=struct.unpack_from('<Q',raw,0x1f8)[0]
    self.report['nativeStopContext']={'preceding32':self.read(ip-32,32).hex(),'xmm0':raw[0x2a0:0x2b0].hex()}
    return prior_stop(self,record,raw)
MaskProbe.attach_after_native=rich_stop
mainmod.MainProbe=MaskProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativezero-groups-v127','AVX512','v62']
with (ROOT/'evidence/avx512-nativezero-groups-v127-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

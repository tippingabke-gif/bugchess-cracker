"""Cover unmasked 128-bit ternary logic from decoded operands, then stop on new opcodes."""
from pathlib import Path
ROOT=Path(r'C:\Lab\BugChess20260627')
source=(ROOT/'guest_native_mask_v125.py').read_text().rsplit('\nmainmod.MainProbe=MaskProbe',1)[0]
source=source.replace('avx512-nativemask-v125','avx512-nativeternary-v126')
exec(compile(source,str(ROOT/'guest_native_mask_v125.py'),'exec'))
from capstone.x86_const import X86_OP_REG,X86_OP_IMM
prior_mask_step=MaskProbe.mask_step

def generalized_step(self,ip,code,raw,context,row):
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    ins=next(md.disasm(code,ip,count=1),None)
    if ins and ins.mnemonic in ('vpternlogd','vpternlogq') and len(ins.operands)==4 and '{' not in ins.op_str:
        ops=ins.operands
        if all(op.type==X86_OP_REG and ins.reg_name(op.reg).startswith('xmm') for op in ops[:3]) and ops[3].type==X86_OP_IMM:
            regs=[int(ins.reg_name(op.reg)[3:]) for op in ops[:3]]
            if all(0<=r<16 for r in regs):
                values=[raw[0x2a0+i*16:0x2b0+i*16] for i in regs]
                value=ternary(*values,ops[3].imm)
                row['ternary128']={'registers':regs,'immediate':ops[3].imm,'inputs':[v.hex() for v in values],'output':value.hex()}
                return vector_load(regs[0],value),ins.size,False
    return prior_mask_step(self,ip,code,raw,context,row)

MaskProbe.mask_step=generalized_step
mainmod.MainProbe=MaskProbe
sys.argv=[str(ROOT/'guest_variant_search_v58.py'),'avx512-nativeternary-v126','AVX512','v62']
with (ROOT/'evidence/avx512-nativeternary-v126-python-stacks.txt').open('w') as stacks:
    faulthandler.dump_traceback_later(45,repeat=True,file=stacks)
    try:runpy.run_path(str(ROOT/'guest_variant_search_v58.py'),run_name='__main__')
    finally:faulthandler.cancel_dump_traceback_later()

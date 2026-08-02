use crate::{runtime::Runtime, vm::bytecode::VMReg};

use iced_x86::code_asm::{
    asm_traits::{CodeAsmAdd, CodeAsmCmp, CodeAsmImul2, CodeAsmMov, CodeAsmSub},
    ptr, qword_ptr, AsmMemoryOperand, AsmRegister32, AsmRegister64, CodeAssembler,
};

pub fn load_reg<T>(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: T)
where
    CodeAssembler: CodeAsmMov<T, AsmMemoryOperand>,
{
    // mov ..., [...]
    rt.asm
        .mov(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn load_reg32(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: AsmRegister32) {
    // mov ..., [...]
    rt.asm
        .mov(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn load_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    src: VMReg,
    tmp: AsmRegister64,
    dst: AsmRegister64,
) {
    // mov ..., [...]
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
    // mov ..., [...]
    rt.asm.mov(dst, ptr(tmp)).unwrap();
}

pub fn store_reg<T>(rt: &mut Runtime, base: AsmRegister64, src: T, dst: VMReg)
where
    CodeAssembler: CodeAsmMov<AsmMemoryOperand, T>,
{
    // mov [...], ...
    rt.asm
        .mov(ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn store_reg32(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister32, dst: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn store_imm(rt: &mut Runtime, base: AsmRegister64, src: i32, dst: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn store_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    dst: VMReg,
    tmp: AsmRegister64,
    src: AsmRegister64,
) {
    // mov ..., [...]
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(dst) as i32 * 8))
        .unwrap();
    // mov [...], ...
    rt.asm.mov(ptr(tmp), src).unwrap();
}

pub fn add_reg<T>(rt: &mut Runtime, base: AsmRegister64, src: T, dst: VMReg)
where
    CodeAssembler: CodeAsmAdd<AsmMemoryOperand, T>,
{
    // add [...], ...
    rt.asm
        .add(ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn add_imm(rt: &mut Runtime, base: AsmRegister64, src: i32, dst: VMReg) {
    // add [...], ...
    rt.asm
        .add(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn reg_add<T>(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: T)
where
    CodeAssembler: CodeAsmAdd<T, AsmMemoryOperand>,
{
    // add ..., [...]
    rt.asm
        .add(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn sub_reg<T>(rt: &mut Runtime, base: AsmRegister64, src: T, dst: VMReg)
where
    CodeAssembler: CodeAsmSub<AsmMemoryOperand, T>,
{
    // sub [...], ...
    rt.asm
        .sub(ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn sub_imm(rt: &mut Runtime, base: AsmRegister64, src: i32, dst: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn reg_sub<T>(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: T)
where
    CodeAssembler: CodeAsmSub<T, AsmMemoryOperand>,
{
    // sub ..., [...]
    rt.asm
        .sub(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn cmp_reg<T>(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: T)
where
    CodeAssembler: CodeAsmCmp<AsmMemoryOperand, T>,
{
    // cmp [...], ...
    rt.asm
        .cmp(ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn cmp_imm(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: i32) {
    // cmp [...], ...
    rt.asm
        .cmp(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn reg_imul<T>(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: T)
where
    CodeAssembler: CodeAsmImul2<T, AsmMemoryOperand>,
{
    // imul ..., [...]
    rt.asm
        .imul_2(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn push(rt: &mut Runtime, base: AsmRegister64, src: VMReg) {
    // push [...]
    rt.asm
        .push(qword_ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn pop(rt: &mut Runtime, base: AsmRegister64, dst: VMReg) {
    // pop [...]
    rt.asm
        .pop(qword_ptr(base + rt.mapper.index(dst) as i32 * 8))
        .unwrap();
}

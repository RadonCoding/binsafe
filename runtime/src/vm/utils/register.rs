use crate::{runtime::Runtime, vm::bytecode::VMReg};

use iced_x86::code_asm::{
    asm_traits::{CodeAsmAdd, CodeAsmCmp, CodeAsmImul2, CodeAsmMov, CodeAsmSub},
    ptr, qword_ptr, AsmMemoryOperand, AsmRegister64, CodeAssembler,
};

pub fn load<T>(rt: &mut Runtime, base: AsmRegister64, dst: T, src: VMReg)
where
    CodeAssembler: CodeAsmMov<T, AsmMemoryOperand>,
{
    // mov ..., [...]
    rt.asm
        .mov(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn store<T>(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: T)
where
    CodeAssembler: CodeAsmMov<AsmMemoryOperand, T>,
{
    // mov [...], ...
    rt.asm
        .mov(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn add_to_virtual<T>(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: T)
where
    CodeAssembler: CodeAsmAdd<AsmMemoryOperand, T>,
{
    // add [...], ...
    rt.asm
        .add(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn sub_from_virtual<T>(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: T)
where
    CodeAssembler: CodeAsmSub<AsmMemoryOperand, T>,
{
    // sub [...], ...
    rt.asm
        .sub(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn sub_from_native<T>(rt: &mut Runtime, base: AsmRegister64, dst: T, src: VMReg)
where
    CodeAssembler: CodeAsmSub<T, AsmMemoryOperand>,
{
    // sub ..., [...]
    rt.asm
        .sub(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn cmp_with_native<T>(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: T)
where
    CodeAssembler: CodeAsmCmp<AsmMemoryOperand, T>,
{
    // cmp [...], ...
    rt.asm
        .cmp(qword_ptr(base + rt.mapper.index(dst) as i32 * 8), src)
        .unwrap();
}

pub fn imul_with_virtual<T>(rt: &mut Runtime, base: AsmRegister64, dst: T, src: VMReg)
where
    CodeAssembler: CodeAsmImul2<T, AsmMemoryOperand>,
{
    // imul ..., [...]
    rt.asm
        .imul_2(dst, ptr(base + rt.mapper.index(src) as i32 * 8))
        .unwrap();
}

pub fn push(rt: &mut Runtime, base: AsmRegister64, dst: VMReg) {
    // push [...]
    rt.asm
        .push(qword_ptr(base + rt.mapper.index(dst) as i32 * 8))
        .unwrap();
}

pub fn pop(rt: &mut Runtime, base: AsmRegister64, dst: VMReg) {
    // pop [...]
    rt.asm
        .pop(qword_ptr(base + rt.mapper.index(dst) as i32 * 8))
        .unwrap();
}

use crate::{runtime::Runtime, vm::bytecode::VMVec};
use iced_x86::code_asm::{ptr, AsmRegister64, AsmRegisterXmm, AsmRegisterYmm};

pub fn load_128(rt: &mut Runtime, base: AsmRegister64, src: VMVec, dst: AsmRegisterXmm) {
    rt.asm
        .movups(dst, ptr(base + rt.mapper.index(src) as i32 * 32))
        .unwrap();
}

pub fn store_128(rt: &mut Runtime, base: AsmRegister64, src: AsmRegisterXmm, dst: VMVec) {
    rt.asm
        .movups(ptr(base + rt.mapper.index(dst) as i32 * 32), src)
        .unwrap();
}

pub fn load_256(rt: &mut Runtime, base: AsmRegister64, src: VMVec, dst: AsmRegisterYmm) {
    rt.asm
        .vmovups(dst, ptr(base + rt.mapper.index(src) as i32 * 32))
        .unwrap();
}

pub fn store_256(rt: &mut Runtime, base: AsmRegister64, src: AsmRegisterYmm, dst: VMVec) {
    rt.asm
        .vmovups(ptr(base + rt.mapper.index(dst) as i32 * 32), src)
        .unwrap();
}

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils::register},
};
use iced_x86::code_asm::{ptr, r10, AsmRegister32, AsmRegister64, AsmRegisterXmm, AsmRegisterYmm};

pub fn store(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister64) {
    // sub [...], 0x8
    register::sub_from_virtual(rt, base, VMReg::VScratch, 0x8);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // mov [r10], ...
    rt.asm.mov(ptr(r10), src).unwrap();
}

pub fn load(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegister64) {
    // add [...], 0x8
    register::add_to_virtual(rt, base, VMReg::VScratch, 0x8);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // mov ..., [r10 - 0x8]
    rt.asm.mov(dst, ptr(r10 - 0x8)).unwrap();
}

pub fn load_32(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegister32) {
    // add [...], 0x8
    register::add_to_virtual(rt, base, VMReg::VScratch, 0x8);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // mov ..., [r10 - 0x8]
    rt.asm.mov(dst, ptr(r10 - 0x8)).unwrap();
}

pub fn store_128(rt: &mut Runtime, base: AsmRegister64, src: AsmRegisterXmm) {
    // sub [...], 0x10
    register::sub_from_virtual(rt, base, VMReg::VScratch, 0x10);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // movups [r10], ...
    rt.asm.movups(ptr(r10), src).unwrap();
}

pub fn load_128(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegisterXmm) {
    // add [...], 0x10
    register::add_to_virtual(rt, base, VMReg::VScratch, 0x10);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // movups ..., [r10 - 0x10]
    rt.asm.movups(dst, ptr(r10 - 0x10)).unwrap();
}

pub fn store_256(rt: &mut Runtime, base: AsmRegister64, src: AsmRegisterYmm) {
    // sub [...], 0x20
    register::sub_from_virtual(rt, base, VMReg::VScratch, 0x20);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // vmovups [r10], ...
    rt.asm.vmovups(ptr(r10), src).unwrap();
}

pub fn load_256(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegisterYmm) {
    // add [...], 0x20
    register::add_to_virtual(rt, base, VMReg::VScratch, 0x20);
    // mov r10, [...]
    register::load(rt, base, r10, VMReg::VScratch);
    // vmovups ..., [r10 - 0x20]
    rt.asm.vmovups(dst, ptr(r10 - 0x20)).unwrap();
}

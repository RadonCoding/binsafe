use iced_x86::code_asm::{ptr, AsmRegister64};

use crate::{runtime::Runtime, vm::bytecode::VMReg};

pub mod compute_effective_address;

pub fn load_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(src + (from as u8 - 1) * 8)).unwrap();
}

pub fn store_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // mov [...], ...
    rt.asm.mov(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn add_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // add [...], ...
    rt.asm.add(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn sub_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // sub [...], ...
    rt.asm.sub(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn sub_vreg_imm_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: u64,
    to: VMReg,
) {
    // mov ..., ...
    rt.asm.mov(with, from).unwrap();
    // sub [...], ...
    rt.asm.sub(ptr(src + (to as u8 - 1) * 8), with).unwrap();
}

pub fn store_vmreg_memory_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: AsmRegister64,
    to: VMReg,
) {
    // mov ..., [...]
    rt.asm.mov(with, ptr(src + (to as u8 - 1) * 8)).unwrap();
    // mov [...], ...
    rt.asm.mov(ptr(with), from).unwrap();
}

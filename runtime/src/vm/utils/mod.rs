use iced_x86::code_asm::{ptr, AsmRegister64};

use crate::{runtime::Runtime, vm::bytecode::VMReg};

pub mod compute_effective_address;

pub fn load_vmreg(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(src + (from as u8 - 1) * 8)).unwrap();
}

pub fn store_vmreg(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // mov [...], ...
    rt.asm.mov(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn add_vmreg(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // add [...], ...
    rt.asm.add(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn store_vmreg_memory(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: AsmRegister64,
    to: VMReg,
) {
    // mov ..., [...]
    rt.asm.mov(with, ptr(src + (to as u8 - 1) * 8)).unwrap();
    // mov [rax], ...
    rt.asm.mov(ptr(with), from).unwrap();
}

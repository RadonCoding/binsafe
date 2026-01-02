pub mod compute_address;

use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{ptr, qword_ptr, AsmRegister32, AsmRegister64};

pub fn mov_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(src + (from as u8 - 1) * 8)).unwrap();
}

pub fn mov_reg_vreg_32(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister32) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(src + (from as u8 - 1) * 8)).unwrap();
}

pub fn mov_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // mov [...], ...
    rt.asm.mov(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn add_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // add [...], ...
    rt.asm.add(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn add_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(qword_ptr(src + (to as u8 - 1) * 8), from)
        .unwrap();
}

pub fn sub_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // sub [...], ...
    rt.asm.sub(ptr(src + (to as u8 - 1) * 8), from).unwrap();
}

pub fn sub_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(qword_ptr(src + (to as u8 - 1) * 8), from)
        .unwrap();
}

pub fn cmp_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, a: VMReg, b: AsmRegister64) {
    // cmp [...], ...
    rt.asm.cmp(ptr(src + (a as u8 - 1) * 8), b).unwrap();
}

pub fn store_vreg_mem_64(
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

pub fn load_reg_mem_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: VMReg,
    to: AsmRegister64,
) {
    // mov ..., [...]
    rt.asm.mov(with, ptr(src + (from as u8 - 1) * 8)).unwrap();
    // mov ..., [...]
    rt.asm.mov(to, ptr(with)).unwrap();
}

pub fn push_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg) {
    // push [...]
    rt.asm.push(qword_ptr(src + (from as u8 - 1) * 8)).unwrap();
}

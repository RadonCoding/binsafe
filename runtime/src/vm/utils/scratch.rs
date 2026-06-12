use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils::vreg},
};
use iced_x86::code_asm::{ptr, r10, AsmRegister64, AsmRegisterXmm, AsmRegisterYmm};

pub fn store(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister64) {
    // sub [...], 0x8
    vreg::sub_imm(rt, base, 0x8, VMReg::VScratch);
    // mov r10, [...]
    vreg::load_reg(rt, base, VMReg::VScratch, r10);
    // mov [r10], ...
    rt.asm.mov(ptr(r10), src).unwrap();
}

pub fn load(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegister64) {
    // add [...], 0x8
    vreg::add_imm(rt, base, 0x8, VMReg::VScratch);
    // mov r10, [...]
    vreg::load_reg(rt, base, VMReg::VScratch, r10);
    // mov ..., [r10 - 0x8]
    rt.asm.mov(dst, ptr(r10 - 0x8)).unwrap();
}

pub fn store_128(rt: &mut Runtime, base: AsmRegister64, src: AsmRegisterXmm) {
    // sub [...], 0x10
    vreg::sub_imm(rt, base, 0x10, VMReg::VScratch);
    // mov r10, [...]
    vreg::load_reg(rt, base, VMReg::VScratch, r10);
    // movups [r10], ...
    rt.asm.movups(ptr(r10), src).unwrap();
}

pub fn load_128(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegisterXmm) {
    // add [...], 0x10
    vreg::add_imm(rt, base, 0x10, VMReg::VScratch);
    // mov r10, [...]
    vreg::load_reg(rt, base, VMReg::VScratch, r10);
    // movups ..., [r10 - 0x10]
    rt.asm.movups(dst, ptr(r10 - 0x10)).unwrap();
}

pub fn store_256(rt: &mut Runtime, base: AsmRegister64, src: AsmRegisterYmm) {
    // sub [...], 0x20
    vreg::sub_imm(rt, base, 0x20, VMReg::VScratch);
    // mov r10, [...]
    vreg::load_reg(rt, base, VMReg::VScratch, r10);
    // vmovups [r10], ...
    rt.asm.vmovups(ptr(r10), src).unwrap();
}

pub fn load_256(rt: &mut Runtime, base: AsmRegister64, dst: AsmRegisterYmm) {
    // add [...], 0x20
    vreg::add_imm(rt, base, 0x20, VMReg::VScratch);
    // mov r10, [...]
    vreg::load_reg(rt, base, VMReg::VScratch, r10);
    // vmovups ..., [r10 - 0x20]
    rt.asm.vmovups(dst, ptr(r10 - 0x20)).unwrap();
}

use iced_x86::code_asm::{ptr, r11, r11d, AsmRegister64};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils::vreg},
};

pub fn store(rt: &mut Runtime, src: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // sub qword [r11 + ...], 0x8
    vreg::sub_imm(rt, r11, 0x8, VMReg::VScratch);
    // mov r11, [r11 + ...]
    vreg::load_reg(rt, r11, VMReg::VScratch, r11);
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
}

pub fn load(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // add qword [r11 + ...], 0x8
    vreg::add_imm(rt, r11, 0x8, VMReg::VScratch);
    // mov r11, [r11 + ...]
    vreg::load_reg(rt, r11, VMReg::VScratch, r11);
    // mov ..., [r11 - 0x8]
    rt.asm.mov(dst, ptr(r11 - 0x8)).unwrap();
}

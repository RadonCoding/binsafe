use iced_x86::code_asm::{r12, rax, rcx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils::vreg},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    // add [...], 0x8
    vreg::add_imm(rt, r12, 0x8, VMReg::VScratch);

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

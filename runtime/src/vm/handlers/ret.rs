use iced_x86::code_asm::{r8, r9, rax, r12, rcx};

use crate::{runtime::Runtime, vm::bytecode::VMReg, vm::utils::vreg};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov r8, [r12 + ...]; mov r9, [r8]
    vreg::load_mem(rt, r12, VMReg::Rsp, r8, r9);
    // mov [r12 + ...], r9
    vreg::store_reg(rt, r12, r9, VMReg::NBranch);
    // add [r12 + ...], 0x8
    vreg::add_imm(rt, r12, 0x8, VMReg::Rsp);

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

use crate::vm::utils;
use iced_x86::code_asm::{eax, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx eax, [rdx]; add rdx, 0x1 -> src
    utils::bytecode::read_byte_zx(rt, rdx, eax);

    // sub [rcx + ...], 0x8
    utils::vreg::sub_imm(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + rax*8]
    rt.asm.mov(r8, ptr(rcx + rax * 8)).unwrap();
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::vreg::store_mem(rt, rcx, rax, r8, VMReg::Rsp);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}

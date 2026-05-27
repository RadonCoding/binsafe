use iced_x86::code_asm::{ptr, r8, r8d, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx r8d, [rdx]; add rdx, 0x1 -> dst
    utils::bytecode::read_byte_zx(rt, rdx, r8d);

    // mov rax, [rcx + ...]; mov rax, [rax]
    utils::vreg::load_mem(rt, rcx, rax, VMReg::Rsp, rax);
    // add [rcx + ...], 0x8
    utils::vreg::add_imm(rt, rcx, 0x8, VMReg::Rsp);
    // mov [rcx + r8*8], rax
    rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}

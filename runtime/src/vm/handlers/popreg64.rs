use iced_x86::code_asm::{byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov rax, [rcx + ...]; mov rax, [rax]
    utils::load_reg_mem_64(rt, rcx, rax, VMReg::Rsp, rax);
    // add [rcx + ...], 0x8
    utils::add_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);

    // mov [rcx + r8*8], rax
    rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}

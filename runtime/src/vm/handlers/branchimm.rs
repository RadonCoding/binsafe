use iced_x86::code_asm::{al, eax, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut skip_ret = rt.asm.create_label();

    // mov al, [rdx]; add rdx, 0x1 -> ret
    utils::bytecode::read_byte(rt, rdx, al);

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [rcx + ...], 0x8
    utils::vreg::sub_imm(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + ...]
    utils::vreg::load_reg(rt, rcx, VMReg::Vex, r8);
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::vreg::store_mem(rt, rcx, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();
    {
        // mov eax, [rdx]; add rdx, 0x4 -> dst
        utils::bytecode::read_dword(rt, rdx, eax);

        // add rax, [rcx + ...]
        utils::vreg::reg_add(rt, rcx, VMReg::Vib, rax);

        // mov [rcx + ...], rax
        utils::vreg::store_reg(rt, rcx, rax, VMReg::Vbr);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // ret
        stack::ret(rt);
    }
}

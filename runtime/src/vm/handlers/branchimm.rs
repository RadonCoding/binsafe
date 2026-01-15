use iced_x86::code_asm::{al, eax, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut skip_ret = rt.asm.create_label();

    // mov al, [rdx] -> ret
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + ...]
    utils::mov_reg_vreg_64(rt, rcx, VMReg::Vex, r8);
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();
    {
        // mov eax, [rdx] -> dst
        rt.asm.mov(eax, ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // add rax, [rcx + ...]
        utils::add_reg_vreg_64(rt, rcx, VMReg::Vib, rax);

        // mov [rcx + ...], rax
        utils::mov_vreg_reg_64(rt, rcx, rax, VMReg::Vbr);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}

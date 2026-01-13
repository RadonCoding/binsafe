use crate::{
    runtime::Runtime,

    vm::{bytecode::VMReg, stack, utils},
};
use iced_x86::code_asm::*;

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut register_loop = rt.asm.create_label();
    let mut is_pop = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);

    // mov r12b, [rdx] -> pop
    rt.asm.mov(r12b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r13, byte [rdx] -> count
    rt.asm.movzx(r13, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    rt.asm.set_label(&mut register_loop).unwrap();
    {
        // test r13, r13
        rt.asm.test(r13, r13).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // movzx r8, byte [rdx]
        rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
        // inc rdx
        rt.asm.inc(rdx).unwrap();

        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jnz ...
        rt.asm.jnz(is_pop).unwrap();

        // sub [rcx + ...], 0x8
        utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
        // mov r9, [rcx + r8*8]
        rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        // mov rax, [rcx + ...]; mov [rax], r9
        utils::store_vreg_mem_64(rt, rcx, rax, r9, VMReg::Rsp);
        // jmp ...
        rt.asm.jmp(continue_loop).unwrap();

        rt.asm.set_label(&mut is_pop).unwrap();
        {
            // mov rax, [rcx + ...]; mov rax, [rax]
            utils::load_reg_mem_64(rt, rcx, rax, VMReg::Rsp, rax);
            // add [rcx + ...], 0x8
            utils::add_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
            // mov [rcx + ...], rax
            rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // dec r13
            rt.asm.dec(r13).unwrap();
            // jmp ...
            rt.asm.jmp(register_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

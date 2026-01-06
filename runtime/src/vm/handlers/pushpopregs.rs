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
    // push r14
    stack::push(rt, r14);

    // mov r12, [rdx] -> seq
    rt.asm.mov(r12, ptr(rdx)).unwrap();
    // add rdx, 0x8
    rt.asm.add(rdx, 0x8).unwrap();

    // mov r13b, [rdx] -> flag
    rt.asm.mov(r13b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r14, 0x8
    rt.asm.mov(r14, 0x8u64).unwrap();

    rt.asm.set_label(&mut register_loop).unwrap();
    {
        // test r14, r14
        rt.asm.test(r14, r14).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // movzx r8, r12b
        rt.asm.movzx(r8, r12b).unwrap();

        // cmp r8, ...
        rt.asm.cmp(r8, rt.mapper.index(VMReg::None) as i32).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();

        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
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
            // mov [rcx + r8*8], rax
            rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // shr r12, 0x8
            rt.asm.shr(r12, 0x8).unwrap();
            // dec r14
            rt.asm.dec(r14).unwrap();
            // jmp ...
            rt.asm.jmp(register_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

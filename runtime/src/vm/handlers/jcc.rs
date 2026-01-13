use crate::vm::stack;
use crate::{
    runtime::Runtime,

    vm::{
        bytecode::{VMLogic, VMReg, VMTest},
        utils,
    },
};
use iced_x86::code_asm::{
    al, byte_ptr, eax, ptr, r12, r12b, r13, r13d, r14, r14b, r8b, r8d, r9b, r9d, rax, rcx, rdx,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();
    let mut condition_loop = rt.asm.create_label();
    let mut check_next = rt.asm.create_label();
    let mut handle_cmp = rt.asm.create_label();
    let mut handle_eq = rt.asm.create_label();
    let mut handle_neq = rt.asm.create_label();
    let mut is_or = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut skip_jump = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r13d, [rcx + ...]
    utils::mov_reg_vreg_32(rt, rcx, VMReg::Flags, r13d);

    // mov al, [rdx] -> logic
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r14b, [rdx] -> number of conditions
    rt.asm.mov(r14b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMLogic::AND) as i32)
        .unwrap();
    // sete r12b
    rt.asm.sete(r12b).unwrap();

    rt.asm.set_label(&mut condition_loop).unwrap();
    {
        // test r14b, r14b
        rt.asm.test(r14b, r14b).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // movzx r8b, [rdx] -> cmp
        rt.asm.mov(r8b, ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // cmp r8b, ...
        rt.asm
            .cmp(r8b, rt.mapper.index(VMTest::CMP) as i32)
            .unwrap();
        // jz ...
        rt.asm.jz(handle_cmp).unwrap();
        // cmp r8b, ...
        rt.asm.cmp(r8b, rt.mapper.index(VMTest::EQ) as i32).unwrap();
        // je ...
        rt.asm.je(handle_eq).unwrap();
        // jmp ...
        rt.asm.jmp(handle_neq).unwrap();

        // Compares the bit in flags specified by the flag bit (lhs) with the set state (rhs)
        rt.asm.set_label(&mut handle_cmp).unwrap();
        {
            // movzx r8d, [rdx] -> lhs
            rt.asm.movzx(r8d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // mov r9b, [rdx] -> rhs
            rt.asm.mov(r9b, ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // bt r13d, r8d
            rt.asm.bt(r13d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // sete r8b
            rt.asm.sete(r8b).unwrap();
            // jmp ...
            rt.asm.jmp(check_next).unwrap();
        }

        // Checks if the bit in flags specified by the first flag bit (lhs) == the bit in flags specified by the second flag bit (rhs)
        rt.asm.set_label(&mut handle_eq).unwrap();
        {
            // movzx r8d, [rdx] -> lhs
            rt.asm.movzx(r8d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // movzx r9d, [rdx] -> rhs
            rt.asm.movzx(r9d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // bt r13d, r8d
            rt.asm.bt(r13d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // bt r13d, r9d
            rt.asm.bt(r13d, r9d).unwrap();
            // setc r9b
            rt.asm.setc(r9b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // sete r8b
            rt.asm.sete(r8b).unwrap();
            // jmp ...
            rt.asm.jmp(check_next).unwrap();
        }

        // Checks if the bit in flags specified by the first flag bit (lhs) != the bit in flags specified by the second flag bit (rhs)
        rt.asm.set_label(&mut handle_neq).unwrap();
        {
            // movzx r8d, [rdx] -> lhs
            rt.asm.movzx(r8d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // movzx r9d, [rdx] -> rhs
            rt.asm.movzx(r9d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // bt r13d, r8d
            rt.asm.bt(r13d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // bt r13d, r9d
            rt.asm.bt(r13d, r9d).unwrap();
            // setc r9b
            rt.asm.setc(r9b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // setne r8b
            rt.asm.setne(r8b).unwrap();
        }

        rt.asm.set_label(&mut check_next).unwrap();
        {
            // cmp al, ...
            rt.asm.cmp(al, rt.mapper.index(VMLogic::OR) as i32).unwrap();
            // je ...
            rt.asm.je(is_or).unwrap();
            // and r12b, r8b
            rt.asm.and(r12b, r8b).unwrap();
            // jmp ...
            rt.asm.jmp(continue_loop).unwrap();
        }

        rt.asm.set_label(&mut is_or).unwrap();
        {
            // or r12b, r8b
            rt.asm.or(r12b, r8b).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // dec r14b
            rt.asm.dec(r14b).unwrap();
            // jmp ...
            rt.asm.jmp(condition_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov eax, [rdx] -> dst
        rt.asm.mov(eax, ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // add rax, [rcx + ...]
        utils::add_reg_vreg_64(rt, rcx, VMReg::VB, rax);

        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jz ...
        rt.asm.jz(skip_jump).unwrap();

        // mov [rcx + ...], rax
        utils::mov_vreg_reg_64(rt, rcx, rax, VMReg::Vip);
    }

    rt.asm.set_label(&mut skip_jump).unwrap();
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

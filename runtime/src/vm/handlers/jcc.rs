use crate::vm::encoders::jcc::{VMLogic, VMTest};
use crate::vm::utils::{self, stack};
use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{
    al, eax, ptr, r12, r12b, r13, r13d, r14, r14d, r8b, r8d, r9b, r9d, rax, rcx, rdx,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut condition_loop = rt.asm.create_label();
    let mut check_next = rt.asm.create_label();
    let mut handle_cmp = rt.asm.create_label();
    let mut handle_eq = rt.asm.create_label();
    let mut handle_neq = rt.asm.create_label();
    let mut is_or = rt.asm.create_label();
    let mut skip_loop = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut check_result = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r13d, [rcx + ...]
    utils::vreg::load_reg32(rt, rcx, VMReg::Flags, r13d);

    // al -> logic
    utils::bytecode::read_byte(rt, rdx, al);

    // r14d -> conditions
    utils::bytecode::read_byte_zx(rt, rdx, r14d);

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMLogic::AND) as i32)
        .unwrap();
    // sete r12b
    rt.asm.sete(r12b).unwrap();

    rt.asm.set_label(&mut condition_loop).unwrap();
    {
        // test r14d, r14d
        rt.asm.test(r14d, r14d).unwrap();
        // jz ...
        rt.asm.jz(check_result).unwrap();

        // r8b -> test
        utils::bytecode::read_byte(rt, rdx, r8b);

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
            // r8d -> lhs
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
            // r9b -> rhs
            utils::bytecode::read_byte(rt, rdx, r9b);

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
            // r8d -> lhs
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
            // r9d -> rhs
            utils::bytecode::read_byte_zx(rt, rdx, r9d);

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
            // r8d -> lhs
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
            // r9d -> rhs
            utils::bytecode::read_byte_zx(rt, rdx, r9d);

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

            // test r8b, r8b
            rt.asm.test(r8b, r8b).unwrap();
            // jz ...
            rt.asm.jz(skip_loop).unwrap();

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
            // dec r14d
            rt.asm.dec(r14d).unwrap();
            // jmp ...
            rt.asm.jmp(condition_loop).unwrap();
        }

        rt.asm.set_label(&mut skip_loop).unwrap();
        {
            // lea r14 [r14 + r14*2]
            rt.asm.lea(r14, ptr(r14 + r14 * 2)).unwrap();
            // lea rdx [rdx + r14+1]
            rt.asm.lea(rdx, ptr(rdx + r14 + 1)).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut check_result).unwrap();
    {
        // eax -> destination
        utils::bytecode::read_dword(rt, rdx, eax);

        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // add rax, [rcx + ...]
        utils::vreg::reg_add(rt, rcx, VMReg::VImage, rax);
        // mov [rcx + ...], rax
        utils::vreg::store_reg(rt, rcx, rax, VMReg::NBranch);
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

use crate::vm::bytecode::{VMLogic, VMTest};
use crate::vm::utils::{self, stack};
use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{
    r12, r12d, r13, r13b, r13d, r14, r14d, r15, r15b, r8, r8b, r8d, r9b, r9d, rax, rcx, rdx,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut condition_loop = rt.asm.create_label();

    let mut handle_cmp = rt.asm.create_label();
    let mut handle_eq = rt.asm.create_label();
    let mut handle_neq = rt.asm.create_label();

    let mut check_continue = rt.asm.create_label();

    let mut is_or = rt.asm.create_label();

    let mut continue_loop = rt.asm.create_label();

    let mut check_result = rt.asm.create_label();
    let mut handle_call = rt.asm.create_label();
    let mut handle_skip = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

    // mov r12d, [rcx + ...]
    utils::vreg::load_reg32(rt, rcx, VMReg::Flags, r12d);

    // r13d -> logic
    utils::bytecode::read_byte_zx(rt, rdx, r13d);

    // r14d -> conditions
    utils::bytecode::read_byte_zx(rt, rdx, r14d);

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::JAND) as i32)
        .unwrap();
    // sete r15b
    rt.asm.sete(r15b).unwrap();
    // je ...
    rt.asm.je(condition_loop).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::CAND) as i32)
        .unwrap();
    // sete r15b
    rt.asm.sete(r15b).unwrap();
    // je ...
    rt.asm.je(condition_loop).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::SAND) as i32)
        .unwrap();
    // sete r15b
    rt.asm.sete(r15b).unwrap();

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

            // bt r12d, r8d
            rt.asm.bt(r12d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // sete r8b
            rt.asm.sete(r8b).unwrap();
            // jmp ...
            rt.asm.jmp(check_continue).unwrap();
        }

        // Checks if the bit in flags specified by the first flag bit (lhs) == the bit in flags specified by the second flag bit (rhs)
        rt.asm.set_label(&mut handle_eq).unwrap();
        {
            // r8d -> lhs
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
            // r9d -> rhs
            utils::bytecode::read_byte_zx(rt, rdx, r9d);

            // bt r12d, r8d
            rt.asm.bt(r12d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // bt r12d, r9d
            rt.asm.bt(r12d, r9d).unwrap();
            // setc r9b
            rt.asm.setc(r9b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // sete r8b
            rt.asm.sete(r8b).unwrap();
            // jmp ...
            rt.asm.jmp(check_continue).unwrap();
        }

        // Checks if the bit in flags specified by the first flag bit (lhs) != the bit in flags specified by the second flag bit (rhs)
        rt.asm.set_label(&mut handle_neq).unwrap();
        {
            // r8d -> lhs
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
            // r9d -> rhs
            utils::bytecode::read_byte_zx(rt, rdx, r9d);

            // bt r12d, r8d
            rt.asm.bt(r12d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // bt r12d, r9d
            rt.asm.bt(r12d, r9d).unwrap();
            // setc r9b
            rt.asm.setc(r9b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // setne r8b
            rt.asm.setne(r8b).unwrap();
        }

        rt.asm.set_label(&mut check_continue).unwrap();
        {
            // cmp r13b, ...
            rt.asm
                .cmp(r13b, rt.mapper.index(VMLogic::JOR) as i32)
                .unwrap();
            // je ...
            rt.asm.je(is_or).unwrap();

            // cmp r13b, ...
            rt.asm
                .cmp(r13b, rt.mapper.index(VMLogic::COR) as i32)
                .unwrap();
            // je ...
            rt.asm.je(is_or).unwrap();

            // cmp r13b, ...
            rt.asm
                .cmp(r13b, rt.mapper.index(VMLogic::SOR) as i32)
                .unwrap();
            // je ...
            rt.asm.je(is_or).unwrap();

            // and r15b, r8b
            rt.asm.and(r15b, r8b).unwrap();
            // jmp ...
            rt.asm.jmp(continue_loop).unwrap();
        }

        rt.asm.set_label(&mut is_or).unwrap();
        {
            // or r15b, r8b
            rt.asm.or(r15b, r8b).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // dec r14d
            rt.asm.dec(r14d).unwrap();
            // jmp ...
            rt.asm.jmp(condition_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut check_result).unwrap();
    {
        // load rax
        utils::scratch::load(rt, rax);

        // test r15b, r15b
        rt.asm.test(r15b, r15b).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMLogic::SAND) as i32)
            .unwrap();
        // je ...
        rt.asm.je(handle_skip).unwrap();

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMLogic::SOR) as i32)
            .unwrap();
        // je ...
        rt.asm.je(handle_skip).unwrap();

        // mov [rcx + ...], rax
        utils::vreg::store_reg(rt, rcx, rax, VMReg::NBranch);

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMLogic::CAND) as i32)
            .unwrap();
        // je ...
        rt.asm.je(handle_call).unwrap();

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMLogic::COR) as i32)
            .unwrap();
        // jne ...
        rt.asm.jne(epilogue).unwrap();
    }

    rt.asm.set_label(&mut handle_call).unwrap();
    {
        // sub [rcx + ...], 0x8
        utils::vreg::sub_imm(rt, rcx, 0x8, VMReg::Rsp);
        // mov r8, [rcx + ...]
        utils::vreg::load_reg(rt, rcx, VMReg::NExit, r8);
        // mov rax, [rcx + ...]; mov [rax], r8
        utils::vreg::store_mem(rt, rcx, VMReg::Rsp, rax, r8);
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut handle_skip).unwrap();
    {
        // add rdx, rax
        rt.asm.add(rdx, rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r15
        stack::pop(rt, r15);
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

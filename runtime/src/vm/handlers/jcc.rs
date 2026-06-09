use crate::vm::bytecode::{VMLogic, VMTest};
use crate::vm::utils::{self};
use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{
    eax, r13, r13b, r13d, r14, r14d, r15, r15b, r8, r8b, r8d, r9b, r9d, rax, rcx, rdx,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut or_loop = rt.asm.create_label();
    let mut or_cmp = rt.asm.create_label();
    let mut or_eq = rt.asm.create_label();
    let mut or_neq = rt.asm.create_label();
    let mut or_fold = rt.asm.create_label();

    let mut and_loop = rt.asm.create_label();
    let mut and_cmp = rt.asm.create_label();
    let mut and_eq = rt.asm.create_label();
    let mut and_neq = rt.asm.create_label();
    let mut and_fold = rt.asm.create_label();

    let mut xor_loop = rt.asm.create_label();
    let mut xor_cmp = rt.asm.create_label();
    let mut xor_eq = rt.asm.create_label();
    let mut xor_neq = rt.asm.create_label();
    let mut xor_fold = rt.asm.create_label();

    let mut check_result = rt.asm.create_label();
    let mut handle_call = rt.asm.create_label();
    let mut handle_skip = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();

    // mov eax, [rcx + ...]
    utils::vreg::load_reg32(rt, rcx, VMReg::Flags, eax);

    // r13d -> logic
    utils::bytecode::read_byte_zx(rt, rdx, r13d);

    // r14d -> conditions
    utils::bytecode::read_byte_zx(rt, rdx, r14d);

    // mov r15b, 0x1
    rt.asm.mov(r15b, 1i32).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::JAND) as i32)
        .unwrap();
    // je ...
    rt.asm.je(and_loop).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::CAND) as i32)
        .unwrap();
    // je ...
    rt.asm.je(and_loop).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::SAND) as i32)
        .unwrap();
    // je ...
    rt.asm.je(and_loop).unwrap();

    // xor r15b, r15b
    rt.asm.xor(r15b, r15b).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::JXOR) as i32)
        .unwrap();
    // je ...
    rt.asm.je(xor_loop).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::CXOR) as i32)
        .unwrap();
    // je ...
    rt.asm.je(xor_loop).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMLogic::SXOR) as i32)
        .unwrap();
    // je ...
    rt.asm.je(xor_loop).unwrap();

    // Iterates through conditions accumulating their results into the accumulator via OR
    rt.asm.set_label(&mut or_loop).unwrap();
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
        rt.asm.jz(or_cmp).unwrap();
        // cmp r8b, ...
        rt.asm.cmp(r8b, rt.mapper.index(VMTest::EQ) as i32).unwrap();
        // je ...
        rt.asm.je(or_eq).unwrap();
        // jmp ...
        rt.asm.jmp(or_neq).unwrap();
    }

    // Compares the bit in flags specified by the flag bit (lhs) with the set state (rhs)
    rt.asm.set_label(&mut or_cmp).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9b -> rhs
        utils::bytecode::read_byte(rt, rdx, r9b);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // sete r8b
        rt.asm.sete(r8b).unwrap();
        // jmp ...
        rt.asm.jmp(or_fold).unwrap();
    }

    // Checks if the bit in flags specified by the first flag bit (lhs) == the bit in flags specified by the second flag bit (rhs)
    rt.asm.set_label(&mut or_eq).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> rhs
        utils::bytecode::read_byte_zx(rt, rdx, r9d);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // bt eax, r9d
        rt.asm.bt(eax, r9d).unwrap();
        // setc r9b
        rt.asm.setc(r9b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // sete r8b
        rt.asm.sete(r8b).unwrap();
        // jmp ...
        rt.asm.jmp(or_fold).unwrap();
    }

    // Checks if the bit in flags specified by the first flag bit (lhs) != the bit in flags specified by the second flag bit (rhs)
    rt.asm.set_label(&mut or_neq).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> rhs
        utils::bytecode::read_byte_zx(rt, rdx, r9d);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // bt eax, r9d
        rt.asm.bt(eax, r9d).unwrap();
        // setc r9b
        rt.asm.setc(r9b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // setne r8b
        rt.asm.setne(r8b).unwrap();
    }

    // Folds the current condition's result into the accumulator via OR and loops back
    rt.asm.set_label(&mut or_fold).unwrap();
    {
        // or r15b, r8b
        rt.asm.or(r15b, r8b).unwrap();
        // dec r14d
        rt.asm.dec(r14d).unwrap();
        // jmp ...
        rt.asm.jmp(or_loop).unwrap();
    }

    // Iterates through conditions accumulating their results into the accumulator via AND
    rt.asm.set_label(&mut and_loop).unwrap();
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
        rt.asm.jz(and_cmp).unwrap();
        // cmp r8b, ...
        rt.asm.cmp(r8b, rt.mapper.index(VMTest::EQ) as i32).unwrap();
        // je ...
        rt.asm.je(and_eq).unwrap();
        // jmp ...
        rt.asm.jmp(and_neq).unwrap();
    }

    // Compares the bit in flags specified by the flag bit (lhs) with the set state (rhs)
    rt.asm.set_label(&mut and_cmp).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9b -> rhs
        utils::bytecode::read_byte(rt, rdx, r9b);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // sete r8b
        rt.asm.sete(r8b).unwrap();
        // jmp ...
        rt.asm.jmp(and_fold).unwrap();
    }

    // Checks if the bit in flags specified by the first flag bit (lhs) == the bit in flags specified by the second flag bit (rhs)
    rt.asm.set_label(&mut and_eq).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> rhs
        utils::bytecode::read_byte_zx(rt, rdx, r9d);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // bt eax, r9d
        rt.asm.bt(eax, r9d).unwrap();
        // setc r9b
        rt.asm.setc(r9b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // sete r8b
        rt.asm.sete(r8b).unwrap();
        // jmp ...
        rt.asm.jmp(and_fold).unwrap();
    }

    // Checks if the bit in flags specified by the first flag bit (lhs) != the bit in flags specified by the second flag bit (rhs)
    rt.asm.set_label(&mut and_neq).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> rhs
        utils::bytecode::read_byte_zx(rt, rdx, r9d);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // bt eax, r9d
        rt.asm.bt(eax, r9d).unwrap();
        // setc r9b
        rt.asm.setc(r9b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // setne r8b
        rt.asm.setne(r8b).unwrap();
    }

    // Folds the current condition's result into the accumulator via AND and loops back
    rt.asm.set_label(&mut and_fold).unwrap();
    {
        // and r15b, r8b
        rt.asm.and(r15b, r8b).unwrap();
        // dec r14d
        rt.asm.dec(r14d).unwrap();
        // jmp ...
        rt.asm.jmp(and_loop).unwrap();
    }

    // Iterates through conditions accumulating their results into the accumulator via XOR
    rt.asm.set_label(&mut xor_loop).unwrap();
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
        rt.asm.jz(xor_cmp).unwrap();
        // cmp r8b, ...
        rt.asm.cmp(r8b, rt.mapper.index(VMTest::EQ) as i32).unwrap();
        // je ...
        rt.asm.je(xor_eq).unwrap();
        // jmp ...
        rt.asm.jmp(xor_neq).unwrap();
    }

    // Compares the bit in flags specified by the flag bit (lhs) with the set state (rhs)
    rt.asm.set_label(&mut xor_cmp).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9b -> rhs
        utils::bytecode::read_byte(rt, rdx, r9b);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // sete r8b
        rt.asm.sete(r8b).unwrap();
        // jmp ...
        rt.asm.jmp(xor_fold).unwrap();
    }

    // Checks if the bit in flags specified by the first flag bit (lhs) == the bit in flags specified by the second flag bit (rhs)
    rt.asm.set_label(&mut xor_eq).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> rhs
        utils::bytecode::read_byte_zx(rt, rdx, r9d);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // bt eax, r9d
        rt.asm.bt(eax, r9d).unwrap();
        // setc r9b
        rt.asm.setc(r9b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // sete r8b
        rt.asm.sete(r8b).unwrap();
        // jmp ...
        rt.asm.jmp(xor_fold).unwrap();
    }

    // Checks if the bit in flags specified by the first flag bit (lhs) != the bit in flags specified by the second flag bit (rhs)
    rt.asm.set_label(&mut xor_neq).unwrap();
    {
        // r8d -> lhs
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> rhs
        utils::bytecode::read_byte_zx(rt, rdx, r9d);

        // bt eax, r8d
        rt.asm.bt(eax, r8d).unwrap();
        // setc r8b
        rt.asm.setc(r8b).unwrap();
        // bt eax, r9d
        rt.asm.bt(eax, r9d).unwrap();
        // setc r9b
        rt.asm.setc(r9b).unwrap();
        // cmp r8b, r9b
        rt.asm.cmp(r8b, r9b).unwrap();
        // setne r8b
        rt.asm.setne(r8b).unwrap();
    }

    // Folds the current condition's result into the accumulator via XOR and loops back
    rt.asm.set_label(&mut xor_fold).unwrap();
    {
        // xor r15b, r8b
        rt.asm.xor(r15b, r8b).unwrap();
        // dec r14d
        rt.asm.dec(r14d).unwrap();
        // jmp ...
        rt.asm.jmp(xor_loop).unwrap();
    }

    rt.asm.set_label(&mut check_result).unwrap();
    {
        // load rax
        utils::scratch::load(rt, rcx, rax);

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

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMLogic::SXOR) as i32)
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
        // je ...
        rt.asm.je(handle_call).unwrap();

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMLogic::CXOR) as i32)
            .unwrap();
        // je ...
        rt.asm.je(handle_call).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
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
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

use iced_x86::code_asm::{ptr, r12, r13, r14, r15, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

pub fn build(rt: &mut Runtime) {
    let mut initialized = rt.asm.create_label();

    let mut execute_loop = rt.asm.create_label();
    let mut execute_entry = rt.asm.create_label();

    let mut epilogue = rt.asm.create_label();

    // push rbx
    rt.asm.push(rbx).unwrap();
    // push rbp
    rt.asm.push(rbp).unwrap();
    // push rsi
    rt.asm.push(rsi).unwrap();
    // push rdi
    rt.asm.push(rdi).unwrap();
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();

    // mov r14, rcx
    rt.asm.mov(r14, rcx).unwrap();
    // mov r15, rdx
    rt.asm.mov(r15, rdx).unwrap();

    // mov r13, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VShadow, r13);
    // test r13, r13
    rt.asm.test(r13, r13).unwrap();
    // jnz ...
    rt.asm.jnz(initialized).unwrap();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmContextCreate])
        .unwrap();
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // mov [r12 + ...], r13
    utils::vreg::store_reg(rt, r12, r13, VMReg::VShadow);

    rt.asm.set_label(&mut initialized).unwrap();

    // mov r12, r13
    rt.asm.mov(r12, r13).unwrap();

    // mov [r12 + ...], r12
    utils::vreg::store_reg(rt, r12, r12, VMReg::R12);

    // mov [r12 + ...], r14
    utils::vreg::store_reg(rt, r12, r14, VMReg::BPointer);
    // mov [r12 + ...], r15
    utils::vreg::store_reg(rt, r12, r15, VMReg::Vg0);

    // lea rax, [...]
    rt.asm.lea(rax, ptr(execute_entry)).unwrap();
    // mov [r12 + ...], rax
    utils::vreg::store_reg(rt, r12, rax, VMReg::NExit);

    // mov [r12 + ...], rsp
    utils::vreg::store_reg(rt, r12, rsp, VMReg::Rsp);
    // mov rsp, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VStack, rsp);

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmDispatch]).unwrap();

        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // jne ...
        rt.asm.jne(rt.function_labels[&FnDef::VmExit]).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();

        rt.asm.set_label(&mut execute_entry).unwrap();
        {
            // call ...
            rt.asm
                .call(rt.function_labels[&FnDef::VmRegistersCaptureVolatile])
                .unwrap();
            // mov [r12 + ...], rsp
            utils::vreg::store_reg(rt, r12, rsp, VMReg::Rsp);
            // mov rsp, [r12 + ...]
            utils::vreg::load_reg(rt, r12, VMReg::VStack, rsp);
        }

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rsp, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::Rsp, rsp);

        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::Vg0, rax);

        // pop r15
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();
        // pop rdi
        rt.asm.pop(rdi).unwrap();
        // pop rsi
        rt.asm.pop(rsi).unwrap();
        // pop rbp
        rt.asm.pop(rbp).unwrap();
        // pop rbx
        rt.asm.pop(rbx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

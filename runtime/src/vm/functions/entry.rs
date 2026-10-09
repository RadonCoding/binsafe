use iced_x86::code_asm::{ptr, r12, r12b, r12d, rax, rcx, rdx, rsp};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self, lock},
    },
};

#[cfg(feature = "profile")]
use crate::debug::{start_profiling, stop_profiling};

pub fn build(rt: &mut Runtime) {
    let mut acquire_global = rt.asm.create_label();

    let mut invoke_ginit = rt.asm.create_label();
    let mut invoke_tinit = rt.asm.create_label();

    let mut initialize_state = rt.asm.create_label();
    let mut initialize_execution = rt.asm.create_label();

    // pushfq
    rt.asm.pushfq().unwrap();
    // push r12
    rt.asm.push(r12).unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // test r12, r12
    rt.asm.test(r12, r12).unwrap();
    // jz ...
    rt.asm.jz(acquire_global).unwrap();

    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();
    // test r12, r12
    rt.asm.test(r12, r12).unwrap();
    // jnz ...
    rt.asm.jnz(initialize_state).unwrap();

    lock::acquire_global(rt, r12b, Some(&mut acquire_global));

    // lea r12, [...]
    rt.asm
        .lea(r12, ptr(rt.data_labels[&DataDef::VmGlobalRegisters]))
        .unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmRegistersCapture])
        .unwrap();
    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmGlobalVectors]))
        .unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVectorsCapture])
        .unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // test r12, r12
    rt.asm.test(r12, r12).unwrap();
    // jz ...
    rt.asm.jz(invoke_ginit).unwrap();
    // jmp ...
    rt.asm.jmp(invoke_tinit).unwrap();

    rt.asm.set_label(&mut invoke_ginit).unwrap();
    {
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmGInit]).unwrap();
    }

    rt.asm.set_label(&mut invoke_tinit).unwrap();
    {
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmTInit]).unwrap();
    }

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmGlobalRegisters]))
        .unwrap();
    // mov rdx, r12
    rt.asm.mov(rdx, r12).unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmRegistersCopy])
        .unwrap();

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmGlobalVectors]))
        .unwrap();
    // mov rdx, [r12 + ...]
    utils::register::load(rt, r12, rdx, VMReg::VVector);
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVectorsCopy])
        .unwrap();

    lock::release_global(rt);

    rt.asm.jmp(initialize_execution).unwrap();

    rt.asm.set_label(&mut initialize_state).unwrap();
    {
        // call ...
        rt.asm
            .call(rt.function_labels[&FnDef::VmRegistersCapture])
            .unwrap();

        // mov rcx, [...]
        utils::register::load(rt, r12, rcx, VMReg::VVector);
        // call ...
        rt.asm
            .call(rt.function_labels[&FnDef::VmVectorsCapture])
            .unwrap();
    }

    rt.asm.set_label(&mut initialize_execution).unwrap();
    {
        // pop rax
        rt.asm.pop(rax).unwrap();
        // mov [r12 + ...], rax
        utils::register::store(rt, r12, VMReg::R12, rax);

        // pop rax
        rt.asm.pop(rax).unwrap();
        // mov [r12 + ...], rax
        utils::register::store(rt, r12, VMReg::Flags, rax);

        // Pop the return address from the stack:
        // pop rcx
        rt.asm.pop(rcx).unwrap();

        // Pop the VM-table index from the stack:
        // pop rdx
        rt.asm.pop(rdx).unwrap();

        // Resolve the VM-table entry into the block pointer:
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmLookup]).unwrap();
        // mov [r12 + ...], rax
        utils::register::store(rt, r12, VMReg::BPointer, rax);

        // Stack now points to where it was before the caller stub:
        // mov [r12 + ...], rsp
        utils::register::store(rt, r12, VMReg::Rsp, rsp);

        // mov rsp, [r12 + ...]
        utils::register::load(rt, r12, rsp, VMReg::VStack);
    }

    #[cfg(feature = "profile")]
    start_profiling(rt);

    // call ...
    rt.asm.call(rt.function_labels[&FnDef::VmDispatch]).unwrap();

    #[cfg(feature = "profile")]
    stop_profiling(rt, FnDef::VmDispatch, "dispatch");

    // jmp ...
    rt.asm.jmp(rt.function_labels[&FnDef::VmExit]).unwrap();
}

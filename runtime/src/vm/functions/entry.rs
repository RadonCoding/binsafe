use iced_x86::code_asm::{ptr, r12, r12b, r12d, r8, rax, rcx, rdx, rsp};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self, lock, stack},
        REGISTERS_TO_NATIVE,
    },
};

pub fn build(rt: &mut Runtime) {
    let mut acquire_global_lock = rt.asm.create_label();

    let mut invoke_ginit = rt.asm.create_label();
    let mut invoke_tinit = rt.asm.create_label();

    let mut continue_attestation = rt.asm.create_label();
    let mut finish_attestation = rt.asm.create_label();

    let mut initialize_state = rt.asm.create_label();
    let mut initialize_execution = rt.asm.create_label();

    let mut copy_native_registers = rt.asm.create_label();

    // pushfq
    rt.asm.pushfq().unwrap();
    // push r12
    rt.asm.push(r12).unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // test r12d, r12d
    rt.asm.test(r12d, r12d).unwrap();
    // jz ...
    rt.asm.jz(acquire_global_lock).unwrap();

    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();
    // test r12, r12
    rt.asm.test(r12, r12).unwrap();
    // jz ...
    rt.asm.jz(acquire_global_lock).unwrap();

    // cmp [r12 + ...], 0x0
    utils::vreg::cmp_imm(rt, r12, VMReg::VAtt, 0x0);
    // jne ...
    rt.asm.jne(initialize_state).unwrap();

    // cmp [r12 + ...], 0x0
    utils::vreg::cmp_imm(rt, r12, VMReg::BPointer, 0x0);
    // je ...
    rt.asm.je(initialize_state).unwrap();

    // jmp ...
    rt.asm.jmp(continue_attestation).unwrap();

    lock::acquire_global(rt, r12b, Some(&mut acquire_global_lock));

    // lea r12, [...]
    rt.asm
        .lea(r12, ptr(rt.data_labels[&DataDef::VmGlobalRegisters]))
        .unwrap();
    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmRegistersCapture])
        .unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // test r12d, r12d
    rt.asm.test(r12d, r12d).unwrap();
    // jz ...
    rt.asm.jz(invoke_ginit).unwrap();
    // jmp ...
    rt.asm.jmp(invoke_tinit).unwrap();

    rt.asm.set_label(&mut invoke_ginit).unwrap();
    {
        rt.asm.call(rt.func_labels[&FnDef::VmGInit]).unwrap();
    }

    rt.asm.set_label(&mut invoke_tinit).unwrap();
    {
        rt.asm.call(rt.func_labels[&FnDef::VmTInit]).unwrap();
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
    rt.asm.call(copy_native_registers).unwrap();

    // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
    // mov rax, [rax + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(rax, ptr(rax + 0x10)).unwrap();
    // mov [r12 + ...], rax
    utils::vreg::store_reg(rt, r12, rax, VMReg::VImage);

    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmVehInitialize])
        .unwrap();
    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmFunctionsInitialize])
        .unwrap();
    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmHandlersInitialize])
        .unwrap();
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.func_labels[&FnDef::VmEntry]))
        .unwrap();
    // mov [r12 + ...], rax
    utils::vreg::store_reg(rt, r12, rax, VMReg::NExit);
    // mov [r12 + ...], rsp
    utils::vreg::store_reg(rt, r12, rsp, VMReg::Rsp);

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

    // cmp [r12 + ...], 0x0
    utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
    // je ...
    rt.asm.je(finish_attestation).unwrap();
    // jmp ...
    rt.asm.jmp(rt.func_labels[&FnDef::VmExit]).unwrap();

    rt.asm.set_label(&mut continue_attestation).unwrap();
    {
        // call ...
        rt.asm
            .call(rt.func_labels[&FnDef::VmRegistersCapture])
            .unwrap();
        // call ...
        rt.asm
            .call(rt.func_labels[&FnDef::VmVectorsCapture])
            .unwrap();
        // Skip the pushes from prologue:
        // add rsp, 0x10
        rt.asm.add(rsp, 0x10i32).unwrap();
        // mov [r12 + ...], rsp
        utils::vreg::store_reg(rt, r12, rsp, VMReg::Rsp);

        // Set the block pointer past the padding, length word, and lock byte:
        // mov rdx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, rdx);
        // mov rcx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BLength, rcx);
        // add rcx, 0x7
        rt.asm.add(rcx, 0x7i32).unwrap();
        // and rcx, -0x8
        rt.asm.and(rcx, -0x8i32).unwrap();
        // add rdx, rcx
        rt.asm.add(rdx, rcx).unwrap();
        // add rdx, 0x3
        rt.asm.add(rdx, 0x3i32).unwrap();

        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // je ...
        rt.asm.je(finish_attestation).unwrap();

        // jmp ...
        rt.asm.jmp(rt.func_labels[&FnDef::VmExit]).unwrap();
    }

    rt.asm.set_label(&mut finish_attestation).unwrap();
    {
        lock::release_global(rt);

        // mov rsp, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::Rsp, rsp);

        // jmp ...
        rt.asm.jmp(initialize_execution).unwrap();
    }

    rt.asm.set_label(&mut initialize_state).unwrap();
    {
        // call ...
        rt.asm
            .call(rt.func_labels[&FnDef::VmRegistersCapture])
            .unwrap();
        // call ...
        rt.asm
            .call(rt.func_labels[&FnDef::VmVectorsCapture])
            .unwrap();
    }

    rt.asm.set_label(&mut initialize_execution).unwrap();
    {
        // pop rax
        rt.asm.pop(rax).unwrap();
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::R12);

        // pop rax
        rt.asm.pop(rax).unwrap();
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::Flags);

        // Pop the return address from the stack:
        // pop rdx
        rt.asm.pop(rdx).unwrap();

        // Pop the VM-table index from the stack:
        // pop r8
        rt.asm.pop(r8).unwrap();

        // Resolve the VM-table entry into the block pointer:
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmLookup]);
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();

        // Stack now points to where it was before the caller stub:
        // mov [r12 + ...], rsp
        utils::vreg::store_reg(rt, r12, rsp, VMReg::Rsp);
    }

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

    // jmp ...
    rt.asm.jmp(rt.func_labels[&FnDef::VmExit]).unwrap();

    rt.asm.set_label(&mut copy_native_registers).unwrap();
    {
        for &(reg, _) in REGISTERS_TO_NATIVE {
            // mov rax, [rcx + ...]
            utils::vreg::load_reg(rt, rcx, reg, rax);
            // mov [rdx + ...], rax
            utils::vreg::store_reg(rt, rdx, rax, reg);
        }
        // ret
        rt.asm.ret().unwrap();
    }
}

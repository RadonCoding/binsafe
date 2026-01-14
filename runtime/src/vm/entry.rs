use iced_x86::code_asm::{byte_ptr, ecx, ptr, r12, r12b, r12d, rax, rcx, rdi, rdx, rsi, rsp};

use crate::{
    mapper::Mappable as _,
    runtime::{BoolDef, DataDef, FnDef, Runtime, StringDef},
    vm::{bytecode::VMReg, stack, utils, VREG_TO_REG},
};

// void (unsigned int)
pub fn build(rt: &mut Runtime) {
    let mut wait_for_global_lock = rt.asm.create_label();
    let mut save_global_state = rt.asm.create_label();
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
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // test r12d, r12d
    rt.asm.test(r12d, r12d).unwrap();
    // jz ...
    rt.asm.jz(wait_for_global_lock).unwrap();

    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();
    // test r12, r12
    rt.asm.test(r12, r12).unwrap();
    // jz ...
    rt.asm.jz(wait_for_global_lock).unwrap();

    // jmp ...
    rt.asm.jmp(initialize_state).unwrap();

    rt.asm.set_label(&mut wait_for_global_lock).unwrap();
    {
        // mov r12b, 0x1
        rt.asm.mov(r12b, 0x1).unwrap();
        // lock xchg [...], r12b
        rt.asm
            .lock()
            .xchg(ptr(rt.bool_labels[&BoolDef::VmIsLocked]), r12b)
            .unwrap();
        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_global_lock).unwrap();
    }

    rt.asm.set_label(&mut save_global_state).unwrap();
    {
        // lea r12, [...]
        rt.asm
            .lea(r12, ptr(rt.data_labels[&DataDef::VmGlobalState]))
            .unwrap();

        for (vreg, reg) in VREG_TO_REG {
            // mov [r12 + ...], ...
            utils::mov_vreg_reg_64(rt, r12, *reg, *vreg);
        }
    }

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
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
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // lea rsi, [...]
    rt.asm
        .lea(rsi, ptr(rt.data_labels[&DataDef::VmGlobalState]))
        .unwrap();
    // mov rdi, r12
    rt.asm.mov(rdi, r12).unwrap();
    // mov rcx, ...
    rt.asm.mov(rcx, VMReg::COUNT as u64).unwrap();
    // rep movsq
    rt.asm.rep().movsq().unwrap();

    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmVehInitialize])
        .unwrap();

    // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
    // mov rax, [rax + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(rax, ptr(rax + 0x10)).unwrap();
    // mov [r12 + ...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::VB);

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::NtQueryInformationProcess);
    // mov [...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::Vsk);

    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmHandlersInitialize])
        .unwrap();

    // mov [...], 0x0
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmIsLocked]), 0x0)
        .unwrap();

    // jmp ...
    rt.asm.jmp(initialize_execution).unwrap();

    rt.asm.set_label(&mut initialize_state).unwrap();
    {
        // mov r12d, [...]
        rt.asm
            .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
            .unwrap();
        // mov r12, [0x1480 + r12*8]
        rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

        for (vreg, reg) in VREG_TO_REG {
            // mov [r12 + ...], ...
            utils::mov_vreg_reg_64(rt, r12, *reg, *vreg);
        }
    }

    rt.asm.set_label(&mut initialize_execution).unwrap();
    {
        // pop rcx -> r12
        rt.asm.pop(rcx).unwrap();
        // mov [r12 + ...], ...
        utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::R12);

        // pop rcx -> flags
        rt.asm.pop(rcx).unwrap();
        // mov [r12 + ...], rcx
        utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::Flags);

        // pop rcx -> ret
        rt.asm.pop(rdx).unwrap();
        // mov [r12 + ...], rcx
        utils::mov_vreg_reg_64(rt, r12, rdx, VMReg::Vra);
        // mov [r12 + ...], rcx
        utils::mov_vreg_reg_64(rt, r12, rdx, VMReg::Vea);

        // sub rdx, [...]
        utils::sub_reg_vreg_64(rt, r12, VMReg::VB, rdx);

        // pop rcx -> index
        rt.asm.pop(rcx).unwrap();
        // xor rcx, rdx
        rt.asm.xor(rcx, rdx).unwrap();
        // and ecx, 0x0FFFFFFF
        rt.asm.and(ecx, 0x0FFFFFFF).unwrap();
        // lea rdx, [...]
        rt.asm
            .lea(rdx, ptr(rt.data_labels[&DataDef::VmTable]))
            .unwrap();

        // lea rdx, [rdx + rcx*8]
        rt.asm.lea(rdx, ptr(rdx + rcx * 8)).unwrap();

        // mov ecx, [rdx] -> displ
        rt.asm.mov(ecx, ptr(rdx)).unwrap();
        // sub [r12 + ...], rcx
        utils::sub_vreg_reg_64(rt, r12, rcx, VMReg::Vea);
        // add [r12 + ...], rcx
        utils::add_vreg_reg_64(rt, r12, rcx, VMReg::Vra);

        // mov ecx, [rdx + 0x4] -> offset
        rt.asm.mov(ecx, ptr(rdx + 0x4)).unwrap();

        // lea rdx, [...]
        rt.asm
            .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
            .unwrap();
        // add rdx, rcx
        rt.asm.add(rdx, rcx).unwrap();

        // mov [r12 + ...], rsp
        utils::mov_vreg_reg_64(rt, r12, rsp, VMReg::Rsp);
    }

    #[cfg(debug_assertions)]
    utils::start_profiling(rt, "VmDispatch");

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

    // jmp ...
    rt.asm.jmp(rt.func_labels[&FnDef::VmExit]).unwrap();
}

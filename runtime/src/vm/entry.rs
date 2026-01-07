use iced_x86::code_asm::{ecx, ptr, r12, r12b, r8d, rcx, rdx, rsp};

use crate::{
    runtime::{BoolDef, DataDef, FnDef, Runtime},
    vm::{bytecode::VMReg, stack, utils, VREG_TO_REG},
};

// void (unsigned int)
pub fn build(rt: &mut Runtime) {
    let mut wait_for_lock = rt.asm.create_label();
    let mut initialize_key = rt.asm.create_label();
    let mut decrypt_entry = rt.asm.create_label();

    // pushfq
    rt.asm.pushfq().unwrap();
    // push r12
    rt.asm.push(r12).unwrap();

    rt.asm.set_label(&mut wait_for_lock).unwrap();
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
        rt.asm.jnz(wait_for_lock).unwrap();
    }

    // lea r12, [...]
    rt.asm
        .lea(r12, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov [r12 + ...], ...
        utils::mov_vreg_reg_64(rt, r12, *reg, *vreg);
    }

    // pop rcx -> r12
    rt.asm.pop(rcx).unwrap();
    // mov [r12 + ...], ...
    utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::R12);

    // pop rcx -> flags
    rt.asm.pop(rcx).unwrap();
    // mov [r12 + ...], rcx
    utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::Flags);

    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmVehInitialize])
        .unwrap();
    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmStackInitialize])
        .unwrap();

    // pop rcx -> ret
    rt.asm.pop(rcx).unwrap();
    // mov [r12 + ...], rcx
    utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::Vip);
    // mov [r12 + ...], rcx
    utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::Veh);

    // mov rdx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rdx, ptr(0x60).gs()).unwrap();
    // mov rdx, [rdx + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(rdx, ptr(rdx + 0x10)).unwrap();
    // mov [r12 + ...], rcx
    utils::mov_vreg_reg_64(rt, r12, rdx, VMReg::VB);

    // sub rcx, rdx
    rt.asm.sub(rcx, rdx).unwrap();
    // mov rdx, rcx
    rt.asm.mov(rdx, rcx).unwrap();

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

    // test ecx, ecx
    rt.asm.test(ecx, ecx).unwrap();
    // jne ...
    rt.asm.jne(initialize_key).unwrap();

    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmKeySeed]))
        .unwrap();
    // jmp ...
    rt.asm.jmp(decrypt_entry).unwrap();

    rt.asm.set_label(&mut initialize_key).unwrap();
    {
        // mov r8d, [rdx - 0x4]
        rt.asm.mov(r8d, ptr(rdx - 0x4)).unwrap();
    }

    rt.asm.set_label(&mut decrypt_entry).unwrap();
    {
        // mov ecx, [rdx] -> displ
        rt.asm.mov(ecx, ptr(rdx)).unwrap();
        // sub [r12 + ...], rcx
        utils::sub_vreg_reg_64(rt, r12, rcx, VMReg::Veh);
        // add [r12 + ...], rcx
        utils::add_vreg_reg_64(rt, r12, rcx, VMReg::Vip);

        // mov ecx, [rdx + 0x4] -> offset
        rt.asm.mov(ecx, ptr(rdx + 0x4)).unwrap();
        // xor ecx, r8d
        rt.asm.xor(ecx, r8d).unwrap();
    }

    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // add rdx, rcx
    rt.asm.add(rdx, rcx).unwrap();

    // mov [r12 + ...], rsp
    utils::mov_vreg_reg_64(rt, r12, rsp, VMReg::Rsp);

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

    // jmp ...
    rt.asm.jmp(rt.func_labels[&FnDef::VmExit]).unwrap();
}

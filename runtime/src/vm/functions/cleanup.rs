use iced_x86::code_asm::{ptr, r12, r13, r8, r8d, rax, rcx, rdx, rsp};

use crate::{
    runtime::{DataDef, ImportDef, Runtime},
    vm::{bytecode::VMReg, utils},
    VM_SCRATCH_SIZE, VM_STACK_SIZE,
};

pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.resolve(ImportDef::GetProcessHeap);
    // call rax
    rt.asm.call(rax).unwrap();
    // mov r12, rax
    rt.asm.mov(r12, rax).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.resolve(ImportDef::RtlFreeHeap);
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // mov r8, [r8 + ...]
    utils::vreg::load_reg(rt, r8, VMReg::VStack, r8);
    // sub r8, ...
    rt.asm.sub(r8, VM_STACK_SIZE as i32).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // mov r8, [r8 + ...]
    utils::vreg::load_reg(rt, r8, VMReg::VScratch, r8);
    // sub r8, ...
    rt.asm.sub(r8, VM_SCRATCH_SIZE as i32).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

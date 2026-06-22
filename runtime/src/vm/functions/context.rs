use iced_x86::code_asm::{ptr, r12, r13, r14, r8, rax, rcx, rdx, rsp};

use crate::{
    mapper::Mappable,
    runtime::{ImportDef, Runtime},
    vm::{
        bytecode::{VMReg, VMVec},
        utils,
    },
    VM_SCRATCH_SIZE, VM_STACK_SIZE,
};

pub fn create(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x20
    rt.asm.sub(rsp, 0x20).unwrap();

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::GetProcessHeap);
    // call rax
    rt.asm.call(rax).unwrap();
    // mov r12, rax
    rt.asm.mov(r12, rax).unwrap();

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::RtlAllocateHeap);
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, 0x00000008 -> HEAP_ZERO_MEMORY
    rt.asm.mov(rdx, 0x00000008u64).unwrap();
    // mov r8, ...
    rt.asm.mov(r8, (VMReg::COUNT * 8) as u64).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, 0x00000008 -> HEAP_ZERO_MEMORY
    rt.asm.mov(rdx, 0x00000008u64).unwrap();
    // mov r8, ...
    rt.asm.mov(r8, (VMVec::COUNT * 32) as u64).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();
    // mov [r14 + ...], rax
    utils::vreg::store_reg(rt, r14, rax, VMReg::VVector);

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, 0x00000008 -> HEAP_ZERO_MEMORY
    rt.asm.mov(rdx, 0x00000008u64).unwrap();
    // mov r8, ...
    rt.asm.mov(r8, VM_STACK_SIZE).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();
    // add rax, ...
    rt.asm.add(rax, VM_STACK_SIZE as i32).unwrap();
    // mov [r14 + ...], rax
    utils::vreg::store_reg(rt, r14, rax, VMReg::VStack);

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, 0x00000008 -> HEAP_ZERO_MEMORY
    rt.asm.mov(rdx, 0x00000008u64).unwrap();
    // mov r8, ...
    rt.asm.mov(r8, VM_SCRATCH_SIZE).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();
    // add rax, ...
    rt.asm.add(rax, VM_SCRATCH_SIZE as i32).unwrap();
    // mov [r14 + ...], rax
    utils::vreg::store_reg(rt, r14, rax, VMReg::VScratch);

    // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
    // mov rax, [rax + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(rax, ptr(rax + 0x10)).unwrap();
    // mov [r14 + ...], rax
    utils::vreg::store_reg(rt, r14, rax, VMReg::VImage);

    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();

    // add rsp, 0x20
    rt.asm.add(rsp, 0x20).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

pub fn delete(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x20
    rt.asm.sub(rsp, 0x20).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::GetProcessHeap);
    // call rax
    rt.asm.call(rax).unwrap();
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::RtlFreeHeap);
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VStack, r8);
    // sub r8, ...
    rt.asm.sub(r8, VM_STACK_SIZE as i32).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VScratch, r8);
    // sub r8, ...
    rt.asm.sub(r8, VM_SCRATCH_SIZE as i32).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VVector, r8);
    // call r14
    rt.asm.call(r14).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8, r12
    rt.asm.mov(r8, r12).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // add rsp, 0x20
    rt.asm.add(rsp, 0x20).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

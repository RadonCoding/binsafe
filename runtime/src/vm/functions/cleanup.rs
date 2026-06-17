use iced_x86::code_asm::{ptr, qword_ptr, r13, r14, r8, r8d, rax, rcx, rdx, rsp};

use crate::{
    runtime::{DataDef, ImportDef, Runtime},
    vm::{bytecode::VMReg, utils},
    VM_SCRATCH_SIZE, VM_STACK_SIZE,
};

pub fn build(rt: &mut Runtime) {
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

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
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // mov r8, [r8 + ...]
    utils::vreg::load_reg(rt, r8, VMReg::VStack, r8);
    // sub r8, ...
    rt.asm.sub(r8, VM_STACK_SIZE as i32).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // mov r8, [r8 + ...]
    utils::vreg::load_reg(rt, r8, VMReg::VScratch, r8);
    // sub r8, ...
    rt.asm.sub(r8, VM_SCRATCH_SIZE as i32).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // mov r8, [r8 + ...]
    utils::vreg::load_reg(rt, r8, VMReg::VVector, r8);
    // call r14
    rt.asm.call(r14).unwrap();

    #[cfg(debug_assertions)]
    {
        use crate::VM_DEBUG_SIZE;

        // mov rcx, r13
        rt.asm.mov(rcx, r13).unwrap();
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();
        // mov r8d, [...]
        rt.asm
            .mov(r8d, ptr(rt.data_labels[&DataDef::VmDebugTlsIndex]))
            .unwrap();
        // mov r8, gs:[0x1480 + r8*8]
        rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
        // sub r8, ...
        rt.asm.sub(r8, VM_DEBUG_SIZE as i32).unwrap();
        // call r14
        rt.asm.call(r14).unwrap();
    }

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov gs:[0x1480 + r8*8], 0x0
    rt.asm.mov(qword_ptr(0x1480 + r8 * 8).gs(), 0x0).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

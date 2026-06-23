use iced_x86::code_asm::{ecx, ptr, r8, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, ImportDef, Runtime};

pub fn build(rt: &mut Runtime) {
    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmContextCreate])
        .unwrap();

    // mov ecx, [...]
    rt.asm
        .mov(ecx, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov [0x1480 + rcx*8], rax
    rt.asm.mov(ptr(0x1480 + rcx * 8).gs(), rax).unwrap();

    #[cfg(debug_assertions)]
    {
        use iced_x86::code_asm::{r12, r13};

        use crate::VM_DEBUG_SIZE;

        // push r12
        rt.asm.push(r12).unwrap();
        // push r13
        rt.asm.push(r13).unwrap();

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
        rt.asm.mov(r8, VM_DEBUG_SIZE).unwrap();
        // call r13
        rt.asm.call(r13).unwrap();

        // add rax, ...
        rt.asm.add(rax, VM_DEBUG_SIZE as i32).unwrap();

        // mov ecx, [...]
        rt.asm
            .mov(ecx, ptr(rt.data_labels[&DataDef::VmDebugTlsIndex]))
            .unwrap();
        // mov rcx, gs:[0x1480 + rcx*8]
        rt.asm.mov(ptr(0x1480 + rcx * 8).gs(), rax).unwrap();

        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();
    }

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::RtlFlsSetValue);
    // mov ecx, [...]
    rt.asm
        .mov(ecx, ptr(rt.data_labels[&DataDef::VmCleanupFlsIndex]))
        .unwrap();
    // mov rdx, 0x1
    rt.asm.mov(rdx, 0x1u64).unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // ret
    rt.asm.ret().unwrap();
}

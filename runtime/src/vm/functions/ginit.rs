use iced_x86::code_asm::{eax, ptr, r13, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, ImportDef, Runtime};

pub fn build(rt: &mut Runtime) {
    // push r13
    rt.asm.push(r13).unwrap();

    // sub rsp, 0x20
    rt.asm.sub(rsp, 0x20).unwrap();

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::TlsAlloc);
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // call r13
    rt.asm.call(r13).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]), eax)
        .unwrap();

    // call r13
    rt.asm.call(r13).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]), eax)
        .unwrap();

    #[cfg(debug_assertions)]
    {
        // call r13
        rt.asm.call(r13).unwrap();
        // mov [...], eax
        rt.asm
            .mov(ptr(rt.data_labels[&DataDef::VmDebugTlsIndex]), eax)
            .unwrap();
    }

    rt.resolve(ImportDef::RtlFlsAlloc);
    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.function_labels[&FnDef::VmCleanup]))
        .unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCleanupFlsIndex]))
        .unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVehInitialize])
        .unwrap();

    // add rsp, 0x20
    rt.asm.add(rsp, 0x20).unwrap();

    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

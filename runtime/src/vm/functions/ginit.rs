use iced_x86::code_asm::{eax, ptr, qword_ptr, r13, r8, r9, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, ImportDef, Runtime};

pub fn build(rt: &mut Runtime) {
    let mut spin = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();

    // sub rsp, 0x30
    rt.asm.sub(rsp, 0x30).unwrap();

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

    // Spawn the attestation service thread:
    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::CreateThread);
    // xor rcx, rcx
    rt.asm.xor(rcx, rcx).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // lea r8, [...]
    rt.asm
        .lea(r8, ptr(rt.function_labels[&FnDef::VmService]))
        .unwrap();
    // xor r9, r9
    rt.asm.xor(r9, r9).unwrap();
    // mov qword [rsp + 0x20], 0x0
    rt.asm.mov(qword_ptr(rsp + 0x20), 0x0).unwrap();
    // mov qword [rsp + 0x28], 0x0
    rt.asm.mov(qword_ptr(rsp + 0x28), 0x0).unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // Wait for the service to run once:
    rt.asm.set_label(&mut spin).unwrap();
    {
        // cmp qword [...], 0x0
        rt.asm
            .cmp(qword_ptr(rt.data_labels[&DataDef::VmServiceBox]), 0x0)
            .unwrap();
        // pause
        rt.asm.pause().unwrap();
        // je ...
        rt.asm.je(spin).unwrap();
    }

    // add rsp, 0x30
    rt.asm.add(rsp, 0x30).unwrap();

    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

use iced_x86::code_asm::{eax, ptr, r12, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, ImportDef, Runtime};

pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(ImportDef::TlsAlloc);
    // mov r12, rax
    rt.asm.mov(r12, rax).unwrap();

    // call r12
    rt.asm.call(r12).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStateTlsIndex]), eax)
        .unwrap();

    // call r12
    rt.asm.call(r12).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackTlsIndex]), eax)
        .unwrap();

    // call r12
    rt.asm.call(r12).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmCacheTlsIndex]), eax)
        .unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(ImportDef::RtlFlsAlloc);
    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.func_labels[&FnDef::VmCleanup]))
        .unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCleanupFlsIndex]))
        .unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

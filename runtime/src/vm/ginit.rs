use iced_x86::code_asm::{eax, ptr, r12, rax, rsp};

use crate::runtime::{DataDef, Runtime, StringDef};

pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::KERNEL32, StringDef::TlsAlloc);
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

    // // lea rcx, [...]; lea rdx, [...]; call ...
    // rt.get_proc_address(StringDef::Ntdll, StringDef::RtlFlsAlloc);
    // // lea rcx, [...]
    // rt.asm
    //     .lea(rcx, ptr(rt.func_labels[&FnDef::VmCleanup]))
    //     .unwrap();
    // // call rax
    // rt.asm.call(rax).unwrap();
    // // mov [...], eax
    // rt.asm
    //     .mov(ptr(rt.data_labels[&DataDef::VmCleanupFlsIndex]), eax)
    //     .unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

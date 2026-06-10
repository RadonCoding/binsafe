use iced_x86::code_asm::{eax, ptr, r13, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, ImportDef, Runtime};

pub fn build(rt: &mut Runtime) {
    // push r13
    rt.asm.push(r13).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
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

    // lea rcx, [...]; lea rdx, [...]; call ...
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

    // mov r13, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(r13, ptr(0x60).gs()).unwrap();
    // mov r13, [r13 + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(r13, ptr(r13 + 0x10)).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmFunctionsInitialize])
        .unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmHandlersInitialize])
        .unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

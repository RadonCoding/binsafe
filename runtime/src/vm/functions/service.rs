use iced_x86::code_asm::{eax, ptr, r12, r12d, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, Runtime};

// DWORD (LPVOID)
pub fn build(rt: &mut Runtime) {
    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // call ...
    rt.asm.call(rt.function_labels[&FnDef::VmTInit]).unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r12, gs:[0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmAttestationService]))
        .unwrap();
    // movsxd rax, [rcx]
    rt.asm.movsxd(rax, ptr(rcx)).unwrap();
    // add rcx, rax
    rt.asm.add(rcx, rax).unwrap();

    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();

    // call ...
    rt.asm.call(rt.function_labels[&FnDef::VmInvoke]).unwrap();

    // xor eax, eax
    rt.asm.xor(eax, eax).unwrap();
    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

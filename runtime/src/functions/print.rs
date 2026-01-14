use iced_x86::code_asm::{ptr, qword_ptr, r12, r13, r14, r8, r9, rax, rcx, rdx, rsp};

use crate::runtime::{FnDef, Runtime, StringDef};

// void (char*)
pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x68
    rt.asm.sub(rsp, 0x68).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // call ...
    rt.asm.call(rt.func_labels[&FnDef::Strlen]).unwrap();
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::NtWriteFile);
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();

    // mov rcx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rcx, ptr(0x60).gs()).unwrap();
    // mov rcx, [rcx + 0x20] -> RTL_USER_PROCESS_PARAMETERS *PEB->ProcessParameters
    rt.asm.mov(rcx, ptr(rcx + 0x20)).unwrap();
    // mov rcx, [rcx + 0x28] -> HANDLE RTL_USER_PROCESS_PARAMETERS->StandardOutput
    rt.asm.mov(rcx, ptr(rcx + 0x28)).unwrap();

    // xor rdx, rdx -> Event
    rt.asm.xor(rdx, rdx).unwrap();
    // xor r8, r8 -> ApcRoutine
    rt.asm.xor(r8, r8).unwrap();
    // xor r9, r9 -> ApcContext
    rt.asm.xor(r9, r9).unwrap();

    // lea rax, [rsp + 0x50]
    rt.asm.lea(rax, ptr(rsp + 0x50)).unwrap();
    // mov [rax], 0x0
    rt.asm.mov(qword_ptr(rax), 0x0).unwrap();
    // mov [rax + 0x8], 0x0
    rt.asm.mov(qword_ptr(rax + 0x8), 0x0).unwrap();
    // mov [rsp + 0x20], rax -> IoStatusBlock
    rt.asm.mov(ptr(rsp + 0x20), rax).unwrap();

    // mov [rsp + 0x28], r12 -> Buffer
    rt.asm.mov(ptr(rsp + 0x28), r12).unwrap();
    // mov [rsp + 0x30], r13 -> Length
    rt.asm.mov(ptr(rsp + 0x30), r13).unwrap();
    // mov qword [rsp + 0x38], 0x0 -> ByteOffset
    rt.asm.mov(qword_ptr(rsp + 0x38), 0x00).unwrap();
    // mov qword [rsp + 0x40], 0x0 -> Key
    rt.asm.mov(qword_ptr(rsp + 0x40), 0x0).unwrap();
    // call r14
    rt.asm.call(r14).unwrap();

    // add rsp, 0x68
    rt.asm.add(rsp, 0x68).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

use iced_x86::code_asm::{ptr, qword_ptr, r12, r13, r14, r8, r9, rax, rbp, rcx, rdx, rsp};

use crate::{
    runtime::{FnDef, ImportDef, Runtime},
    stack,
};

// void (char*)
pub fn build(rt: &mut Runtime) {
    let mut write = rt.asm.create_label();

    let mut offset = 0;

    stack!(_shadow_space, offset, 32);

    stack!(ntwritefile_io_status_block, offset, 8);
    stack!(ntwritefile_buffer, offset, 8);
    stack!(ntwritefile_length, offset, 8);
    stack!(ntwritefile_byte_offset, offset, 8);
    stack!(ntwritefile_key, offset, 8);

    stack!(io_status_block, offset, 16);

    let stack_size = (offset + 0xF) & !0xF;

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // sub rsp, ...
    rt.asm.sub(rsp, stack_size).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Strlen]).unwrap();
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();
    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::NtWriteFile);
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();
    // mov rcx, gs:[0x60]
    rt.asm.mov(rcx, ptr(0x60).gs()).unwrap();
    // mov rcx, [rcx + 0x20]
    rt.asm.mov(rcx, ptr(rcx + 0x20)).unwrap();
    // mov rcx, [rcx + 0x28]
    rt.asm.mov(rcx, ptr(rcx + 0x28)).unwrap();
    // test rcx, rcx
    rt.asm.test(rcx, rcx).unwrap();
    // jnz ...
    rt.asm.jnz(write).unwrap();
    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::AllocConsole);
    // call rax
    rt.asm.call(rax).unwrap();
    // mov rcx, gs:[0x60]
    rt.asm.mov(rcx, ptr(0x60).gs()).unwrap();
    // mov rcx, [rcx + 0x20]
    rt.asm.mov(rcx, ptr(rcx + 0x20)).unwrap();
    // mov rcx, [rcx + 0x28]
    rt.asm.mov(rcx, ptr(rcx + 0x28)).unwrap();

    rt.asm.set_label(&mut write).unwrap();
    {
        // xor rdx, rdx -> Event
        rt.asm.xor(rdx, rdx).unwrap();
        // xor r8, r8 -> ApcRoutine
        rt.asm.xor(r8, r8).unwrap();
        // xor r9, r9 -> ApcContext
        rt.asm.xor(r9, r9).unwrap();
        // lea rax, [rbp - ...]
        rt.asm.lea(rax, ptr(rbp - io_status_block)).unwrap();
        // mov [rax], 0x0
        rt.asm.mov(qword_ptr(rax), 0x0).unwrap();
        // mov [rax + 0x8], 0x0
        rt.asm.mov(qword_ptr(rax + 0x8), 0x0).unwrap();
        // mov [rsp + ...], rax -> IoStatusBlock
        rt.asm
            .mov(ptr(rsp + ntwritefile_io_status_block), rax)
            .unwrap();
        // mov [rsp + ...], r12 -> Buffer
        rt.asm.mov(ptr(rsp + ntwritefile_buffer), r12).unwrap();
        // mov [rsp + ...], r13 -> Length
        rt.asm.mov(ptr(rsp + ntwritefile_length), r13).unwrap();
        // mov [rsp + ...], 0x0 -> ByteOffset
        rt.asm
            .mov(qword_ptr(rsp + ntwritefile_byte_offset), 0x0)
            .unwrap();
        // mov [rsp + ...], 0x0 -> Key
        rt.asm.mov(qword_ptr(rsp + ntwritefile_key), 0x0).unwrap();
        // call r14
        rt.asm.call(r14).unwrap();
    }

    // mov rsp, rbp
    rt.asm.mov(rsp, rbp).unwrap();
    // pop rbp
    rt.asm.pop(rbp).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();

    // ret
    rt.asm.ret().unwrap();
}

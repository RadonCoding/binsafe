use std::mem;

use crate::{
    runtime::{FnDef, Runtime},
    vm::utils::lock,
};
use iced_x86::code_asm::{ptr, qword_ptr, r10, r11, r8, r9, rax, rcx, rdx, rsp, AsmRegister64};

pub fn print_s(rt:  &mut Runtime, s: &str) {
    // push rax
    rt.asm.push(rax).unwrap();
    // push rcx
    rt.asm.push(rcx).unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();
    // push r8
    rt.asm.push(r8).unwrap();
    // push r9
    rt.asm.push(r9).unwrap();
    // push r10
    rt.asm.push(r10).unwrap();
    // push r11
    rt.asm.push(r11).unwrap();

    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);

    let stack_size = (bytes.len() + 0xF) & !0xF;

    // sub rsp, ...
    rt.asm.sub(rsp, stack_size as i32).unwrap();

    let mut offset = 0;

    for chunk in bytes.chunks(mem::size_of::<u64>()) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);

        let value = u64::from_le_bytes(buf);

        // mov rax, ...
        rt.asm.mov(rax, value).unwrap();
        // mov [rsp + ...], rax
        rt.asm.mov(qword_ptr(rsp + offset), rax).unwrap();

        offset += mem::size_of::<u64>();
    }

    // mov rcx, rsp
    rt.asm.mov(rcx, rsp).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();
    // add rsp, ...
    rt.asm.add(rsp, stack_size as i32).unwrap();

    // pop r11
    rt.asm.pop(r11).unwrap();
    // pop r10
    rt.asm.pop(r10).unwrap();
    // pop r9
    rt.asm.pop(r9).unwrap();
    // pop r8
    rt.asm.pop(r8).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // pop rcx
    rt.asm.pop(rcx).unwrap();
    // pop rax
    rt.asm.pop(rax).unwrap();
}

pub fn print_q(rt:  &mut Runtime, q: AsmRegister64) {
    // push rax
    rt.asm.push(rax).unwrap();
    // push rcx
    rt.asm.push(rcx).unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();
    // push r8
    rt.asm.push(r8).unwrap();
    // push r9
    rt.asm.push(r9).unwrap();
    // push r10
    rt.asm.push(r10).unwrap();
    // push r11
    rt.asm.push(r11).unwrap();

    // mov rax, ...
    rt.asm.mov(rax, q).unwrap();

    // mov rcx, rsp
    rt.asm.mov(rcx, rsp).unwrap();
    // mov rdx, ...
    rt.asm.mov(rdx, rax).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Fmtdec]).unwrap();

    // mov rcx, rsp
    rt.asm.mov(rcx, rsp).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    // pop r11
    rt.asm.pop(r11).unwrap();
    // pop r10
    rt.asm.pop(r10).unwrap();
    // pop r9
    rt.asm.pop(r9).unwrap();
    // pop r8
    rt.asm.pop(r8).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // pop rcx
    rt.asm.pop(rcx).unwrap();
    // pop rax
    rt.asm.pop(rax).unwrap();
}

fn print_thread_prefix(rt:  &mut Runtime) {
    // push rax
    rt.asm.push(rax).unwrap();
    // mov rax, gs:[0x48] -> HANDLE TEB->ClientId->UniqueThread
    rt.asm.mov(rax, ptr(0x48).gs()).unwrap();

    print_s(rt, "Thread ");
    print_q(rt, rax);
    print_s(rt, " | ");

    // pop rax
    rt.asm.pop(rax).unwrap();
}

pub fn start_profiling(rt:  &mut Runtime, message: &str) {
    use iced_x86::code_asm::al;

    // push rax
    rt.asm.push(rax).unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();

    lock::acquire_global(rt, al, None);
    print_thread_prefix(rt);
    print_s(rt, &format!("Starting {}...\n", message));
    lock::release_global(rt);

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // pop rax
    rt.asm.pop(rax).unwrap();
}

pub fn stop_profiling(rt:  &mut Runtime, message: &str) {
    use iced_x86::code_asm::al;

    // push rdx
    rt.asm.push(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // sub rax, rdx
    rt.asm.sub(rax, rdx).unwrap();

    lock::acquire_global(rt, al, None);
    print_thread_prefix(rt);
    print_s(rt, &format!("Cycles for {}: ", message));
    print_q(rt, rax);
    print_s(rt, "\n");
    lock::release_global(rt);

    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
}

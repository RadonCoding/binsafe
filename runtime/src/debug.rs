#![allow(unused)]

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    stack,
    vm::utils::lock,
};
use iced_x86::code_asm::{
    al, byte_ptr, ptr, r10, r10d, r11, r8, r9, rax, rbp, rcx, rdx, rsp, ymm0, ymm1, ymm2, ymm3,
    ymm4, ymm5, AsmMemoryOperand, AsmRegister64,
};

fn preserve(rt: &mut Runtime) {
    // pushfq
    rt.asm.pushfq().unwrap();
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
    // push rbp
    rt.asm.push(rbp).unwrap();
    // sub rsp, 0xC0
    rt.asm.sub(rsp, 0xC0).unwrap();
    // vmovups [rsp], ymm0
    rt.asm.vmovups(ptr(rsp), ymm0).unwrap();
    // vmovups [rsp + 0x20], ymm1
    rt.asm.vmovups(ptr(rsp + 0x20), ymm1).unwrap();
    // vmovups [rsp + 0x40], ymm2
    rt.asm.vmovups(ptr(rsp + 0x40), ymm2).unwrap();
    // vmovups [rsp + 0x60], ymm3
    rt.asm.vmovups(ptr(rsp + 0x60), ymm3).unwrap();
    // vmovups [rsp + 0x80], ymm4
    rt.asm.vmovups(ptr(rsp + 0x80), ymm4).unwrap();
    // vmovups [rsp + 0xA0], ymm5
    rt.asm.vmovups(ptr(rsp + 0xA0), ymm5).unwrap();
}

fn restore(rt: &mut Runtime) {
    // vmovups ymm5, [rsp + 0xA0]
    rt.asm.vmovups(ymm5, ptr(rsp + 0xA0)).unwrap();
    // vmovups ymm4, [rsp + 0x80]
    rt.asm.vmovups(ymm4, ptr(rsp + 0x80)).unwrap();
    // vmovups ymm3, [rsp + 0x60]
    rt.asm.vmovups(ymm3, ptr(rsp + 0x60)).unwrap();
    // vmovups ymm2, [rsp + 0x40]
    rt.asm.vmovups(ymm2, ptr(rsp + 0x40)).unwrap();
    // vmovups ymm1, [rsp + 0x20]
    rt.asm.vmovups(ymm1, ptr(rsp + 0x20)).unwrap();
    // vmovups ymm0, [rsp]
    rt.asm.vmovups(ymm0, ptr(rsp)).unwrap();
    // add rsp, 0xC0
    rt.asm.add(rsp, 0xC0).unwrap();
    // pop rbp
    rt.asm.pop(rbp).unwrap();
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
    // popfq
    rt.asm.popfq().unwrap();
}

fn write_string(rt: &mut Runtime, string: &str, offset: usize) {
    let mut bytes = string.as_bytes().to_vec();

    bytes.push(0);

    let mut cursor = 0;

    for byte in bytes {
        // mov [rsp + ...], rax
        rt.asm
            .mov(byte_ptr(rsp + offset + cursor), byte as i32)
            .unwrap();

        cursor += 1;
    }
}

fn save_register(rt: &mut Runtime, register: AsmRegister64, offset: usize) {
    // mov [rsp + ...], ...
    rt.asm.mov(ptr(rsp + offset), register).unwrap();
}

fn write_register(rt: &mut Runtime, value_offset: usize, string_offset: usize) {
    // mov rdx, [rsp + ...]
    rt.asm.mov(rdx, ptr(rsp + value_offset)).unwrap();
    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + string_offset)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Format]).unwrap();
}

pub fn print(rt: &mut Runtime, message: &str, register: Option<AsmRegister64>) {
    const NEWLINE: &str = "\n";

    preserve(rt);

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // and rsp, -0x10
    rt.asm.and(rsp, -0x10i32).unwrap();

    let mut offset = 0;

    stack!(message_string, offset, message.len() + 1);

    let (register_value, register_string) = if register.is_some() {
        stack!(register_value, offset, 8);
        stack!(register_string, offset, size_of::<u64>() * 2 + 1);
        (register_value, register_string)
    } else {
        (0, 0)
    };

    stack!(newline_string, offset, NEWLINE.len() + 1);

    let stack_size = (offset + 0xF) & !0xF;

    // sub rsp, ...
    rt.asm.sub(rsp, stack_size as i32).unwrap();

    if let Some(register) = register {
        save_register(rt, register, register_value);
    }

    write_string(rt, message, message_string);
    write_string(rt, NEWLINE, newline_string);

    if register.is_some() {
        write_register(rt, register_value, register_string);
    }

    lock::acquire_debug(rt, al, None);

    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + message_string)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    if register.is_some() {
        // lea rcx, [rsp + ...]
        rt.asm.lea(rcx, ptr(rsp + register_string)).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();
    }

    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + newline_string)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    lock::release_debug(rt);

    // mov rsp, rbp
    rt.asm.mov(rsp, rbp).unwrap();
    // pop rbp
    rt.asm.pop(rbp).unwrap();

    restore(rt);
}

pub fn print_thread_message(
    rt: &mut Runtime,
    message: &str,
    variable: Option<AsmRegister64>,
    memory: Option<AsmMemoryOperand>,
) {
    const PIPE: &str = " | ";
    const COLON: &str = ": ";
    const NEWLINE: &str = "\n";

    preserve(rt);

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // and rsp, -0x10
    rt.asm.and(rsp, -0x10i32).unwrap();

    let mut offset = 0;

    stack!(thread_value, offset, 8);
    stack!(thread_string, offset, size_of::<u64>() * 2 + 1);
    stack!(pipe_string, offset, PIPE.len() + 1);
    stack!(message_string, offset, message.len() + 1);
    stack!(colon_string, offset, COLON.len() + 1);
    stack!(newline_string, offset, NEWLINE.len() + 1);

    let (variable_value, variable_string) = if variable.is_some() || memory.is_some() {
        stack!(cycles_value, offset, 8);
        stack!(cycles_string, offset, 16 + 1);
        (cycles_value, cycles_string)
    } else {
        (0, 0)
    };

    let stack_size = (offset + 0xF) & !0xF;

    // sub rsp, ...
    rt.asm.sub(rsp, stack_size as i32).unwrap();

    if let Some(variable) = variable {
        save_register(rt, variable, variable_value);
    } else if let Some(memory) = memory {
        // movzx rax, [...]
        rt.asm.movzx(rax, memory).unwrap_or_else(|_| {
            // mov rax, [...]
            rt.asm.mov(rax, memory).unwrap();
        });
        save_register(rt, rax, variable_value);
    }

    // mov rax, gs:[0x48] -> HANDLE TEB->ClientId->UniqueThread
    rt.asm.mov(rax, ptr(0x48).gs()).unwrap();

    save_register(rt, rax, thread_value);

    write_register(rt, thread_value, thread_string);
    write_string(rt, PIPE, pipe_string);
    write_string(rt, message, message_string);

    if variable.is_some() || memory.is_some() {
        write_string(rt, COLON, colon_string);
        write_register(rt, variable_value, variable_string);
    }

    write_string(rt, NEWLINE, newline_string);

    lock::acquire_debug(rt, al, None);

    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + thread_string)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + pipe_string)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + message_string)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    if variable.is_some() || memory.is_some() {
        // lea rcx, [rsp + ...]
        rt.asm.lea(rcx, ptr(rsp + colon_string)).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

        // lea rcx, [rsp + ...]
        rt.asm.lea(rcx, ptr(rsp + variable_string)).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();
    }

    // lea rcx, [rsp + ...]
    rt.asm.lea(rcx, ptr(rsp + newline_string)).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::Print]).unwrap();

    lock::release_debug(rt);

    // mov rsp, rbp
    rt.asm.mov(rsp, rbp).unwrap();
    // pop rbp
    rt.asm.pop(rbp).unwrap();

    lock::release_debug(rt);

    restore(rt);
}

fn store(rt: &mut Runtime, src: AsmRegister64) {
    // mov r10d, [...]
    rt.asm
        .mov(r10d, ptr(rt.data_labels[&DataDef::VmDebugTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r10 * 8]
    rt.asm.mov(r11, ptr(0x1480 + r10 * 8).gs()).unwrap();
    // sub r11, 0x8
    rt.asm.sub(r11, 0x8).unwrap();
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
    // mov gs:[0x1480 + r10 * 8], r11
    rt.asm.mov(ptr(0x1480 + r10 * 8).gs(), r11).unwrap();
}

fn load(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r10d, [...]
    rt.asm
        .mov(r10d, ptr(rt.data_labels[&DataDef::VmDebugTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r10 * 8]
    rt.asm.mov(r11, ptr(0x1480 + r10 * 8).gs()).unwrap();
    // mov ..., [r11]
    rt.asm.mov(dst, ptr(r11)).unwrap();
    // add r11, 0x8
    rt.asm.add(r11, 0x8).unwrap();
    // mov gs:[0x1480 + r10 * 8], r11
    rt.asm.mov(ptr(0x1480 + r10 * 8).gs(), r11).unwrap();
}

pub fn start_profiling(rt: &mut Runtime, _message: &str) {
    // pushfq
    rt.asm.pushfq().unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // push r10
    rt.asm.push(r10).unwrap();
    // push r11
    rt.asm.push(r11).unwrap();

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rdx, rax
    rt.asm.or(rdx, rax).unwrap();

    store(rt, rdx);

    // pop r11
    rt.asm.pop(r11).unwrap();
    // pop r10
    rt.asm.pop(r10).unwrap();

    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // popfq
    rt.asm.popfq().unwrap();
}

pub fn stop_profiling(rt: &mut Runtime, message: &str) {
    // pushfq
    rt.asm.pushfq().unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // push r10
    rt.asm.push(r10).unwrap();
    // push r11
    rt.asm.push(r11).unwrap();

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rdx, rax
    rt.asm.or(rdx, rax).unwrap();

    load(rt, rax);

    // sub rdx, rax
    rt.asm.sub(rdx, rax).unwrap();

    print_thread_message(rt, &format!("cycles for {}", message), Some(rdx), None);

    // pop r11
    rt.asm.pop(r11).unwrap();
    // pop r10
    rt.asm.pop(r10).unwrap();

    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // popfq
    rt.asm.popfq().unwrap();
}

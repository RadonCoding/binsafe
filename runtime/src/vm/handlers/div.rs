use iced_x86::code_asm::*;

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    // rax -> width
    utils::bytecode::read_byte_zx(rt, r13, eax);

    // load r8
    scratch::load(rt, r12, r8);
    // load r9
    scratch::load(rt, r12, r9);
    // load r14
    scratch::load(rt, r12, r14);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(|rt| wide(rt, false))),
        Some(Box::new(|rt| dword(rt, false))),
        None,
        Some(Box::new(|rt| word(rt, false))),
        None,
        Some(Box::new(|rt| byte(rt, false))),
        Some(Box::new(|rt| wide(rt, true))),
        Some(Box::new(|rt| dword(rt, true))),
        Some(Box::new(|rt| word(rt, true))),
        Some(Box::new(|rt| byte(rt, true))),
        None,
        None,
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r8
        scratch::store(rt, r12, r8);
        // store r9
        scratch::store(rt, r12, r9);

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

fn wide(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    // mov rdx, r8
    rt.asm.mov(rdx, r8).unwrap();
    if signed {
        // rax = rdx:rax / r14, rdx = rdx:rax % r14
        rt.asm.idiv(r14).unwrap();
    } else {
        // rax = rdx:rax / r14, rdx = rdx:rax % r14
        rt.asm.div(r14).unwrap();
    }
    // mov r9, rax
    rt.asm.mov(r9, rax).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
}

fn dword(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    // mov rdx, r8
    rt.asm.mov(rdx, r8).unwrap();
    if signed {
        // eax = edx:eax / r14d, edx = edx:eax % r14d
        rt.asm.idiv(r14d).unwrap();
    } else {
        // eax = edx:eax / r14d, edx = edx:eax % r14d
        rt.asm.div(r14d).unwrap();
    }
    // mov r9, rax
    rt.asm.mov(r9, rax).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
}

fn word(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    // mov rdx, r8
    rt.asm.mov(rdx, r8).unwrap();
    if signed {
        // ax = dx:ax / r14w, dx = dx:ax % r14w
        rt.asm.idiv(r14w).unwrap();
    } else {
        // ax = dx:ax / r14w, dx = dx:ax % r14w
        rt.asm.div(r14w).unwrap();
    }
    // mov r9, rax
    rt.asm.mov(r9, rax).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
}

fn byte(rt: &mut Runtime, signed: bool) {
    // movzx ecx, r8b
    rt.asm.movzx(ecx, r8b).unwrap();
    // shl ecx, 0x8
    rt.asm.shl(ecx, 0x8i32).unwrap();
    // movzx eax, r9b
    rt.asm.movzx(eax, r9b).unwrap();
    // or eax, ecx
    rt.asm.or(eax, ecx).unwrap();
    if signed {
        // al = ax / r14b, ah = ax % r14b
        rt.asm.idiv(r14b).unwrap();
    } else {
        // al = ax / r14b, ah = ax % r14b
        rt.asm.div(r14b).unwrap();
    }
    // movzx ecx, ah
    rt.asm.movzx(ecx, ah).unwrap();
    // movzx r9d, al
    rt.asm.movzx(r9d, al).unwrap();
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
}

use iced_x86::code_asm::*;

use crate::{
    runtime::{FnDef, Runtime},
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // al -> width
    utils::bytecode::read_byte(rt, r13, al);

    // load r8
    scratch::load(rt, rcx, r8);
    // load rt, rcx, r9
    scratch::load(rt, rcx, r9);

    utils::width::dispatch_register(
        rt,
        al,
        &mut epilogue,
        |rt| wide(rt, false),
        |rt| dword(rt, false),
        |rt| word(rt, false),
        |rt| byte(rt, false),
        |rt| byte(rt, false),
        |rt| wide(rt, true),
        |rt| dword(rt, true),
        |rt| word(rt, true),
        |rt| byte(rt, true),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r8
        scratch::store(rt, r12, r8);
        // store r9
        scratch::store(rt, r12, r9);

        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // pushfq
        rt.asm.pushfq().unwrap();
        // call ...
        rt.asm.call(rt.func_labels[&FnDef::VmFlags]).unwrap();

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

fn wide(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    if signed {
        // rdx:rax = rax * r8
        rt.asm.imul(r8).unwrap();
    } else {
        // rdx:rax = rax * r8
        rt.asm.mul(r8).unwrap();
    }
    // mov r9, rax
    rt.asm.mov(r9, rax).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
}

fn dword(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    if signed {
        // edx:eax = eax * r8d
        rt.asm.imul(r8d).unwrap();
    } else {
        // edx:eax = eax * r8d
        rt.asm.mul(r8d).unwrap();
    }
    // mov r9, rax
    rt.asm.mov(r9, rax).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
}

fn word(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    if signed {
        // dx:ax = ax * r8w
        rt.asm.imul(r8w).unwrap();
    } else {
        // dx:ax = ax * r8w
        rt.asm.mul(r8w).unwrap();
    }
    // mov r9, rax
    rt.asm.mov(r9, rax).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
}

fn byte(rt: &mut Runtime, signed: bool) {
    // mov rax, r9
    rt.asm.mov(rax, r9).unwrap();
    if signed {
        // ax = al * r8b
        rt.asm.imul(r8b).unwrap();
    } else {
        // ax = al * r8b
        rt.asm.mul(r8b).unwrap();
    }
    // movzx ecx, ah
    rt.asm.movzx(ecx, ah).unwrap();
    // movzx r9d, al
    rt.asm.movzx(r9d, al).unwrap();
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
}

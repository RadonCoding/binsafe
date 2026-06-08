use iced_x86::code_asm::*;

use crate::{
    runtime::{FnDef, Runtime},
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // al -> width
    utils::bytecode::read_byte(rt, r13, al);

    // load r8
    scratch::load(rt, r8);
    // load r14
    scratch::load(rt, r14);

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
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // pushfq
        stack::pushfq(rt);
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmFlags]);

        // store r15
        scratch::store(rt, r15);
        // store r14
        scratch::store(rt, r14);

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

fn wide(rt: &mut Runtime, signed: bool) {
    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();
    if signed {
        // rdx:rax = rax * r8
        rt.asm.imul(r8).unwrap();
    } else {
        // rdx:rax = rax * r8
        rt.asm.mul(r8).unwrap();
    }
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();
    // mov r15, rdx
    rt.asm.mov(r15, rdx).unwrap();
}

fn dword(rt: &mut Runtime, signed: bool) {
    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();
    if signed {
        // edx:eax = eax * r8d
        rt.asm.imul(r8d).unwrap();
    } else {
        // edx:eax = eax * r8d
        rt.asm.mul(r8d).unwrap();
    }
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();
    // mov r15, rdx
    rt.asm.mov(r15, rdx).unwrap();
}

fn word(rt: &mut Runtime, signed: bool) {
    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();
    if signed {
        // dx:ax = ax * r8w
        rt.asm.imul(r8w).unwrap();
    } else {
        // dx:ax = ax * r8w
        rt.asm.mul(r8w).unwrap();
    }
    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();
    // mov r15, rdx
    rt.asm.mov(r15, rdx).unwrap();
}

fn byte(rt: &mut Runtime, signed: bool) {
    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();
    if signed {
        // ax = al * r8b
        rt.asm.imul(r8b).unwrap();
    } else {
        // ax = al * r8b
        rt.asm.mul(r8b).unwrap();
    }
    // movzx ecx, ah
    rt.asm.movzx(ecx, ah).unwrap();
    // movzx r14d, al
    rt.asm.movzx(r14d, al).unwrap();
    // mov r15, rcx
    rt.asm.mov(r15, rcx).unwrap();
}

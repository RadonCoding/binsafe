use iced_x86::code_asm::*;

use crate::{
    runtime::{FnDef, Runtime},
    vm::{
        bytecode::VMFlag,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    // rax -> width
    utils::bytecode::read_byte_zx(rt, r13, eax);

    // load r8
    scratch::load(rt, r12, r8);
    // load r9
    scratch::load(rt, r12, r9);

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
        // pushfq
        rt.asm.pushfq().unwrap();

        // store r8
        scratch::store(rt, r12, r8);
        // store r9
        scratch::store(rt, r12, r9);

        // mov rcx, ...
        rt.asm
            .mov(
                rcx,
                VMFlag::Carry.bit64()
                    | VMFlag::Parity.bit64()
                    | VMFlag::Auxiliary.bit64()
                    | VMFlag::Zero.bit64()
                    | VMFlag::Sign.bit64()
                    | VMFlag::Overflow.bit64(),
            )
            .unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmFlags]).unwrap();

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
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

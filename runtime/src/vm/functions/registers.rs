use iced_x86::code_asm::{r12, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        utils, REGISTERS_TO_NATIVE, REGISTERS_TO_NATIVE_NONVOLATILE, REGISTERS_TO_NATIVE_VOLATILE,
    },
};

pub fn capture(rt: &mut Runtime) {
    for (dst, src) in REGISTERS_TO_NATIVE {
        // mov [r12 + ...], ...
        utils::register::store(rt, r12, dst, src);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn capture_volatile(rt: &mut Runtime) {
    for &(dst, src) in REGISTERS_TO_NATIVE_VOLATILE {
        // mov [r12 + ...], ...
        utils::register::store(rt, r12, dst, src);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn capture_nonvolatile(rt: &mut Runtime) {
    for &(dst, src) in REGISTERS_TO_NATIVE_NONVOLATILE {
        // mov [r12 + ...], ...
        utils::register::store(rt, r12, dst, src);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn restore(rt: &mut Runtime) {
    for (src, dst) in REGISTERS_TO_NATIVE {
        // mov ..., [r12 + ...]
        utils::register::load(rt, r12, dst, src);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn copy(rt: &mut Runtime) {
    for (reg, _) in REGISTERS_TO_NATIVE {
        // mov rax, [rcx + ...]
        utils::register::load(rt, rcx, rax, reg);
        // mov [rdx + ...], rax
        utils::register::store(rt, rdx, reg, rax);
    }
    // ret
    rt.asm.ret().unwrap();
}

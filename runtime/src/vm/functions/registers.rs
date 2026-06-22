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
        utils::vreg::store_reg(rt, r12, src, dst);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn capture_volatile(rt: &mut Runtime) {
    for &(dst, src) in REGISTERS_TO_NATIVE_VOLATILE {
        utils::vreg::store_reg(rt, r12, src, dst);
    }
    rt.asm.ret().unwrap();
}

pub fn capture_nonvolatile(rt: &mut Runtime) {
    for &(dst, src) in REGISTERS_TO_NATIVE_NONVOLATILE {
        utils::vreg::store_reg(rt, r12, src, dst);
    }
    rt.asm.ret().unwrap();
}

pub fn restore(rt: &mut Runtime) {
    for (src, dst) in REGISTERS_TO_NATIVE {
        // mov ..., [r12 + ...]
        utils::vreg::load_reg(rt, r12, src, dst);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn copy(rt: &mut Runtime) {
    for (reg, _) in REGISTERS_TO_NATIVE {
        // mov rax, [rcx + ...]
        utils::vreg::load_reg(rt, rcx, reg, rax);
        // mov [rdx + ...], rax
        utils::vreg::store_reg(rt, rdx, rax, reg);
    }
    // ret
    rt.asm.ret().unwrap();
}

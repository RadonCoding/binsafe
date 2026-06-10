use iced_x86::code_asm::r12;

use crate::{
    runtime::Runtime,
    vm::{utils, REGISTERS_TO_NATIVE},
};

pub fn capture(rt:  &mut Runtime) {
    for (dst, src) in REGISTERS_TO_NATIVE {
        // mov [r12 + ...], ...
        utils::vreg::store_reg(rt, r12, *src, *dst);
    }
    // ret
    rt.asm.ret().unwrap();
}

pub fn restore(rt:  &mut Runtime) {
    for (src, dst) in REGISTERS_TO_NATIVE {
        // mov ..., [r12 + ...]
        utils::vreg::load_reg(rt, r12, *src, *dst);
    }
    // ret
    rt.asm.ret().unwrap();
}

use iced_x86::code_asm::{ptr, r12, r8, r8b, r8d, r9, r9d, rax, rcx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // r8b -> width
    utils::bytecode::read_byte(rt, rcx, r8b);
    // r9d -> destination
    utils::bytecode::read_byte_zx(rt, rcx, r9d);

    // shl r9, 0x5
    rt.asm.shl(r9, 0x5).unwrap();

    // mov rax, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VVector, rax);

    utils::width::dispatch_scalar(
        rt,
        r8b,
        &mut epilogue,
        |rt| {
            // load r8
            scratch::load(rt, r12, r8);
            // mov [rax + r9], r8d
            rt.asm.mov(ptr(rax + r9), r8d).unwrap();
        },
        |rt| {
            // load r8
            scratch::load(rt, r12, r8);
            // mov [rax + r9], rax
            rt.asm.mov(ptr(rax + r9), r8).unwrap();
        },
        |rt| {
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            // movups [rax + r9], xmm0
            rt.asm.movups(ptr(rax + r9), xmm0).unwrap();
        },
        |rt| {
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            // vmovups [rax + r9], ymm0
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

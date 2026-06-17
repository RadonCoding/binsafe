use iced_x86::code_asm::{ptr, r12, r8, r8d, r9, r9d, rax, rcx, xmm0, ymm0};

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

    // r8d -> width
    utils::bytecode::read_byte_zx(rt, rcx, r8d);
    // r9d -> destination
    utils::bytecode::read_byte_zx(rt, rcx, r9d);

    // shl r9, 0x5
    rt.asm.shl(r9, 0x5).unwrap();

    // mov rax, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VVector, rax);

    utils::width::dispatch(
        rt,
        r8,
        &mut epilogue,
        Some(Box::new(|rt| {
            // load r8
            scratch::load(rt, r12, r8);
            // vpxor ymm0, ymm0, ymm0
            rt.asm.vpxor(xmm0, xmm0, xmm0).unwrap();
            // vmovq xmm0, r8
            rt.asm.vmovq(xmm0, r8).unwrap();
            // vmovups [rax + r9], ymm0
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
        Some(Box::new(|rt| {
            // load r8
            scratch::load(rt, r12, r8);
            // vpxor ymm0, ymm0, ymm0
            rt.asm.vpxor(xmm0, xmm0, xmm0).unwrap();
            // vmovd xmm0, r8d
            rt.asm.vmovd(xmm0, r8d).unwrap();
            // vmovups [rax + r9], ymm0
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            // vmovaps xmm0, xmm0 (VEX encoding zeroes upper 128 bits)
            rt.asm.vmovaps(xmm0, xmm0).unwrap();
            // vmovups [rax + r9], ymm0
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
        Some(Box::new(|rt| {
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            // vmovups [rax + r9], ymm0
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

use crate::{runtime::Runtime, vm::handlers::vector};
use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    vector::with_precision(
        rt,
        |rt| {
            // paddb xmm0, xmm1
            rt.asm.paddb(xmm0, xmm1).unwrap();
        },
        |rt| {
            // paddw xmm0, xmm1
            rt.asm.paddw(xmm0, xmm1).unwrap();
        },
        |rt| {
            // paddd xmm0, xmm1
            rt.asm.paddd(xmm0, xmm1).unwrap();
        },
        |rt| {
            // paddq xmm0, xmm1
            rt.asm.paddq(xmm0, xmm1).unwrap();
        },
        |rt| {
            // addps xmm0, xmm1
            rt.asm.addps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // addps xmm0, xmm1
            rt.asm.addps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // addps xmm0, xmm1
            rt.asm.addps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // addsd xmm0, xmm1
            rt.asm.addsd(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vpaddb ymm0, ymm0, ymm1
            rt.asm.vpaddb(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpaddw ymm0, ymm0, ymm1
            rt.asm.vpaddw(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpaddd ymm0, ymm0, ymm1
            rt.asm.vpaddd(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpaddq ymm0, ymm0, ymm1
            rt.asm.vpaddq(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vaddps ymm0, ymm0, ymm1
            rt.asm.vaddps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vaddps ymm0, ymm0, ymm1
            rt.asm.vaddps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vaddps ymm0, ymm0, ymm1
            rt.asm.vaddps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vaddsd ymm0, ymm0, ymm1
            rt.asm.vaddsd(xmm0, xmm0, xmm1).unwrap();
        },
    );
}

use crate::{runtime::Runtime, vm::handlers::vector};
use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

pub fn build(rt: &mut Runtime) {
    vector::arithmetic(
        rt,
        |rt| {
            // psubb xmm0, xmm1
            rt.asm.psubb(xmm0, xmm1).unwrap();
        },
        |rt| {
            // psubw xmm0, xmm1
            rt.asm.psubw(xmm0, xmm1).unwrap();
        },
        |rt| {
            // psubd xmm0, xmm1
            rt.asm.psubd(xmm0, xmm1).unwrap();
        },
        |rt| {
            // psubq xmm0, xmm1
            rt.asm.psubq(xmm0, xmm1).unwrap();
        },
        |rt| {
            // subps xmm0, xmm1
            rt.asm.subps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // subps xmm0, xmm1
            rt.asm.subps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // subps xmm0, xmm1
            rt.asm.subps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // subsd xmm0, xmm1
            rt.asm.subsd(xmm0, xmm1).unwrap();
        },
        // avx_int
        |rt| {
            // vpsubb ymm0, ymm0, ymm1
            rt.asm.vpsubb(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpsubw ymm0, ymm0, ymm1
            rt.asm.vpsubw(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpsubd ymm0, ymm0, ymm1
            rt.asm.vpsubd(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpsubq ymm0, ymm0, ymm1
            rt.asm.vpsubq(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vsubps ymm0, ymm0, ymm1
            rt.asm.vsubps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vsubps ymm0, ymm0, ymm1
            rt.asm.vsubps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vsubps ymm0, ymm0, ymm1
            rt.asm.vsubps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vsubsd ymm0, ymm0, ymm1
            rt.asm.vsubsd(xmm0, xmm0, xmm1).unwrap();
        },
    );
}

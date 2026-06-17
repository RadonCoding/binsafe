use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

use crate::{runtime::Runtime, vm::handlers::vector};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    vector::with_stride_extended(
        rt,
        |rt| {
            // mulpd xmm0, xmm1
            rt.asm.mulpd(xmm0, xmm1).unwrap();
        },
        |rt| {
            // pmulld xmm0, xmm1
            rt.asm.pmulld(xmm0, xmm1).unwrap();
        },
        |rt| {
            // mulps xmm0, xmm1
            rt.asm.mulps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // pmulhw xmm0, xmm1
            rt.asm.pmulhw(xmm0, xmm1).unwrap();
        },
        |rt| {
            // pmullw xmm0, xmm1
            rt.asm.pmullw(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vmulpd ymm0, ymm0, ymm1
            rt.asm.vmulpd(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpmulld ymm0, ymm0, ymm1
            rt.asm.vpmulld(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vmulps ymm0, ymm0, ymm1
            rt.asm.vmulps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpmulhw ymm0, ymm0, ymm1
            rt.asm.vpmulhw(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vpmullw ymm0, ymm0, ymm1
            rt.asm.vpmullw(ymm0, ymm0, ymm1).unwrap();
        },
    );
}

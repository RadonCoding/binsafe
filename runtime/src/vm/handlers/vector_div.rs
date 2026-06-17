use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

use crate::{runtime::Runtime, vm::handlers::vector};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    vector::with_stride(
        rt,
        |rt| {
            // divps xmm0, xmm1
            rt.asm.divps(xmm0, xmm1).unwrap();
        },
        |rt| {
            // divpd xmm0, xmm1
            rt.asm.divpd(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vdivps ymm0, ymm0, ymm1
            rt.asm.vdivps(ymm0, ymm0, ymm1).unwrap();
        },
        |rt| {
            // vdivpd ymm0, ymm0, ymm1
            rt.asm.vdivpd(ymm0, ymm0, ymm1).unwrap();
        },
    );
}

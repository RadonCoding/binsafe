use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

use crate::{runtime::Runtime, vm::handlers::vector};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    vector::with_width(
        rt,
        |rt| {
            // pxor xmm0, xmm1
            rt.asm.pxor(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vpxor ymm0, ymm0, ymm1
            rt.asm.vpxor(ymm0, ymm0, ymm1).unwrap();
        },
    );
}

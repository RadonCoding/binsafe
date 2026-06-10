use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

use crate::{runtime::Runtime, vm::handlers::vector};

// unsigned char* (unsigned char*)
pub fn build(rt:  &mut Runtime) {
    vector::bitwise(
        rt,
        |rt| {
            // pand xmm0, xmm1
            rt.asm.pand(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vpand ymm0, ymm0, ymm1
            rt.asm.vpand(ymm0, ymm0, ymm1).unwrap();
        },
    );
}

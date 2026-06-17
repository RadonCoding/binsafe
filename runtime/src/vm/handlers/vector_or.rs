use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

use crate::{runtime::Runtime, vm::handlers::vector};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    vector::bitwise(
        rt,
        |rt| {
            // por xmm0, xmm1
            rt.asm.por(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vpor ymm0, ymm0, ymm1
            rt.asm.vpor(ymm0, ymm0, ymm1).unwrap();
        },
    );
}

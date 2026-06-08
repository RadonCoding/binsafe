use iced_x86::code_asm::{xmm0, xmm1, ymm0, ymm1};

use crate::{runtime::Runtime, vm::handlers::vector};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    vector::bitwise(
        rt,
        |rt| {
            // pandn xmm0, xmm1
            rt.asm.pandn(xmm0, xmm1).unwrap();
        },
        |rt| {
            // vpandn ymm0, ymm0, ymm1
            rt.asm.vpandn(ymm0, ymm0, ymm1).unwrap();
        },
    );
}

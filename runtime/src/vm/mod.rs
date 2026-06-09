pub mod bytecode;
pub mod encoders;
pub mod functions;
pub mod handlers;
pub mod lifters;
pub mod transform;
pub mod utils;

use crate::vm::bytecode::{VMReg, VMVec};
use iced_x86::code_asm::{
    r10, r11, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, xmm0, xmm1, xmm10, xmm11,
    xmm12, xmm13, xmm14, xmm15, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, ymm0, ymm1, ymm10,
    ymm11, ymm12, ymm13, ymm14, ymm15, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, ymm9,
    AsmRegister64, AsmRegisterXmm, AsmRegisterYmm,
};

const REGISTERS_TO_NATIVE: &[(VMReg, AsmRegister64)] = &[
    (VMReg::Rax, rax),
    (VMReg::Rcx, rcx),
    (VMReg::Rdx, rdx),
    (VMReg::Rbx, rbx),
    (VMReg::Rbp, rbp),
    (VMReg::Rsi, rsi),
    (VMReg::Rdi, rdi),
    (VMReg::R8, r8),
    (VMReg::R9, r9),
    (VMReg::R10, r10),
    (VMReg::R11, r11),
    // (VMReg::R12, r12),
    (VMReg::R13, r13),
    (VMReg::R14, r14),
    (VMReg::R15, r15),
];

const VECTORS_TO_NATIVE: &[(VMVec, AsmRegisterYmm, AsmRegisterXmm)] = &[
    (VMVec::Ymm0, ymm0, xmm0),
    (VMVec::Ymm1, ymm1, xmm1),
    (VMVec::Ymm2, ymm2, xmm2),
    (VMVec::Ymm3, ymm3, xmm3),
    (VMVec::Ymm4, ymm4, xmm4),
    (VMVec::Ymm5, ymm5, xmm5),
    (VMVec::Ymm6, ymm6, xmm6),
    (VMVec::Ymm7, ymm7, xmm7),
    (VMVec::Ymm8, ymm8, xmm8),
    (VMVec::Ymm9, ymm9, xmm9),
    (VMVec::Ymm10, ymm10, xmm10),
    (VMVec::Ymm11, ymm11, xmm11),
    (VMVec::Ymm12, ymm12, xmm12),
    (VMVec::Ymm13, ymm13, xmm13),
    (VMVec::Ymm14, ymm14, xmm14),
    (VMVec::Ymm15, ymm15, xmm15),
];

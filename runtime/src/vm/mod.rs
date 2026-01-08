pub mod bytecode;
pub mod crypt;
pub mod dispatch;
pub mod entry;
pub mod exit;
pub mod ginit;
pub mod handlers;
pub mod stack;
pub mod tinit;
pub mod utils;
pub mod veh;

use crate::vm::bytecode::VMReg;
use iced_x86::code_asm::{
    r10, r11, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, AsmRegister64,
};

const VREG_TO_REG: &[(VMReg, AsmRegister64)] = &[
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
    (VMReg::R13, r13),
    (VMReg::R14, r14),
    (VMReg::R15, r15),
];

use iced_x86::{Register, UsedRegister};
use runtime::{
    mapper::Mappable,
    register,
    vm::bytecode::{VMReg, VMVec},
};

use crate::State;

pub const VIRTUAL_REGISTERS: [VMReg; 17] = [
    VMReg::Rax,
    VMReg::Rcx,
    VMReg::Rdx,
    VMReg::Rbx,
    VMReg::Rsp,
    VMReg::Rbp,
    VMReg::Rsi,
    VMReg::Rdi,
    VMReg::R8,
    VMReg::R9,
    VMReg::R10,
    VMReg::R11,
    VMReg::R12,
    VMReg::R13,
    VMReg::R14,
    VMReg::R15,
    VMReg::Flags,
];

pub const VIRTUAL_VECTORS: [VMVec; 16] = [
    VMVec::Ymm0,
    VMVec::Ymm1,
    VMVec::Ymm2,
    VMVec::Ymm3,
    VMVec::Ymm4,
    VMVec::Ymm5,
    VMVec::Ymm6,
    VMVec::Ymm7,
    VMVec::Ymm8,
    VMVec::Ymm9,
    VMVec::Ymm10,
    VMVec::Ymm11,
    VMVec::Ymm12,
    VMVec::Ymm13,
    VMVec::Ymm14,
    VMVec::Ymm15,
];

pub const NATIVE_REGISTERS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

pub const IMMEDIATES: &[u64] = &[0, 0xFFFF_FFFF_FFFF_FFFF];

pub fn baseline() -> State {
    let mut state = State::default();

    for register in [
        VMReg::Rax,
        VMReg::Rcx,
        VMReg::Rdx,
        VMReg::Rbx,
        VMReg::Rbp,
        VMReg::Rsi,
        VMReg::Rdi,
        VMReg::R8,
        VMReg::R9,
        VMReg::R10,
        VMReg::R11,
        VMReg::R12,
        VMReg::R13,
        VMReg::R14,
        VMReg::R15,
        VMReg::Flags,
    ] {
        state.registers.insert(register, 0);
    }

    for &vector in VMVec::VARIANTS {
        state.vectors.insert(vector, [0u128; 2]);
    }

    state
}

pub fn vector(mut state: State, register: VMVec, bytes: [u128; 2]) -> State {
    state.vectors.insert(register, bytes);
    state
}

pub fn register(operand: usize, size: usize) -> Register {
    register::sized(NATIVE_REGISTERS[operand % NATIVE_REGISTERS.len()], size).unwrap()
}

pub fn available(used: &[UsedRegister]) -> Register {
    NATIVE_REGISTERS
        .iter()
        .copied()
        .find(|candidate| !used.iter().any(|used| used.register() == *candidate))
        .unwrap()
}

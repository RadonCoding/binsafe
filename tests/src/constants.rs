use runtime::{
    mapper::Mappable,
    vm::bytecode::{VMReg, VMVec},
};

use crate::State;

pub const REGISTERS: [VMReg; 17] = [
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
pub const VECTORS: [VMVec; 16] = [
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

pub fn bytes16(value: u128) -> [u128; 2] {
    let mut vector = [0u128; 2];
    vector[0] = value;
    vector
}

pub fn gpr() -> State {
    baseline()
        .with(VMReg::Rax, IMM64_A)
        .with(VMReg::Rcx, IMM64_B)
        .with(VMReg::Rdx, IMM64_C)
}

pub fn simd() -> State {
    let state = baseline();
    let state = vector(state, VMVec::Ymm0, bytes16(IMM128_A));
    let state = vector(state, VMVec::Ymm1, bytes16(IMM128_B));
    vector(state, VMVec::Ymm2, bytes16(IMM128_C))
}

pub const IMM8_A: u8 = 0x85;
pub const IMM16_A: u16 = 0x8A5C;
pub const IMM32_A: u32 = 0x8A5C_E179;
pub const IMM64_A: u64 = 0x8A5C_E179_2D4B_7F67;
pub const IMM64_B: u64 = 0x5BD4_F28A_3E5C_6E78;
pub const IMM64_C: u64 = 0x4CE5_039B_4F6D_5D69;

pub const SIMM8_A: i32 = 0x75;
pub const _SIMM16_A: i16 = 0x6A5C;
pub const SIMM32_A: i32 = 0x6A5C_E179;
pub const _SIMM64_A: i64 = 0x6A5C_E179_2D4B_7F67;

pub const IMM128_A: u128 = 0x6A5C_E179_2D4B_7F67_1032_5476_789A_BCDE;
pub const IMM128_B: u128 = 0x5BD4_F28A_3E5C_6E78_2143_6587_89AB_CDEF;
pub const IMM128_C: u128 = 0x4CE5_039B_4F6D_5D69_3254_7698_9ABC_DEF0;

pub const FAKE_BRANCH_ADDRESS: u64 = 0x1234_ABCD;

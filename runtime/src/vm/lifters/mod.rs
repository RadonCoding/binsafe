use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::VMWidth;

pub mod arithmetic;
pub mod bitwise;
pub mod branch;
pub mod bsr;
pub mod bswap;
pub mod bt;
pub mod cmov;
pub mod cmpxchg;
pub mod divide;
pub mod extend;
pub mod lea;
pub mod multiply;
pub mod pcmpeqb;
pub mod pmovskb;
pub mod scalar;
pub mod set;
pub mod stack;
pub mod transfer;
pub mod tzcnt;
pub mod unary;
pub mod xadd;
pub mod xchg;

fn operation_width(instruction: &Instruction, kind: OpKind) -> VMWidth {
    match kind {
        OpKind::Register => VMWidth::from(instruction.op0_register()),
        OpKind::Memory => match instruction.memory_size().size() {
            1 => VMWidth::Lower8,
            2 => VMWidth::Lower16,
            4 => VMWidth::Lower32,
            8 => VMWidth::Lower64,
            16 => VMWidth::Lower128,
            32 => VMWidth::Lower256,
            _ => panic!("unsupported code: {:?}", instruction.code()),
        },
        kind if is_immediate(kind) => match operation_immediate(instruction, kind) {
            0..=0xFF => VMWidth::Lower8,
            0..=0xFFFF => VMWidth::Lower16,
            0..=0xFFFFFFFF => VMWidth::Lower32,
            _ => VMWidth::Lower64,
        },
        _ => panic!("unsupported kind: {kind:?}",),
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn operation_immediate(instruction: &Instruction, kind: OpKind) -> u64 {
    match kind {
        OpKind::Immediate8 => instruction.immediate8() as u64,
        OpKind::Immediate16 => instruction.immediate16() as u64,
        OpKind::Immediate32 => instruction.immediate32() as u64,
        OpKind::Immediate64 => instruction.immediate64(),
        OpKind::Immediate8to16 => instruction.immediate8to16() as u16 as u64,
        OpKind::Immediate8to32 => instruction.immediate8to32() as u32 as u64,
        OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
        OpKind::Immediate32to64 => instruction.immediate32to64() as u64,
        _ => unreachable!(),
    }
}

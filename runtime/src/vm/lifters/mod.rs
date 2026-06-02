use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::VMWidth;

pub mod add;
pub mod and;
pub mod arithmetic;
pub mod cmov;
pub mod cmp;
pub mod dec;
pub mod imul;
pub mod inc;
pub mod jcc;
pub mod lea;
pub mod mov;
pub mod movsx;
pub mod movzx;
pub mod mul;
pub mod multiply;
pub mod neg;
pub mod not;
pub mod or;
pub mod pop;
pub mod push;
pub mod rol;
pub mod ror;
pub mod sar;
pub mod set;
pub mod shl;
pub mod shr;
pub mod sub;
pub mod test;
pub mod unary;
pub mod xor;

fn operation_width(instruction: &Instruction, kind: OpKind) -> Option<VMWidth> {
    match kind {
        OpKind::Register => Some(VMWidth::from(instruction.op0_register())),
        OpKind::Memory => match instruction.memory_size().size() {
            1 => Some(VMWidth::Lower8),
            2 => Some(VMWidth::Lower16),
            4 => Some(VMWidth::Lower32),
            8 => Some(VMWidth::Lower64),
            _ => None,
        },
        kind if is_immediate(kind) => Some(match operation_immediate(instruction, kind) {
            0..=0xFF => VMWidth::Lower8,
            0..=0xFFFF => VMWidth::Lower16,
            0..=0xFFFFFFFF => VMWidth::Lower32,
            _ => VMWidth::Lower64,
        }),
        _ => None,
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

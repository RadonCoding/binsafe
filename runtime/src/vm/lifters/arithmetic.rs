use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    discard::Discard, encode_immediate, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};

pub enum Tail {
    Writeback,
    Discard,
}

pub fn encode<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
    tail: Tail,
) -> Option<Vec<Box<dyn Encode>>> {
    let op0_kind = instruction.op0_kind();
    let op1_kind = instruction.op1_kind();

    let width = operation_width(instruction, op0_kind)?;

    let mut operations = Vec::<Box<dyn Encode>>::new();

    match op0_kind {
        OpKind::Register => {
            operations.push(Box::new(LoadRegister {
                width,
                source: VMReg::from(instruction.op0_register()),
            }));
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory { width }));
        }
        _ => return None,
    }

    match op1_kind {
        OpKind::Register => {
            let register = instruction.op1_register();
            operations.push(Box::new(LoadRegister {
                width: VMWidth::from(register),
                source: VMReg::from(register),
            }));
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory { width }));
        }
        kind if is_immediate(kind) => {
            let value = extract_immediate(instruction, kind);
            let (immediate_width, size) = encode_immediate(value);
            operations.push(Box::new(LoadImmediate {
                width: immediate_width,
                source: value.to_le_bytes()[..size].to_vec(),
            }));
        }
        _ => return None,
    }

    operations.push(Box::new(make(width)));

    match tail {
        Tail::Writeback => match op0_kind {
            OpKind::Register => {
                operations.push(Box::new(StoreRegister {
                    width,
                    destination: VMReg::from(instruction.op0_register()),
                }));
            }
            OpKind::Memory => {
                operations.push(Box::new(LoadAddress {
                    source: VMMem::from(instruction),
                }));
                operations.push(Box::new(StoreMemory { width }));
            }
            _ => unreachable!(),
        },
        Tail::Discard => {
            operations.push(Box::new(Discard));
        }
    }

    Some(operations)
}

fn operation_width(instruction: &Instruction, op0_kind: OpKind) -> Option<VMWidth> {
    match op0_kind {
        OpKind::Register => Some(VMWidth::from(instruction.op0_register())),
        OpKind::Memory => match instruction.memory_size().size() {
            1 => Some(VMWidth::Lower8),
            2 => Some(VMWidth::Lower16),
            4 => Some(VMWidth::Lower32),
            8 => Some(VMWidth::Lower64),
            _ => None,
        },
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

fn extract_immediate(instruction: &Instruction, kind: OpKind) -> u64 {
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

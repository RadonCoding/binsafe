use std::rc::Rc;
use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    discard::Discard, encode_immediate, imul::Imul, load_address::LoadAddress,
    load_immediate::LoadImmediate, load_memory::LoadMemory, load_register::LoadRegister,
    store_register::StoreRegister, Encode,
};

pub fn wide<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let op0_kind = instruction.op0_kind();
    let width = operation_width(instruction, op0_kind)?;

    let accumulator = match width {
        VMWidth::Higher8 => VMWidth::Lower8,
        other => other,
    };

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    operations.push(Rc::new(LoadRegister {
        width: accumulator,
        source: VMReg::Rax,
    }));

    source(&mut operations, instruction, 0, width)?;

    operations.push(Rc::new(make(width)));

    match width {
        VMWidth::Lower8 | VMWidth::Higher8 => {
            operations.push(Rc::new(StoreRegister {
                width: VMWidth::Lower8,
                destination: VMReg::Rax,
            }));
            operations.push(Rc::new(StoreRegister {
                width: VMWidth::Higher8,
                destination: VMReg::Rax,
            }));
        }
        _ => {
            operations.push(Rc::new(StoreRegister {
                width,
                destination: VMReg::Rax,
            }));
            operations.push(Rc::new(StoreRegister {
                width,
                destination: VMReg::Rdx,
            }));
        }
    }

    Some(operations)
}

pub fn narrow(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    if instruction.op0_kind() != OpKind::Register {
        return None;
    }

    let destination = instruction.op0_register();
    let width = VMWidth::from(destination);

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op_count() {
        2 => {
            operations.push(Rc::new(LoadRegister {
                width,
                source: VMReg::from(destination),
            }));
            source(&mut operations, instruction, 1, width)?;
        }
        3 => {
            source(&mut operations, instruction, 1, width)?;
            let value = extract_immediate(instruction, instruction.op_kind(2))?;
            let (immediate_width, size) = encode_immediate(value);
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: value.to_le_bytes()[..size].to_vec(),
            }));
        }
        _ => return None,
    }

    operations.push(Rc::new(Imul { width }));
    operations.push(Rc::new(StoreRegister {
        width,
        destination: VMReg::from(destination),
    }));
    operations.push(Rc::new(Discard));

    Some(operations)
}

fn source(
    operations: &mut Vec<Rc<dyn Encode>>,
    instruction: &Instruction,
    index: u32,
    width: VMWidth,
) -> Option<()> {
    match instruction.op_kind(index) {
        OpKind::Register => {
            operations.push(Rc::new(LoadRegister {
                width,
                source: VMReg::from(instruction.op_register(index)),
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory { width }));
        }
        _ => return None,
    }

    Some(())
}

fn extract_immediate(instruction: &Instruction, kind: OpKind) -> Option<u64> {
    match kind {
        OpKind::Immediate8to16 => Some(instruction.immediate8to16() as u16 as u64),
        OpKind::Immediate8to32 => Some(instruction.immediate8to32() as u32 as u64),
        OpKind::Immediate8to64 => Some(instruction.immediate8to64() as u64),
        OpKind::Immediate16 => Some(instruction.immediate16() as u64),
        OpKind::Immediate32 => Some(instruction.immediate32() as u64),
        OpKind::Immediate32to64 => Some(instruction.immediate32to64() as u64),
        _ => None,
    }
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

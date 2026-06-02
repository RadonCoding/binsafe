use std::rc::Rc;
use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    encode_immediate, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};

pub fn encode<O: Encode + 'static>(
    instruction: &Instruction,
    value: u64,
    reverse: bool,
    preserve: bool,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let op0_kind = instruction.op0_kind();
    let width = operation_width(instruction, op0_kind)?;

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    if preserve {
        operations.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Flags,
        }));
    }

    if reverse {
        operations.push(immediate(value));
        load(&mut operations, instruction, op0_kind, width);
    } else {
        load(&mut operations, instruction, op0_kind, width);
        operations.push(immediate(value));
    }

    operations.push(Rc::new(make(width)));

    match op0_kind {
        OpKind::Register => {
            operations.push(Rc::new(StoreRegister {
                width,
                destination: VMReg::from(instruction.op0_register()),
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory { width }));
        }
        _ => unreachable!(),
    }

    if preserve {
        operations.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }));
    }

    Some(operations)
}

fn load(
    operations: &mut Vec<Rc<dyn Encode>>,
    instruction: &Instruction,
    op0_kind: OpKind,
    width: VMWidth,
) {
    match op0_kind {
        OpKind::Register => {
            operations.push(Rc::new(LoadRegister {
                width,
                source: VMReg::from(instruction.op0_register()),
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory { width }));
        }
        _ => unreachable!(),
    }
}

fn immediate(value: u64) -> Rc<dyn Encode> {
    let (width, size) = encode_immediate(value);
    Rc::new(LoadImmediate {
        width,
        source: value.to_le_bytes()[..size].to_vec(),
    })
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

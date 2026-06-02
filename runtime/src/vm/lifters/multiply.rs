use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    discard::Discard, imul::Imul, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{operation_immediate, operation_width};

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

            let immediate = operation_immediate(instruction, instruction.op_kind(2));
            let immediate_width = operation_width(instruction, instruction.op_kind(2))?;
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate.to_le_bytes()[..immediate_width.size()].to_vec(),
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

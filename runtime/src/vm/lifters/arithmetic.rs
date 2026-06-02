use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    discard::Discard, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{is_immediate, operation_immediate, operation_width};

pub enum Tail {
    Writeback,
    Discard,
}

pub fn encode<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
    tail: Tail,
) -> Option<Vec<Rc<dyn Encode>>> {
    let op0_kind = instruction.op0_kind();
    let op1_kind = instruction.op1_kind();

    let width = operation_width(instruction, op0_kind)?;

    let mut operations = Vec::<Rc<dyn Encode>>::new();

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
        _ => return None,
    }

    match op1_kind {
        OpKind::Register => {
            let register = instruction.op1_register();
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::from(register),
                source: VMReg::from(register),
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory { width }));
        }
        kind if is_immediate(kind) => {
            let immediate = operation_immediate(instruction, kind);
            let immediate_width = operation_width(instruction, kind)?;
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => return None,
    }

    operations.push(Rc::new(make(width)));

    match tail {
        Tail::Writeback => match op0_kind {
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
        },
        Tail::Discard => {
            operations.push(Rc::new(Discard));
        }
    }

    Some(operations)
}

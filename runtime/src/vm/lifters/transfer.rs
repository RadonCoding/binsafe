use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, load_vector::LoadVector, store_memory::StoreMemory,
    store_register::StoreRegister, store_vector::StoreVector, Encode,
};
use crate::vm::lifters::{is_immediate, operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let destination_width = operation_width(instruction, instruction.op0_kind());

    match instruction.op1_kind() {
        OpKind::Register => {
            let register = instruction.op1_register();

            if vector(destination_width) {
                let source_register = VMVec::from(register);
                operations.push(Rc::new(LoadVector {
                    width: destination_width,
                    source: source_register,
                }));
            } else {
                let source_register = VMReg::from(register);
                let source_width = VMWidth::from(register);
                operations.push(Rc::new(LoadRegister {
                    width: source_width,
                    source: source_register,
                }));
            }
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: destination_width,
            }));
        }
        kind if is_immediate(kind) => {
            let immediate_source = operation_immediate(instruction, kind);
            let immediate_width = operation_width(instruction, kind);
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate_source.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => unreachable!(),
    }

    match instruction.op0_kind() {
        OpKind::Register => {
            let register = instruction.op0_register();

            if vector(destination_width) {
                let destination_register = VMVec::from(register);
                operations.push(Rc::new(StoreVector {
                    width: destination_width,
                    destination: destination_register,
                }));
            } else {
                let destination_register = VMReg::from(register);
                operations.push(Rc::new(StoreRegister {
                    width: destination_width,
                    destination: destination_register,
                }));
            }
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory {
                width: destination_width,
            }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

fn vector(width: VMWidth) -> bool {
    matches!(width, VMWidth::Lower128 | VMWidth::Lower256)
}

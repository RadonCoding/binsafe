use iced_x86::{Instruction, OpKind};


use crate::vm::bytecode::{VMMem, VMReg, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, load_vector::LoadVector, store_memory::StoreMemory,
    store_merge::StoreMerge, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{is_immediate, operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    let destination_width = operation_width(instruction, 0);

    match instruction.op1_kind() {
        OpKind::Register => {
            if instruction.op1_register().is_vector_register() {
                let source_vector = VMVec::from(instruction.op1_register());
                operations.push(Box::new(LoadVector {
                    width: destination_width,
                    source: source_vector,
                }));
            } else {
                let source_register = VMReg::from(instruction.op1_register());
                let source_width = VMWidth::from(instruction.op1_register());
                operations.push(Box::new(LoadRegister {
                    width: source_width,
                    source: source_register,
                }));
            }
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory {
                width: destination_width,
            }));
        }
        kind if is_immediate(kind) => {
            let immediate_source = operation_immediate(instruction, kind);
            let immediate_width = operation_width(instruction, 1);
            operations.push(Box::new(LoadImmediate {
                width: immediate_width,
                source: immediate_source.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => unreachable!(),
    }

    match instruction.op0_kind() {
        OpKind::Register => {
            if instruction.op0_register().is_vector_register() {
                let destination_vector = VMVec::from(instruction.op0_register());
                operations.push(Box::new(StoreMerge {
                    width: destination_width,
                    destination: destination_vector,
                }));
            } else {
                let destination_register = VMReg::from(instruction.op0_register());
                operations.push(Box::new(StoreRegister {
                    width: destination_width,
                    destination: destination_register,
                }));
            }
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(StoreMemory {
                width: destination_width,
            }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

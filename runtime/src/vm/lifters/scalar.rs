use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    store_memory::StoreMemory, store_vector::StoreVector, vector_xor::VectorXor, Encode,
};
use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let scalar_width = match instruction.mnemonic() {
        Mnemonic::Movss => VMWidth::Lower32,
        Mnemonic::Movsd => VMWidth::Lower64,
        _ => panic!("unsupported mnemonic: {:?}", instruction.mnemonic()),
    };

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_vector = VMVec::from(instruction.op1_register());
            operations.push(Rc::new(LoadVector {
                width: scalar_width,
                source: source_vector,
            }));
        }
        OpKind::Memory => {
            let destination_width = VMWidth::from(instruction.op0_register());
            let destination_vector = VMVec::from(instruction.op0_register());

            operations.push(Rc::new(LoadVector {
                width: destination_width,
                source: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: destination_width,
                source: destination_vector,
            }));
            operations.push(Rc::new(VectorXor {
                width: destination_width,
            }));
            operations.push(Rc::new(StoreVector {
                width: destination_width,
                destination: destination_vector,
            }));

            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: scalar_width,
            }));
        }
        _ => unreachable!(),
    }

    match instruction.op0_kind() {
        OpKind::Register => {
            let destination_vector = VMVec::from(instruction.op0_register());
            operations.push(Rc::new(StoreVector {
                width: scalar_width,
                destination: destination_vector,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory {
                width: scalar_width,
            }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

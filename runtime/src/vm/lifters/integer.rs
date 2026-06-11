use crate::vm::bytecode::{VMMem, VMReg, VMVec, VMWidth};
use crate::vm::encoders::store_extend::StoreExtend;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_register::LoadRegister,
    load_vector::LoadVector, store_register::StoreRegister, Encode,
};
use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let scalar_width = match instruction.mnemonic() {
        Mnemonic::Movd => VMWidth::Lower32,
        Mnemonic::Movq => VMWidth::Lower64,
        _ => panic!("unsupported mnemonic: {:?}", instruction.mnemonic()),
    };

    match instruction.op1_kind() {
        OpKind::Register => {
            if instruction.op1_register().is_vector_register() {
                let source_vector = VMVec::from(instruction.op1_register());
                operations.push(Rc::new(LoadVector {
                    width: scalar_width,
                    source: source_vector,
                }));
            } else {
                let source_register = VMReg::from(instruction.op1_register());
                operations.push(Rc::new(LoadRegister {
                    width: scalar_width,
                    source: source_register,
                }));
            }
        }
        OpKind::Memory => {
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
            if instruction.op0_register().is_vector_register() {
                let destination_vector = VMVec::from(instruction.op0_register());

                operations.push(Rc::new(StoreExtend {
                    width: scalar_width,
                    destination: destination_vector,
                }));
            } else {
                let destination_register = VMReg::from(instruction.op0_register());
                operations.push(Rc::new(StoreRegister {
                    width: scalar_width,
                    destination: destination_register,
                }));
            }
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

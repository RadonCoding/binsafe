use crate::vm::bytecode::{VMMem, VMReg, VMVec, VMWidth};
use crate::vm::encoders::store_extend::StoreExtend;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_register::LoadRegister,
    load_vector::LoadVector, store_register::StoreRegister, Encode,
};
use iced_x86::{Instruction, Mnemonic, OpKind};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    let width = match instruction.mnemonic() {
        Mnemonic::Movd => VMWidth::Lower32,
        Mnemonic::Movq => VMWidth::Lower64,
        _ => panic!("unsupported mnemonic: {:?}", instruction.mnemonic()),
    };

    match instruction.op1_kind() {
        OpKind::Register => {
            if instruction.op1_register().is_vector_register() {
                let source = VMVec::from(instruction.op1_register());
                operations.push(Box::new(LoadVector { width, source }));
            } else {
                let source_register = VMReg::from(instruction.op1_register());
                operations.push(Box::new(LoadRegister {
                    width,
                    source: source_register,
                }));
            }
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory { width }));
        }
        _ => unreachable!(),
    }

    match instruction.op0_kind() {
        OpKind::Register => {
            if instruction.op0_register().is_vector_register() {
                let destination = VMVec::from(instruction.op0_register());
                operations.push(Box::new(StoreExtend { width, destination }));
            } else {
                let destination = VMReg::from(instruction.op0_register());
                operations.push(Box::new(StoreRegister { width, destination }));
            }
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(StoreMemory { width }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

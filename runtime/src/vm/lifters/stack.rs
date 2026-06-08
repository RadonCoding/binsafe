use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, pop::Pop, push::Push, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Push => push(instruction),
        Mnemonic::Pop => pop(instruction),
        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

fn push(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op0_kind() {
        OpKind::Register => {
            let source_register = VMReg::from(instruction.op0_register());
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::Lower64,
                source: source_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: VMWidth::Lower64,
            }));
        }
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate8to64 => {
            let immediate_source = operation_immediate(instruction, instruction.op0_kind());
            let immediate_width = operation_width(instruction, instruction.op0_kind())?;
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate_source.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Rc::new(Push));

    Some(operations)
}

fn pop(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    operations.push(Rc::new(Pop));

    match instruction.op0_kind() {
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());
            operations.push(Rc::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: destination_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory {
                width: VMWidth::Lower64,
            }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

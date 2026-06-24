use iced_x86::{Instruction, Mnemonic, OpKind};


use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, pop::Pop, push::Push, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Push => push(instruction),
        Mnemonic::Pop => pop(instruction),
        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

fn push(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    match instruction.op0_kind() {
        OpKind::Register => {
            let source_register = VMReg::from(instruction.op0_register());

            operations.push(Box::new(LoadRegister {
                width: VMWidth::Lower64,
                source: source_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory {
                width: VMWidth::Lower64,
            }));
        }
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate8to64 => {
            let immediate_source = operation_immediate(instruction, instruction.op0_kind());
            let immediate_width = operation_width(instruction, 0);

            operations.push(Box::new(LoadImmediate {
                width: immediate_width,
                source: immediate_source.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Box::new(Push));

    Some(operations)
}

fn pop(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    operations.push(Box::new(Pop));

    match instruction.op0_kind() {
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());

            operations.push(Box::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: destination_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(StoreMemory {
                width: VMWidth::Lower64,
            }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

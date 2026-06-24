use iced_x86::{Instruction, OpKind};


use crate::vm::bytecode::{VMMem, VMReg};
use crate::vm::encoders::{
    add::Add, exchange_add::ExchangeAdd, load_address::LoadAddress, load_register::LoadRegister,
    store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let destination_width = operation_width(instruction, 0);
    let source_register = VMReg::from(instruction.op1_register());

    let mut operations = Vec::<Box<dyn Encode>>::new();

    match instruction.op0_kind() {
        OpKind::Memory => {
            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: source_register,
            }));
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(ExchangeAdd {
                width: destination_width,
            }));
            operations.push(Box::new(StoreRegister {
                width: destination_width,
                destination: source_register,
            }));
        }
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());

            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: source_register,
            }));
            operations.push(Box::new(Add {
                width: destination_width,
            }));
            operations.push(Box::new(StoreRegister {
                width: destination_width,
                destination: destination_register,
            }));
            operations.push(Box::new(StoreRegister {
                width: destination_width,
                destination: source_register,
            }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

use iced_x86::{Instruction, OpKind, Register};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    exchange::Exchange, load_address::LoadAddress, load_register::LoadRegister,
    store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match (instruction.op0_kind(), instruction.op1_kind()) {
        (OpKind::Register, OpKind::Register) => {
            let destination_width = operation_width(instruction, 0);
            let destination_register = VMReg::from(instruction.op0_register());
            let source_width = operation_width(instruction, 1);
            let source_register = VMReg::from(instruction.op1_register());

            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: source_register,
            }));
            operations.push(Rc::new(StoreRegister {
                width: destination_width,
                destination: destination_register,
            }));
            operations.push(Rc::new(StoreRegister {
                width: source_width,
                destination: source_register,
            }));
        }
        (OpKind::Memory, OpKind::Register) => {
            exchange(&mut operations, instruction, instruction.op1_register())
        }
        (OpKind::Register, OpKind::Memory) => {
            exchange(&mut operations, instruction, instruction.op0_register())
        }
        _ => unreachable!(),
    }

    Some(operations)
}

fn exchange(operations: &mut Vec<Rc<dyn Encode>>, instruction: &Instruction, register: Register) {
    let destination_width = VMWidth::from(register);
    let destination_register = VMReg::from(register);

    operations.push(Rc::new(LoadRegister {
        width: destination_width,
        source: destination_register,
    }));
    operations.push(Rc::new(LoadAddress {
        source: VMMem::from(instruction),
    }));
    operations.push(Rc::new(Exchange {
        width: destination_width,
    }));
    operations.push(Rc::new(StoreRegister {
        width: destination_width,
        destination: destination_register,
    }));
}

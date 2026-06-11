use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_register::LoadRegister,
    store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let signed = matches!(instruction.mnemonic(), Mnemonic::Movsx | Mnemonic::Movsxd);

    let destination_width = match VMWidth::from(instruction.op0_register()) {
        VMWidth::Lower16 => VMWidth::Lower16,
        _ => VMWidth::Lower64,
    };
    let destination_register = VMReg::from(instruction.op0_register());

    let source_width = operation_width(instruction, 1);
    let source_width = if signed {
        source_width.signed()
    } else {
        source_width
    };

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_register = VMReg::from(instruction.op1_register());
            operations.push(Rc::new(LoadRegister {
                width: source_width,
                source: source_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: source_width,
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Rc::new(StoreRegister {
        width: destination_width,
        destination: destination_register,
    }));

    Some(operations)
}

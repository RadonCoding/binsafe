use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, push::Push, Encode,
};
use crate::vm::lifters::{operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op0_kind() {
        OpKind::Register => {
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::Lower64,
                source: VMReg::from(instruction.op0_register()),
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
            let immediate = operation_immediate(instruction, instruction.op0_kind());
            let immediate_width = operation_width(instruction, instruction.op0_kind())?;
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => return None,
    }

    operations.push(Rc::new(Push));

    Some(operations)
}

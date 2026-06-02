use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, push::Push, Encode,
};
use crate::vm::lifters::encode_immediate;

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
            let value = match instruction.op0_kind() {
                OpKind::Immediate8 => instruction.immediate8() as u64,
                OpKind::Immediate16 => instruction.immediate16() as u64,
                OpKind::Immediate32 => instruction.immediate32() as u64,
                OpKind::Immediate8to64 => instruction.immediate8to64() as u64,
                _ => unreachable!(),
            };
            let (width, size) = encode_immediate(value);
            operations.push(Rc::new(LoadImmediate {
                width,
                source: value.to_le_bytes()[..size].to_vec(),
            }));
        }
        _ => return None,
    }

    operations.push(Rc::new(Push));

    Some(operations)
}

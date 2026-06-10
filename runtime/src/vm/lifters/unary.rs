use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, store_memory::StoreMemory, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode<O: Encode + 'static>(
    instruction: &Instruction,
    immediate: u64,
    reverse: bool,
    preserve: bool,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let width = operation_width(instruction, instruction.op0_kind());

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    if preserve {
        operations.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Flags,
        }));
    }

    if reverse {
        operations.push(Rc::new(LoadImmediate {
            width,
            source: immediate.to_le_bytes()[..width.size()].to_vec(),
        }));
        load(&mut operations, instruction, instruction.op0_kind(), width);
    } else {
        load(&mut operations, instruction, instruction.op0_kind(), width);
        operations.push(Rc::new(LoadImmediate {
            width,
            source: immediate.to_le_bytes()[..width.size()].to_vec(),
        }));
    }

    operations.push(Rc::new(make(width)));

    match instruction.op0_kind() {
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());
            operations.push(Rc::new(StoreRegister {
                width,
                destination: destination_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory { width }));
        }
        _ => unreachable!(),
    }

    if preserve {
        operations.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }));
    }

    Some(operations)
}

fn load(
    operations: &mut Vec<Rc<dyn Encode>>,
    instruction: &Instruction,
    op0_kind: OpKind,
    width: VMWidth,
) {
    match op0_kind {
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());
            operations.push(Rc::new(LoadRegister {
                width,
                source: destination_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory { width }));
        }
        _ => unreachable!(),
    }
}

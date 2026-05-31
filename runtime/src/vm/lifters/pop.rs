use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, pop::Pop, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations: Vec<Box<dyn Encode>> = vec![Box::new(Pop)];

    match instruction.op0_kind() {
        OpKind::Register => {
            operations.push(Box::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: VMReg::from(instruction.op0_register()),
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
        _ => return None,
    }

    Some(operations)
}

use std::rc::Rc;
use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, pop::Pop, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
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
        _ => return None,
    }

    Some(operations)
}

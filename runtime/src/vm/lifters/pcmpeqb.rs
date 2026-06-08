use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    packed_byte_equal::PackedByteEqual, store_vector::StoreVector, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let destination = VMVec::from(instruction.op0_register());

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_register = VMVec::from(instruction.op1_register());
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower128,
                source: source_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: VMWidth::Lower128,
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Rc::new(LoadVector {
        width: VMWidth::Lower128,
        source: destination,
    }));

    operations.push(Rc::new(PackedByteEqual {
        width: VMWidth::Lower128,
    }));

    operations.push(Rc::new(StoreVector {
        width: VMWidth::Lower128,
        destination,
    }));

    Some(operations)
}

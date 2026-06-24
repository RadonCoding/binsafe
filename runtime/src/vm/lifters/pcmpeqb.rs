use iced_x86::{Instruction, OpKind};


use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    packed_byte_equal::PackedByteEqual, store_merge::StoreMerge, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    let destination_vector = VMVec::from(instruction.op0_register());

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_register = VMVec::from(instruction.op1_register());
            operations.push(Box::new(LoadVector {
                width: VMWidth::Lower128,
                source: source_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory {
                width: VMWidth::Lower128,
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Box::new(LoadVector {
        width: VMWidth::Lower128,
        source: destination_vector,
    }));

    operations.push(Box::new(PackedByteEqual {
        width: VMWidth::Lower128,
    }));

    operations.push(Box::new(StoreMerge {
        width: VMWidth::Lower128,
        destination: destination_vector,
    }));

    Some(operations)
}

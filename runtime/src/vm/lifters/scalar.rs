use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::store_extend::StoreExtend;
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    store_memory::StoreMemory, store_merge::StoreMerge, Encode,
};
use iced_x86::{Instruction, Mnemonic, OpKind};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    let width = match instruction.mnemonic() {
        Mnemonic::Movss => VMWidth::Lower32,
        Mnemonic::Movsd => VMWidth::Lower64,
        _ => panic!("unsupported mnemonic: {:?}", instruction.mnemonic()),
    };

    match (instruction.op1_kind(), instruction.op0_kind()) {
        (OpKind::Register, OpKind::Register) => {
            let source = VMVec::from(instruction.op1_register());
            operations.push(Box::new(LoadVector { width, source }));
            let destination = VMVec::from(instruction.op0_register());
            operations.push(Box::new(StoreMerge { width, destination }));
        }
        (OpKind::Memory, OpKind::Register) => {
            let destination = VMVec::from(instruction.op0_register());
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(LoadMemory { width }));
            operations.push(Box::new(StoreExtend { width, destination }));
        }
        (OpKind::Register, OpKind::Memory) => {
            let source = VMVec::from(instruction.op1_register());
            operations.push(Box::new(LoadVector { width, source }));
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(StoreMemory { width }));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

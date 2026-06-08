use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    and::And, load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector, or::Or,
    store_vector::StoreVector, vector_and::VectorAnd, vector_and_not::VectorAndNot,
    vector_or::VectorOr, vector_xor::VectorXor, xor::Xor, Encode,
};
use crate::vm::lifters::arithmetic::{self, Tail};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::And => arithmetic::binary(instruction, |width| And { width }, Tail::Writeback),
        Mnemonic::Or => arithmetic::binary(instruction, |width| Or { width }, Tail::Writeback),
        Mnemonic::Xor => arithmetic::binary(instruction, |width| Xor { width }, Tail::Writeback),

        Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd | Mnemonic::Vandps => {
            vector(instruction, |width| VectorAnd { width })
        }
        Mnemonic::Por | Mnemonic::Orps | Mnemonic::Orpd => {
            vector(instruction, |width| VectorOr { width })
        }
        Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Vpxor | Mnemonic::Vxorps => {
            vector(instruction, |width| VectorXor { width })
        }
        Mnemonic::Pandn | Mnemonic::Andnps | Mnemonic::Andnpd => {
            vector(instruction, |width| VectorAndNot { width })
        }

        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

fn vector<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let destination = VMVec::from(instruction.op0_register());
    let width = width(instruction.op0_register());

    let (first, second) = if instruction.op_count() == 3 {
        (1, 2)
    } else {
        (0, 1)
    };

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    operand(&mut operations, instruction, first, width);
    operand(&mut operations, instruction, second, width);

    operations.push(Rc::new(make(width)));

    operations.push(Rc::new(StoreVector { width, destination }));

    Some(operations)
}

fn operand(
    operations: &mut Vec<Rc<dyn Encode>>,
    instruction: &Instruction,
    index: u32,
    width: VMWidth,
) {
    match instruction.op_kind(index) {
        OpKind::Register => {
            let source_register = VMVec::from(instruction.op_register(index));
            operations.push(Rc::new(LoadVector {
                width,
                source: source_register,
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

fn width(register: Register) -> VMWidth {
    if register.is_ymm() {
        VMWidth::Lower256
    } else {
        VMWidth::Lower128
    }
}

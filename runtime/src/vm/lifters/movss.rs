use iced_x86::{Code, Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    store_memory::StoreMemory, store_vector::StoreVector, vector_xor::VectorXor, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.code() {
        Code::Movss_xmm_xmmm32 => {
            let destination = VMVec::from(instruction.op0_register());

            match instruction.op1_kind() {
                OpKind::Register => {
                    let source_register = VMVec::from(instruction.op1_register());
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower32,
                        source: source_register,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower32,
                        destination,
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: destination,
                    }));
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: destination,
                    }));
                    operations.push(Rc::new(VectorXor {
                        width: VMWidth::Lower128,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower128,
                        destination,
                    }));

                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(LoadMemory {
                        width: VMWidth::Lower32,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower32,
                        destination,
                    }));
                }
                _ => unreachable!(),
            }
        }

        Code::Movss_xmmm32_xmm => {
            let source_register = VMVec::from(instruction.op1_register());
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower32,
                source: source_register,
            }));

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_register = VMVec::from(instruction.op0_register());
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower32,
                        destination: destination_register,
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(StoreMemory {
                        width: VMWidth::Lower32,
                    }));
                }
                _ => unreachable!(),
            }
        }

        _ => panic!("unsupported code: {:?}", instruction.code()),
    }

    Some(operations)
}

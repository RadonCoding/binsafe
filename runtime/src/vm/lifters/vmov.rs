use iced_x86::{Code, Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    store_memory::StoreMemory, store_vector::StoreVector, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let code = instruction.code();

    match code {
        Code::Movaps_xmm_xmmm128
        | Code::Movups_xmm_xmmm128
        | Code::Movdqa_xmm_xmmm128
        | Code::Movdqu_xmm_xmmm128 => {
            let destination = VMVec::from(instruction.op0_register());

            let mut operations = Vec::<Rc<dyn Encode>>::new();

            match instruction.op1_kind() {
                OpKind::Register => {
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: VMVec::from(instruction.op1_register()),
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
                _ => return None,
            }

            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower128,
                destination,
            }));

            Some(operations)
        }

        Code::Movaps_xmmm128_xmm
        | Code::Movups_xmmm128_xmm
        | Code::Movdqa_xmmm128_xmm
        | Code::Movdqu_xmmm128_xmm => {
            let source = VMVec::from(instruction.op1_register());

            let mut operations = Vec::<Rc<dyn Encode>>::new();
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower128,
                source,
            }));

            match instruction.op0_kind() {
                OpKind::Register => {
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower128,
                        destination: VMVec::from(instruction.op0_register()),
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(StoreMemory {
                        width: VMWidth::Lower128,
                    }));
                }
                _ => return None,
            }

            Some(operations)
        }

        _ => None,
    }
}

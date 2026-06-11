use crate::vm::bytecode::{VMMem, VMVec, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_vector::LoadVector,
    store_memory::StoreMemory, store_vector::StoreVector, vector_xor::VectorXor, Encode,
};
use iced_x86::{Code, Instruction, OpKind};
use std::rc::Rc;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.code() {
        Code::Movss_xmm_xmmm32 => {
            let destination_vector = VMVec::from(instruction.op0_register());

            match instruction.op1_kind() {
                OpKind::Register => {
                    let source_vector = VMVec::from(instruction.op1_register());

                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower32,
                        source: source_vector,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower32,
                        destination: destination_vector,
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: destination_vector,
                    }));
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: destination_vector,
                    }));
                    operations.push(Rc::new(VectorXor {
                        width: VMWidth::Lower128,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower128,
                        destination: destination_vector,
                    }));
                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(LoadMemory {
                        width: VMWidth::Lower32,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower32,
                        destination: destination_vector,
                    }));
                }
                _ => unreachable!(),
            }
        }
        Code::Movss_xmmm32_xmm => {
            let source_vector = VMVec::from(instruction.op1_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower32,
                source: source_vector,
            }));

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_vector = VMVec::from(instruction.op0_register());

                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower32,
                        destination: destination_vector,
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
        Code::Movsd_xmm_xmmm64 => {
            let destination_vector = VMVec::from(instruction.op0_register());

            match instruction.op1_kind() {
                OpKind::Register => {
                    let source_vector = VMVec::from(instruction.op1_register());

                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower64,
                        source: source_vector,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower64,
                        destination: destination_vector,
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: destination_vector,
                    }));
                    operations.push(Rc::new(LoadVector {
                        width: VMWidth::Lower128,
                        source: destination_vector,
                    }));
                    operations.push(Rc::new(VectorXor {
                        width: VMWidth::Lower128,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower128,
                        destination: destination_vector,
                    }));
                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(LoadMemory {
                        width: VMWidth::Lower64,
                    }));
                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower64,
                        destination: destination_vector,
                    }));
                }
                _ => unreachable!(),
            }
        }
        Code::Movsd_xmmm64_xmm => {
            let source_vector = VMVec::from(instruction.op1_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower64,
                source: source_vector,
            }));

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_vector = VMVec::from(instruction.op0_register());

                    operations.push(Rc::new(StoreVector {
                        width: VMWidth::Lower64,
                        destination: destination_vector,
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
                _ => unreachable!(),
            }
        }
        Code::VEX_Vmovss_xmm_xmm_xmm => {
            let destination_vector = VMVec::from(instruction.op0_register());
            let upper_vector = VMVec::from(instruction.op1_register());
            let lower_vector = VMVec::from(instruction.op2_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(VectorXor {
                width: VMWidth::Lower256,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower256,
                destination: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower128,
                source: upper_vector,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower128,
                destination: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower32,
                source: lower_vector,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower32,
                destination: destination_vector,
            }));
        }
        Code::VEX_Vmovss_xmm_m32 => {
            let destination_vector = VMVec::from(instruction.op0_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(VectorXor {
                width: VMWidth::Lower256,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower256,
                destination: destination_vector,
            }));
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: VMWidth::Lower32,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower32,
                destination: destination_vector,
            }));
        }
        Code::VEX_Vmovss_m32_xmm => {
            let source_vector = VMVec::from(instruction.op1_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower32,
                source: source_vector,
            }));
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory {
                width: VMWidth::Lower32,
            }));
        }
        Code::VEX_Vmovsd_xmm_xmm_xmm => {
            let destination_vector = VMVec::from(instruction.op0_register());
            let upper_vector = VMVec::from(instruction.op1_register());
            let lower_vector = VMVec::from(instruction.op2_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(VectorXor {
                width: VMWidth::Lower256,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower256,
                destination: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower128,
                source: upper_vector,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower128,
                destination: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower64,
                source: lower_vector,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower64,
                destination: destination_vector,
            }));
        }
        Code::VEX_Vmovsd_xmm_m64 => {
            let destination_vector = VMVec::from(instruction.op0_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower256,
                source: destination_vector,
            }));
            operations.push(Rc::new(VectorXor {
                width: VMWidth::Lower256,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower256,
                destination: destination_vector,
            }));
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: VMWidth::Lower64,
            }));
            operations.push(Rc::new(StoreVector {
                width: VMWidth::Lower64,
                destination: destination_vector,
            }));
        }
        Code::VEX_Vmovsd_m64_xmm => {
            let source_vector = VMVec::from(instruction.op1_register());

            operations.push(Rc::new(LoadVector {
                width: VMWidth::Lower64,
                source: source_vector,
            }));
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory {
                width: VMWidth::Lower64,
            }));
        }
        _ => panic!("unsupported code: {:?}", instruction.code()),
    }

    Some(operations)
}

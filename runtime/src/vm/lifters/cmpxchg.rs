use iced_x86::{Instruction, OpKind};

use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMMem, VMReg};
use crate::vm::encoders::block::Block;
use crate::vm::encoders::{
    compare_exchange::CompareExchange, discard::Discard, load_address::LoadAddress,
    load_register::LoadRegister, store_register::StoreRegister, sub::Sub, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let destination_width = operation_width(instruction, 0);
    let source_register = VMReg::from(instruction.op1_register());

    let mut operations = Vec::<Box<dyn Encode>>::new();

    match instruction.op0_kind() {
        OpKind::Memory => {
            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: VMReg::Rax,
            }));
            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: source_register,
            }));
            operations.push(Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Box::new(CompareExchange {
                width: destination_width,
            }));
            operations.push(Box::new(StoreRegister {
                width: destination_width,
                destination: VMReg::Rax,
            }));
        }
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());

            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: VMReg::Rax,
            }));
            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Box::new(Sub {
                width: destination_width,
            }));
            operations.push(Box::new(Discard::new()));

            operations.push(Box::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Box::new(StoreRegister {
                width: destination_width,
                destination: VMReg::Rax,
            }));

            let body = vec![
                Box::new(LoadRegister {
                    width: destination_width,
                    source: source_register,
                }) as Box<dyn Encode>,
                Box::new(StoreRegister {
                    width: destination_width,
                    destination: destination_register,
                }),
            ];
            operations.push(Box::new(Block::skip(
                VMLogic::SAND,
                vec![VMCondition::cmp(VMFlag::Zero, 0)],
                body,
            )));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

use iced_x86::{Instruction, OpKind};
use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMFlag, VMLogic, VMMem, VMReg};
use crate::vm::encoders::{
    compare_exchange::CompareExchange, discard::Discard, load_address::LoadAddress,
    load_register::LoadRegister, skip::Skip, store_register::StoreRegister, sub::Sub, Encode,
};
use crate::vm::lifters::{branch::cmp, operation_width};

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let destination_width = operation_width(instruction, 0);
    let source_register = VMReg::from(instruction.op1_register());

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op0_kind() {
        OpKind::Memory => {
            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: VMReg::Rax,
            }));
            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: source_register,
            }));
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(CompareExchange {
                width: destination_width,
            }));
            operations.push(Rc::new(StoreRegister {
                width: destination_width,
                destination: VMReg::Rax,
            }));
        }
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());

            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: VMReg::Rax,
            }));
            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Rc::new(Sub {
                width: destination_width,
            }));
            operations.push(Rc::new(Discard));

            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            operations.push(Rc::new(StoreRegister {
                width: destination_width,
                destination: VMReg::Rax,
            }));

            let body = vec![
                Rc::new(LoadRegister {
                    width: destination_width,
                    source: source_register,
                }) as Rc<dyn Encode>,
                Rc::new(StoreRegister {
                    width: destination_width,
                    destination: destination_register,
                }),
            ];
            operations.push(Rc::new(Skip::new(
                mapper,
                VMLogic::SAND,
                vec![cmp(VMFlag::Zero, 0)],
                body,
            )));
        }
        _ => unreachable!(),
    }

    Some(operations)
}

use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    divide::Divide, load_address::LoadAddress, load_memory::LoadMemory,
    load_register::LoadRegister, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::operation_width;

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Div => wide(instruction, |width| Divide { width }),
        Mnemonic::Idiv => wide(instruction, |width| Divide {
            width: width.signed(),
        }),
        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

pub fn wide<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let width = operation_width(instruction, 0);

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    source(&mut operations, instruction, 0, width)?;

    match width {
        VMWidth::Lower8 | VMWidth::Higher8 => {
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::Lower8,
                source: VMReg::Rax,
            }));
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::Higher8,
                source: VMReg::Rax,
            }));
        }
        _ => {
            operations.push(Rc::new(LoadRegister {
                width,
                source: VMReg::Rax,
            }));
            operations.push(Rc::new(LoadRegister {
                width,
                source: VMReg::Rdx,
            }));
        }
    }

    operations.push(Rc::new(make(width)));

    match width {
        VMWidth::Lower8 | VMWidth::Higher8 => {
            operations.push(Rc::new(StoreRegister {
                width: VMWidth::Lower8,
                destination: VMReg::Rax,
            }));
            operations.push(Rc::new(StoreRegister {
                width: VMWidth::Higher8,
                destination: VMReg::Rax,
            }));
        }
        _ => {
            operations.push(Rc::new(StoreRegister {
                width,
                destination: VMReg::Rax,
            }));
            operations.push(Rc::new(StoreRegister {
                width,
                destination: VMReg::Rdx,
            }));
        }
    }

    Some(operations)
}

fn source(
    operations: &mut Vec<Rc<dyn Encode>>,
    instruction: &Instruction,
    index: u32,
    width: VMWidth,
) -> Option<()> {
    match instruction.op_kind(index) {
        OpKind::Register => {
            operations.push(Rc::new(LoadRegister {
                width,
                source: VMReg::from(instruction.op_register(index)),
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

    Some(())
}

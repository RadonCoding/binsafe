use iced_x86::{Instruction, Mnemonic};


use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::{
    divide::Divide, load_register::LoadRegister, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{operation_width, source};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
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
) -> Option<Vec<Box<dyn Encode>>> {
    let width = operation_width(instruction, 0);

    let mut operations = Vec::<Box<dyn Encode>>::new();

    source(&mut operations, instruction, 0, width)?;

    match width {
        VMWidth::Lower8 | VMWidth::Higher8 => {
            operations.push(Box::new(LoadRegister {
                width: VMWidth::Lower8,
                source: VMReg::Rax,
            }));
            operations.push(Box::new(LoadRegister {
                width: VMWidth::Higher8,
                source: VMReg::Rax,
            }));
        }
        _ => {
            operations.push(Box::new(LoadRegister {
                width,
                source: VMReg::Rax,
            }));
            operations.push(Box::new(LoadRegister {
                width,
                source: VMReg::Rdx,
            }));
        }
    }

    operations.push(Box::new(make(width)));

    match width {
        VMWidth::Lower8 | VMWidth::Higher8 => {
            operations.push(Box::new(StoreRegister {
                width: VMWidth::Lower8,
                destination: VMReg::Rax,
            }));
            operations.push(Box::new(StoreRegister {
                width: VMWidth::Higher8,
                destination: VMReg::Rax,
            }));
        }
        _ => {
            operations.push(Box::new(StoreRegister {
                width,
                destination: VMReg::Rax,
            }));
            operations.push(Box::new(StoreRegister {
                width,
                destination: VMReg::Rdx,
            }));
        }
    }

    Some(operations)
}

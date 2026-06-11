use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    discard::Discard, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, mul::Mul, store_register::StoreRegister,
    Encode,
};
use crate::vm::lifters::{operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Mul => wide(instruction, |width| Mul { width }),
        Mnemonic::Imul if instruction.op_count() == 1 => wide(instruction, |width| Mul {
            width: width.signed(),
        }),
        Mnemonic::Imul => narrow(instruction),
        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

pub fn wide<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let width = operation_width(instruction, 0);

    operations.push(Rc::new(LoadRegister {
        width,
        source: VMReg::Rax,
    }));

    source(&mut operations, instruction, 0, width)?;

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

pub fn narrow(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let destination_width = VMWidth::from(instruction.op0_register());
    let destination_register = VMReg::from(instruction.op0_register());

    match instruction.op_count() {
        2 => {
            operations.push(Rc::new(LoadRegister {
                width: destination_width,
                source: destination_register,
            }));
            source(&mut operations, instruction, 1, destination_width)?;
        }
        3 => {
            source(&mut operations, instruction, 1, destination_width)?;

            let immediate_source = operation_immediate(instruction, instruction.op_kind(2));
            let immediate_width = operation_width(instruction, 2);
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate_source.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Rc::new(Mul {
        width: destination_width.signed(),
    }));
    operations.push(Rc::new(StoreRegister {
        width: destination_width,
        destination: destination_register,
    }));
    operations.push(Rc::new(Discard));

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

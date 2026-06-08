use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    add::Add, discard::Discard, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, rol::Rol, ror::Ror, sar::Sar, shl::Shl,
    shr::Shr, store_memory::StoreMemory, store_register::StoreRegister, sub::Sub, test::Test,
    xor::Xor, Encode,
};
use crate::vm::lifters::{is_immediate, operation_immediate, operation_width, unary};

pub enum Tail {
    Writeback,
    Discard,
}

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Add => binary(instruction, |width| Add { width }, Tail::Writeback),
        Mnemonic::Sub => binary(instruction, |width| Sub { width }, Tail::Writeback),
        Mnemonic::Shl => binary(instruction, |width| Shl { width }, Tail::Writeback),
        Mnemonic::Shr => binary(instruction, |width| Shr { width }, Tail::Writeback),
        Mnemonic::Sar => binary(instruction, |width| Sar { width }, Tail::Writeback),
        Mnemonic::Rol => binary(instruction, |width| Rol { width }, Tail::Writeback),
        Mnemonic::Ror => binary(instruction, |width| Ror { width }, Tail::Writeback),

        Mnemonic::Cmp => binary(instruction, |width| Sub { width }, Tail::Discard),
        Mnemonic::Test => binary(instruction, |width| Test { width }, Tail::Discard),

        Mnemonic::Inc => unary::encode(instruction, 1, false, false, |width| Add { width }),
        Mnemonic::Dec => unary::encode(instruction, 1, false, false, |width| Sub { width }),
        Mnemonic::Neg => unary::encode(instruction, 0, true, false, |width| Sub { width }),
        Mnemonic::Not => unary::encode(instruction, u64::MAX, false, true, |width| Xor { width }),

        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

pub fn binary<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
    tail: Tail,
) -> Option<Vec<Rc<dyn Encode>>> {
    let op0_kind = instruction.op0_kind();
    let op1_kind = instruction.op1_kind();

    let width = operation_width(instruction, op0_kind)?;

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match op0_kind {
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());
            operations.push(Rc::new(LoadRegister {
                width,
                source: destination_register,
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

    match op1_kind {
        OpKind::Register => {
            let source_width = VMWidth::from(instruction.op1_register());
            let source_register = VMReg::from(instruction.op1_register());
            operations.push(Rc::new(LoadRegister {
                width: source_width,
                source: source_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory { width }));
        }
        kind if is_immediate(kind) => {
            let immediate_source = operation_immediate(instruction, kind);
            let immediate_width = operation_width(instruction, kind)?;
            operations.push(Rc::new(LoadImmediate {
                width: immediate_width,
                source: immediate_source.to_le_bytes()[..immediate_width.size()].to_vec(),
            }));
        }
        _ => unreachable!(),
    }

    operations.push(Rc::new(make(width)));

    match tail {
        Tail::Writeback => match op0_kind {
            OpKind::Register => {
                let destination_register = VMReg::from(instruction.op0_register());
                operations.push(Rc::new(StoreRegister {
                    width,
                    destination: destination_register,
                }));
            }
            OpKind::Memory => {
                operations.push(Rc::new(LoadAddress {
                    source: VMMem::from(instruction),
                }));
                operations.push(Rc::new(StoreMemory { width }));
            }
            _ => unreachable!(),
        },
        Tail::Discard => {
            operations.push(Rc::new(Discard));
        }
    }

    Some(operations)
}

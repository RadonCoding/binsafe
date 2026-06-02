use iced_x86::{Code, Instruction, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_immediate::LoadImmediate, load_memory::LoadMemory,
    load_register::LoadRegister, store_memory::StoreMemory, store_register::StoreRegister, Encode,
};
use crate::vm::lifters::{operation_immediate, operation_width};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let code = instruction.code();

    match code {
        Code::Mov_r8_imm8
        | Code::Mov_r16_imm16
        | Code::Mov_r32_imm32
        | Code::Mov_r64_imm64
        | Code::Mov_rm8_imm8
        | Code::Mov_rm16_imm16
        | Code::Mov_rm32_imm32
        | Code::Mov_rm64_imm32 => {
            let destination_width = operation_width(instruction, instruction.op0_kind())?;

            let source_immediate = operation_immediate(instruction, instruction.op1_kind());
            let source_width = operation_width(instruction, instruction.op1_kind())?;

            let mut operations = Vec::<Rc<dyn Encode>>::new();
            operations.push(Rc::new(LoadImmediate {
                width: source_width,
                source: source_immediate.to_le_bytes()[..source_width.size()].to_vec(),
            }));

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_register = VMReg::from(instruction.op0_register());

                    operations.push(Rc::new(StoreRegister {
                        width: destination_width,
                        destination: destination_register,
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(StoreMemory {
                        width: destination_width,
                    }));
                }
                _ => return None,
            }

            Some(operations)
        }

        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
            r_rm(instruction)
        }

        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let source_width = VMWidth::from(instruction.op1_register());
            let source_register = VMReg::from(instruction.op1_register());

            let mut operations = Vec::<Rc<dyn Encode>>::new();
            operations.push(Rc::new(LoadRegister {
                width: source_width,
                source: source_register,
            }));

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_width = VMWidth::from(instruction.op0_register());
                    let destination_register = VMReg::from(instruction.op0_register());

                    operations.push(Rc::new(StoreRegister {
                        width: destination_width,
                        destination: destination_register,
                    }));
                }
                OpKind::Memory => {
                    operations.push(Rc::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }));
                    operations.push(Rc::new(StoreMemory {
                        width: source_width,
                    }));
                }
                _ => return None,
            }

            Some(operations)
        }
        _ => None,
    }
}

pub fn r_rm(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let destination_width = VMWidth::from(instruction.op0_register());
    let destination_register = VMReg::from(instruction.op0_register());

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op1_kind() {
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
            operations.push(Rc::new(LoadMemory {
                width: destination_width,
            }));
        }
        _ => return None,
    }

    operations.push(Rc::new(StoreRegister {
        width: destination_width,
        destination: destination_register,
    }));

    Some(operations)
}

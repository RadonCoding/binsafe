use iced_x86::{Code, Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    encode_immediate, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, store_memory::StoreMemory,
    store_register::StoreRegister, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let code = instruction.code();

    match code {
        Code::Mov_r8_imm8 | Code::Mov_r16_imm16 | Code::Mov_r32_imm32 | Code::Mov_r64_imm64 => {
            let (store_width, value) = match code {
                Code::Mov_r8_imm8 => (
                    VMWidth::from(instruction.op0_register()),
                    instruction.immediate8() as u64,
                ),
                Code::Mov_r16_imm16 => (VMWidth::Lower16, instruction.immediate16() as u64),
                Code::Mov_r32_imm32 => (VMWidth::Lower32, instruction.immediate32() as u64),
                Code::Mov_r64_imm64 => (VMWidth::Lower64, instruction.immediate64()),
                _ => unreachable!(),
            };
            let (load_width, size) = encode_immediate(value);
            Some(vec![
                Box::new(LoadImmediate {
                    width: load_width,
                    source: value.to_le_bytes()[..size].to_vec(),
                }),
                Box::new(StoreRegister {
                    width: store_width,
                    destination: VMReg::from(instruction.op0_register()),
                }),
            ])
        }

        Code::Mov_rm8_imm8 | Code::Mov_rm16_imm16 | Code::Mov_rm32_imm32 | Code::Mov_rm64_imm32
            if instruction.op0_kind() == OpKind::Register =>
        {
            let (store_width, value) = match code {
                Code::Mov_rm8_imm8 => (
                    VMWidth::from(instruction.op0_register()),
                    instruction.immediate8() as u64,
                ),
                Code::Mov_rm16_imm16 => (VMWidth::Lower16, instruction.immediate16() as u64),
                Code::Mov_rm32_imm32 => (VMWidth::Lower32, instruction.immediate32() as u64),
                Code::Mov_rm64_imm32 => (VMWidth::Lower64, instruction.immediate32to64() as u64),
                _ => unreachable!(),
            };
            let (load_width, size) = encode_immediate(value);
            Some(vec![
                Box::new(LoadImmediate {
                    width: load_width,
                    source: value.to_le_bytes()[..size].to_vec(),
                }),
                Box::new(StoreRegister {
                    width: store_width,
                    destination: VMReg::from(instruction.op0_register()),
                }),
            ])
        }

        Code::Mov_rm8_imm8 | Code::Mov_rm16_imm16 | Code::Mov_rm32_imm32 | Code::Mov_rm64_imm32 => {
            let (store_width, value) = match code {
                Code::Mov_rm8_imm8 => (VMWidth::Lower8, instruction.immediate8() as u64),
                Code::Mov_rm16_imm16 => (VMWidth::Lower16, instruction.immediate16() as u64),
                Code::Mov_rm32_imm32 => (VMWidth::Lower32, instruction.immediate32() as u64),
                Code::Mov_rm64_imm32 => (VMWidth::Lower64, instruction.immediate32to64() as u64),
                _ => unreachable!(),
            };
            let (load_width, size) = encode_immediate(value);
            Some(vec![
                Box::new(LoadImmediate {
                    width: load_width,
                    source: value.to_le_bytes()[..size].to_vec(),
                }),
                Box::new(LoadAddress {
                    source: VMMem::from(instruction),
                }),
                Box::new(StoreMemory { width: store_width }),
            ])
        }

        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
            r_rm(instruction)
        }

        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let source_register = instruction.op1_register();
            let source_width = VMWidth::from(source_register);
            let source = VMReg::from(source_register);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_register = instruction.op0_register();
                    Some(vec![
                        Box::new(LoadRegister {
                            width: source_width,
                            source,
                        }),
                        Box::new(StoreRegister {
                            width: VMWidth::from(destination_register),
                            destination: VMReg::from(destination_register),
                        }),
                    ])
                }
                OpKind::Memory => Some(vec![
                    Box::new(LoadRegister {
                        width: source_width,
                        source,
                    }),
                    Box::new(LoadAddress {
                        source: VMMem::from(instruction),
                    }),
                    Box::new(StoreMemory {
                        width: source_width,
                    }),
                ]),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn r_rm(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let destination_register = instruction.op0_register();
    let destination_width = VMWidth::from(destination_register);
    let destination = VMReg::from(destination_register);

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_register = instruction.op1_register();
            Some(vec![
                Box::new(LoadRegister {
                    width: VMWidth::from(source_register),
                    source: VMReg::from(source_register),
                }),
                Box::new(StoreRegister {
                    width: destination_width,
                    destination,
                }),
            ])
        }
        OpKind::Memory => Some(vec![
            Box::new(LoadAddress {
                source: VMMem::from(instruction),
            }),
            Box::new(LoadMemory {
                width: destination_width,
            }),
            Box::new(StoreRegister {
                width: destination_width,
                destination,
            }),
        ]),
        _ => None,
    }
}

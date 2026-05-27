use iced_x86::{Code, Instruction, OpKind};

use crate::vm::bytecode::{VMBits, VMMem, VMReg};
use crate::vm::encoders::{
    compose_2, compose_3, load_addr::LoadAddr, load_imm::LoadImm, load_mem::LoadMem,
    load_reg::LoadReg, store_mem::StoreMem, store_reg::StoreReg, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let code = instruction.code();

    match code {
        Code::Mov_r8_imm8 | Code::Mov_r16_imm16 | Code::Mov_r32_imm32 | Code::Mov_r64_imm64 => {
            let (width, value, size) = match code {
                Code::Mov_r8_imm8 => (
                    VMBits::from(instruction.op0_register()),
                    instruction.immediate8() as u64,
                    1,
                ),
                Code::Mov_r16_imm16 => (VMBits::Lower16, instruction.immediate16() as u64, 2),
                Code::Mov_r32_imm32 => (VMBits::Lower32, instruction.immediate32() as u64, 4),
                Code::Mov_r64_imm64 => (VMBits::Lower64, instruction.immediate64(), 8),
                _ => unreachable!(),
            };
            Some(compose_2(
                LoadImm {
                    width,
                    source: value.to_le_bytes()[..size].to_vec(),
                },
                StoreReg {
                    width,
                    destination: VMReg::from(instruction.op0_register()),
                },
            ))
        }

        Code::Mov_rm8_imm8 | Code::Mov_rm16_imm16 | Code::Mov_rm32_imm32 | Code::Mov_rm64_imm32
            if instruction.op0_kind() == OpKind::Register =>
        {
            let (width, value, size) = match code {
                Code::Mov_rm8_imm8 => (
                    VMBits::from(instruction.op0_register()),
                    instruction.immediate8() as u64,
                    1,
                ),
                Code::Mov_rm16_imm16 => (VMBits::Lower16, instruction.immediate16() as u64, 2),
                Code::Mov_rm32_imm32 => (VMBits::Lower32, instruction.immediate32() as u64, 4),
                Code::Mov_rm64_imm32 => (VMBits::Lower64, instruction.immediate32to64() as u64, 8),
                _ => unreachable!(),
            };
            Some(compose_2(
                LoadImm {
                    width,
                    source: value.to_le_bytes()[..size].to_vec(),
                },
                StoreReg {
                    width,
                    destination: VMReg::from(instruction.op0_register()),
                },
            ))
        }

        Code::Mov_rm8_imm8 | Code::Mov_rm16_imm16 | Code::Mov_rm32_imm32 | Code::Mov_rm64_imm32 => {
            let (width, value, size) = match code {
                Code::Mov_rm8_imm8 => (VMBits::Lower8, instruction.immediate8() as u64, 1),
                Code::Mov_rm16_imm16 => (VMBits::Lower16, instruction.immediate16() as u64, 2),
                Code::Mov_rm32_imm32 => (VMBits::Lower32, instruction.immediate32() as u64, 4),
                Code::Mov_rm64_imm32 => (VMBits::Lower64, instruction.immediate32to64() as u64, 8),
                _ => unreachable!(),
            };
            Some(compose_3(
                LoadImm {
                    width,
                    source: value.to_le_bytes()[..size].to_vec(),
                },
                LoadAddr {
                    source: VMMem::from(instruction),
                },
                StoreMem { width },
            ))
        }

        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
            let destination_register = instruction.op0_register();
            let destination_width = VMBits::from(destination_register);
            let destination = VMReg::from(destination_register);

            match instruction.op1_kind() {
                OpKind::Register => {
                    let source_register = instruction.op1_register();
                    Some(compose_2(
                        LoadReg {
                            width: VMBits::from(source_register),
                            source: VMReg::from(source_register),
                        },
                        StoreReg {
                            width: destination_width,
                            destination,
                        },
                    ))
                }
                OpKind::Memory => Some(compose_3(
                    LoadAddr {
                        source: VMMem::from(instruction),
                    },
                    LoadMem {
                        width: destination_width,
                    },
                    StoreReg {
                        width: destination_width,
                        destination,
                    },
                )),
                _ => None,
            }
        }

        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let source_register = instruction.op1_register();
            let source_width = VMBits::from(source_register);
            let source = VMReg::from(source_register);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let destination_register = instruction.op0_register();
                    Some(compose_2(
                        LoadReg {
                            width: source_width,
                            source,
                        },
                        StoreReg {
                            width: VMBits::from(destination_register),
                            destination: VMReg::from(destination_register),
                        },
                    ))
                }
                OpKind::Memory => Some(compose_3(
                    LoadReg {
                        width: source_width,
                        source,
                    },
                    LoadAddr {
                        source: VMMem::from(instruction),
                    },
                    StoreMem {
                        width: source_width,
                    },
                )),
                _ => None,
            }
        }
        _ => None,
    }
}

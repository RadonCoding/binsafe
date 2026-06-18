#[cfg(debug_assertions)]
use std::collections::HashSet;

use crate::engine::Engine;
use crate::protections::Protection;
use iced_x86::code_asm::*;
use iced_x86::{Instruction, Mnemonic, OpKind};
use logger::info;
use rand::Rng;

#[derive(Default)]
pub struct Mutation;

impl Mutation {
    fn has_dead_flags(&self, instructions: &[Instruction]) -> bool {
        let written_flags = instructions[0].rflags_written();

        for i in 1..instructions.len() {
            let instruction = &instructions[i];

            if (instruction.rflags_read() & written_flags) != 0 {
                return false;
            }

            if (instruction.rflags_written() & written_flags) == written_flags {
                return true;
            }
        }

        true
    }
}

impl Protection for Mutation {
    fn initialize(&mut self, _engine: &mut Engine) {}

    fn apply(&self, engine: &mut Engine) {
        let mut rng = rand::thread_rng();

        let mut mutated = 0usize;

        #[cfg(debug_assertions)]
        let mut logged = HashSet::new();

        for i in 0..engine.blocks.len() {
            let block = &engine.blocks[i];

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();

            let mut processed = false;

            for (index, instruction) in block.instructions.iter().enumerate() {
                let dead_flags = self.has_dead_flags(&block.instructions[index..]);
                let mnemonic = instruction.mnemonic();
                let raw = instruction.op0_register();

                #[cfg(debug_assertions)]
                let asm_index = asm.instructions().len();

                let mut mutated = false;

                'mutation: {
                    // MOV reg, imm -> MOV reg, (imm^key); XOR reg, key
                    if mnemonic == Mnemonic::Mov
                        && instruction.try_immediate(1).is_ok()
                        && dead_flags
                    {
                        let imm = instruction.immediate(1);
                        let key = rng.gen::<u32>();

                        if let Some(reg) = get_gpr64(raw) {
                            asm.mov(reg, imm ^ (key as u64)).unwrap();
                            asm.xor(reg, key as i32).unwrap();
                            mutated = true;
                            break 'mutation;
                        } else if let Some(reg) = get_gpr32(raw) {
                            asm.mov(reg, (imm as u32) ^ key).unwrap();
                            asm.xor(reg, key as i32).unwrap();
                            mutated = true;
                            break 'mutation;
                        }
                    }

                    // ADD/SUB reg, imm -> SUB/ADD reg, -imm
                    if (mnemonic == Mnemonic::Add || mnemonic == Mnemonic::Sub)
                        && instruction.op1_kind() == OpKind::Immediate32
                        && dead_flags
                    {
                        let imm = instruction.immediate(1) as i32;
                        let addition = mnemonic == Mnemonic::Add;

                        if let Some(reg) = get_gpr64(raw) {
                            if addition {
                                asm.sub(reg, -imm).unwrap();
                            } else {
                                asm.add(reg, -imm).unwrap();
                            }
                            mutated = true;
                            break 'mutation;
                        } else if let Some(reg) = get_gpr32(raw) {
                            if addition {
                                asm.sub(reg, -imm).unwrap();
                            } else {
                                asm.add(reg, -imm).unwrap();
                            }
                            mutated = true;
                            break 'mutation;
                        }
                    }

                    // XOR reg, imm -> NOT reg; XOR reg, !imm
                    if mnemonic == Mnemonic::Xor
                        && instruction.op1_kind() == OpKind::Immediate32
                        && dead_flags
                    {
                        let imm = instruction.immediate(1) as i32;

                        if let Some(reg) = get_gpr64(raw) {
                            asm.not(reg).unwrap();
                            asm.xor(reg, !imm).unwrap();
                            mutated = true;
                            break 'mutation;
                        } else if let Some(reg) = get_gpr32(raw) {
                            asm.not(reg).unwrap();
                            asm.xor(reg, !imm).unwrap();
                            mutated = true;
                            break 'mutation;
                        }
                    }

                    // AND reg, imm -> NOT reg; OR reg, !imm; NOT reg
                    if mnemonic == Mnemonic::And
                        && instruction.op1_kind() == OpKind::Immediate32
                        && dead_flags
                    {
                        let imm = instruction.immediate(1) as i32;

                        if let Some(reg) = get_gpr64(raw) {
                            asm.not(reg).unwrap();
                            asm.or(reg, !imm).unwrap();
                            asm.not(reg).unwrap();
                            mutated = true;
                            break 'mutation;
                        } else if let Some(reg) = get_gpr32(raw) {
                            asm.not(reg).unwrap();
                            asm.or(reg, !imm).unwrap();
                            asm.not(reg).unwrap();
                            mutated = true;
                            break 'mutation;
                        }
                    }

                    // OR reg, imm -> NOT reg; AND reg, !imm; NOT reg
                    if mnemonic == Mnemonic::Or
                        && instruction.op1_kind() == OpKind::Immediate32
                        && dead_flags
                    {
                        let imm = instruction.immediate(1) as i32;

                        if let Some(reg) = get_gpr64(raw) {
                            asm.not(reg).unwrap();
                            asm.and(reg, !imm).unwrap();
                            asm.not(reg).unwrap();
                            mutated = true;
                            break 'mutation;
                        } else if let Some(reg) = get_gpr32(raw) {
                            asm.not(reg).unwrap();
                            asm.and(reg, !imm).unwrap();
                            asm.not(reg).unwrap();
                            mutated = true;
                            break 'mutation;
                        }
                    }

                    // NEG reg -> NOT reg; ADD reg, 1
                    if mnemonic == Mnemonic::Neg && dead_flags {
                        if let Some(reg) = get_gpr64(raw) {
                            asm.not(reg).unwrap();
                            asm.add(reg, 1).unwrap();
                            mutated = true;
                            break 'mutation;
                        } else if let Some(reg) = get_gpr32(raw) {
                            asm.not(reg).unwrap();
                            asm.add(reg, 1).unwrap();
                            mutated = true;
                            break 'mutation;
                        }
                    }

                    // SUB reg, reg -> XOR reg, reg
                    if mnemonic == Mnemonic::Sub
                        && instruction.op0_kind() == OpKind::Register
                        && instruction.op1_kind() == OpKind::Register
                    {
                        if raw == instruction.op1_register() && dead_flags {
                            if let Some(reg) = get_gpr64(raw) {
                                asm.xor(reg, reg).unwrap();
                                mutated = true;
                                break 'mutation;
                            } else if let Some(reg) = get_gpr32(raw) {
                                asm.xor(reg, reg).unwrap();
                                mutated = true;
                                break 'mutation;
                            }
                        }
                    }

                    asm.add_instruction(*instruction).unwrap();
                }

                if mutated {
                    processed = true;

                    #[cfg(debug_assertions)]
                    {
                        use logger::debug;

                        if logged.insert(instruction.code()) {
                            let after = asm.instructions()[asm_index..]
                                .iter()
                                .map(|i| format!("    {}", i))
                                .collect::<Vec<String>>()
                                .join("\n");
                            debug!(
                                "MUTATED @ 0x{:08X}:\n  BEFORE: {}\n  AFTER:\n{}",
                                instruction.ip(),
                                instruction,
                                after
                            );
                        }
                    }
                }
            }

            if processed {
                let bytes = asm.assemble(block.rva as u64).unwrap();

                if bytes.len() <= block.size {
                    engine.replace(i, &bytes);
                    mutated += 1;
                }
            }
        }

        let total = engine.blocks.len();
        let percentage = (mutated as f64 / total.max(1) as f64) * 100.0;

        info!("MUTATED: {}/{} blocks ({:.2}%)", mutated, total, percentage);
    }
}

use crate::engine::Engine;
use crate::protections::Protection;
use iced_x86::code_asm::*;
use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use logger::info;
use rand::Rng;

#[derive(Default)]
pub struct Mutation;

impl Mutation {
    fn resolve_gpr32(&self, reg: Register) -> Option<AsmRegister32> {
        use iced_x86::code_asm::registers::gpr32::*;
        match reg {
            Register::EAX => Some(eax),
            Register::ECX => Some(ecx),
            Register::EDX => Some(edx),
            Register::EBX => Some(ebx),
            Register::ESP => Some(esp),
            Register::EBP => Some(ebp),
            Register::ESI => Some(esi),
            Register::EDI => Some(edi),
            Register::R8D => Some(r8d),
            Register::R9D => Some(r9d),
            Register::R10D => Some(r10d),
            Register::R11D => Some(r11d),
            Register::R12D => Some(r12d),
            Register::R13D => Some(r13d),
            Register::R14D => Some(r14d),
            Register::R15D => Some(r15d),
            _ => None,
        }
    }

    fn resolve_gpr64(&self, reg: Register) -> Option<AsmRegister64> {
        use iced_x86::code_asm::registers::gpr64::*;
        match reg {
            Register::RAX => Some(rax),
            Register::RCX => Some(rcx),
            Register::RDX => Some(rdx),
            Register::RBX => Some(rbx),
            Register::RSP => Some(rsp),
            Register::RBP => Some(rbp),
            Register::RSI => Some(rsi),
            Register::RDI => Some(rdi),
            Register::R8 => Some(r8),
            Register::R9 => Some(r9),
            Register::R10 => Some(r10),
            Register::R11 => Some(r11),
            Register::R12 => Some(r12),
            Register::R13 => Some(r13),
            Register::R14 => Some(r14),
            Register::R15 => Some(r15),
            _ => None,
        }
    }

    fn has_dead_flags(&self, instructions: &[Instruction], start_index: usize) -> bool {
        for i in start_index..instructions.len() {
            let instr = &instructions[i];
            match instr.mnemonic() {
                Mnemonic::Jb
                | Mnemonic::Jae
                | Mnemonic::Je
                | Mnemonic::Jne
                | Mnemonic::Jbe
                | Mnemonic::Ja
                | Mnemonic::Js
                | Mnemonic::Jns
                | Mnemonic::Jp
                | Mnemonic::Jnp
                | Mnemonic::Jl
                | Mnemonic::Jge
                | Mnemonic::Jle
                | Mnemonic::Jg
                | Mnemonic::Cmovb
                | Mnemonic::Cmove
                | Mnemonic::Sete
                | Mnemonic::Setne
                | Mnemonic::Adc
                | Mnemonic::Sbb => return false,
                Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Xor
                | Mnemonic::Or
                | Mnemonic::And
                | Mnemonic::Cmp
                | Mnemonic::Test => return true,
                _ => {}
            }
        }
        true
    }
}

impl Protection for Mutation {
    fn initialize(&mut self, _engine: &mut Engine) {}

    fn apply(&self, engine: &mut Engine) {
        let mut rng = rand::thread_rng();

        for i in 0..engine.blocks.len() {
            let block = &engine.blocks[i];

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();

            let mut mutated = false;

            for (index, instruction) in block.instructions.iter().enumerate() {
                let dead_flags = self.has_dead_flags(&block.instructions, index + 1);
                let mnemonic = instruction.mnemonic();
                let raw = instruction.op0_register();

                // MOV reg, imm -> MOV reg, (imm^key); XOR reg, key
                if mnemonic == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1);
                    let key = rng.gen::<u32>();

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.mov(reg, imm ^ (key as u64)).unwrap();
                        asm.xor(reg, key as i32).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.mov(reg, (imm as u32) ^ key).unwrap();
                        asm.xor(reg, key as i32).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // ADD/SUB reg, imm -> SUB/ADD reg, -imm
                if (mnemonic == Mnemonic::Add || mnemonic == Mnemonic::Sub)
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;
                    let addition = mnemonic == Mnemonic::Add;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        if addition {
                            asm.sub(reg, -imm).unwrap();
                        } else {
                            asm.add(reg, -imm).unwrap();
                        }
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        if addition {
                            asm.sub(reg, -imm).unwrap();
                        } else {
                            asm.add(reg, -imm).unwrap();
                        }
                        mutated = true;
                        continue;
                    }
                }

                // XOR reg, imm -> NOT reg; XOR reg, !imm
                if mnemonic == Mnemonic::Xor
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.xor(reg, !imm).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.xor(reg, !imm).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // AND reg, imm -> NOT reg; OR reg, !imm; NOT reg
                if mnemonic == Mnemonic::And
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.or(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.or(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // OR reg, imm -> NOT reg; AND reg, !imm; NOT reg
                if mnemonic == Mnemonic::Or
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.and(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.and(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // NEG reg -> NOT reg; ADD reg, 1
                if mnemonic == Mnemonic::Neg && dead_flags {
                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.add(reg, 1).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.add(reg, 1).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // SUB reg, reg -> XOR reg, reg
                if mnemonic == Mnemonic::Sub
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                {
                    if raw == instruction.op1_register() && dead_flags {
                        if let Some(reg) = self.resolve_gpr64(raw) {
                            asm.xor(reg, reg).unwrap();
                            mutated = true;
                            continue;
                        } else if let Some(reg) = self.resolve_gpr32(raw) {
                            asm.xor(reg, reg).unwrap();
                            mutated = true;
                            continue;
                        }
                    }
                }

                asm.add_instruction(*instruction).unwrap();
            }

            if mutated {
                let bytes = asm.assemble(block.rva as u64).unwrap();

                if bytes.len() <= block.size {
                    info!("PRE-MUTATION:\n{}", engine.blocks[i]);
                    engine.replace(i, &bytes);
                    info!("POST-MUTATION:\n{}", engine.blocks[i]);
                }
            }
        }
    }
}

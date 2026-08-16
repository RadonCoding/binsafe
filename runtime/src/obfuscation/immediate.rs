use std::collections::HashSet;

use iced_x86::{
    code_asm::{get_gpr32, get_gpr64, get_gpr8, AsmRegister8, CodeAssembler},
    Code, FlowControl, Instruction, InstructionInfoFactory, OpAccess, OpCodeOperandKind, OpKind,
    Register, RflagsBits,
};
use rand::Rng;

use crate::obfuscation::{flags, scratch, sized, Operation};

#[derive(Clone, Copy)]
enum Condition {
    Carry,
    Overflow,
    Sign,
    Zero,
    Parity,
}

pub fn obfuscate<R: Rng>(
    instructions: &[Instruction],
    asm: &mut CodeAssembler,
    rng: &mut R,
) -> Option<usize> {
    let instruction = &instructions[0];

    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(instruction);

    let registers = info
        .used_registers()
        .iter()
        .map(|r| r.register().full_register())
        .collect::<Vec<Register>>();

    if registers.contains(&Register::RSP) {
        return None;
    }

    let count = instruction.op_count();

    let immediate = (0..count).find(|&i| is_immediate(instruction.op_kind(i)));
    let memory = (0..count).find(|&i| instruction.op_kind(i) == OpKind::Memory);

    let (value, size, memory) = if let Some(i) = immediate {
        if !matches!(instruction.op0_kind(), OpKind::Register) {
            return None;
        }

        (
            instruction.immediate(i),
            instruction.op_register(0).size(),
            false,
        )
    } else if memory.is_some() {
        if instruction.memory_base() == Register::None || instruction.memory_base() == Register::RIP
        {
            return None;
        }

        if instruction.memory_index() != Register::None {
            return None;
        }

        let displacement = instruction.memory_displacement64();

        let size = if displacement <= 0xFF {
            1
        } else if displacement <= 0xFFFF {
            2
        } else if displacement <= 0xFFFF_FFFF {
            4
        } else {
            8
        };

        (displacement, size, true)
    } else {
        return None;
    };

    let mut excluded = registers.clone();
    excluded.push(Register::RSP);

    let (register1, preserve1) = match deadregister(instructions, &excluded) {
        Some(register) => (register, false),
        None => (scratch(&excluded, rng), true),
    };

    excluded.push(register1);

    let (register2, preserve2) = if size == 8 {
        match deadregister(instructions, &excluded) {
            Some(register) => (register, false),
            None => (scratch(&excluded, rng), true),
        }
    } else {
        (register1, false)
    };

    let rewritten = if memory {
        rewrite_memory(instruction, register1)?
    } else {
        rewrite_immediate(instruction, register1)?
    };

    let reads = instruction.rflags_read() != RflagsBits::NONE;
    let writes = instruction.rflags_written() != RflagsBits::NONE;
    let dead = deadflags(instructions);

    if preserve1 {
        asm.push(get_gpr64(register1).unwrap()).unwrap();
    }

    if preserve2 {
        asm.push(get_gpr64(register2).unwrap()).unwrap();
    }

    if !writes && !dead {
        asm.pushfq().unwrap();
    }

    if reads {
        asm.pushfq().unwrap();
    }

    reconstruct(value, size, register1, register2, asm, rng);

    if reads {
        asm.popfq().unwrap();
    }

    asm.add_instruction(rewritten).unwrap();

    if !writes && !dead {
        asm.popfq().unwrap();
    }

    if preserve2 {
        asm.pop(get_gpr64(register2).unwrap()).unwrap();
    }

    if preserve1 {
        asm.pop(get_gpr64(register1).unwrap()).unwrap();
    }

    Some(1)
}

fn deadregister(instructions: &[Instruction], excluded: &[Register]) -> Option<Register> {
    let mut factory = InstructionInfoFactory::new();
    let mut reads = HashSet::new();

    for instruction in instructions.iter().skip(1) {
        if instruction.flow_control() != FlowControl::Next {
            break;
        }

        let info = factory.info(instruction);

        for register in info.used_registers() {
            let access = register.access();

            let register = register.register().full_register();

            if !register.is_gpr() {
                continue;
            }

            if excluded.contains(&register) {
                continue;
            }

            match access {
                OpAccess::Read
                | OpAccess::CondRead
                | OpAccess::ReadWrite
                | OpAccess::ReadCondWrite => {
                    reads.insert(register);
                }
                OpAccess::Write => {
                    if !reads.contains(&register) {
                        return Some(register);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn deadflags(instructions: &[Instruction]) -> bool {
    // This is a potentially unsafe implementation which assumes that after branches the flags are dead.
    for instruction in instructions.iter().skip(1) {
        if instruction.rflags_read() != RflagsBits::NONE {
            return false;
        }

        if instruction.rflags_modified() != RflagsBits::NONE {
            return true;
        }
    }
    true
}

fn rewrite_immediate(instruction: &Instruction, scratch: Register) -> Option<Instruction> {
    let mnemonic = instruction.mnemonic();
    let count = instruction.op_count();
    let index = (0..count).find(|&i| is_immediate(instruction.op_kind(i)))?;
    let destination = instruction.op_register(0);

    let kind = match destination.size() {
        1 => OpCodeOperandKind::r8_reg,
        2 => OpCodeOperandKind::r16_reg,
        4 => OpCodeOperandKind::r32_reg,
        8 => OpCodeOperandKind::r64_reg,
        _ => return None,
    };

    let code = Code::values().find(|&c| {
        let info = c.op_code();

        info.mnemonic() == mnemonic && info.op_count() == count && info.op_kind(index) == kind
    })?;

    let scratch = sized(scratch, destination.size())?;

    Instruction::with2(code, destination, scratch).ok()
}

fn rewrite_memory(instruction: &Instruction, scratch: Register) -> Option<Instruction> {
    let mut rewritten = instruction.clone();

    rewritten.set_ip(0);

    rewritten.set_memory_index(sized(scratch, 8)?);
    rewritten.set_memory_index_scale(1);
    rewritten.set_memory_displacement64(0);
    rewritten.set_memory_displ_size(0);

    Some(rewritten)
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn setcc(assembler: &mut CodeAssembler, destination: AsmRegister8, condition: Condition) {
    match condition {
        Condition::Carry => assembler.setc(destination),
        Condition::Overflow => assembler.seto(destination),
        Condition::Sign => assembler.sets(destination),
        Condition::Zero => assembler.setz(destination),
        Condition::Parity => assembler.setp(destination),
    }
    .unwrap();
}

fn reconstruct(
    immediate: u64,
    size: usize,
    register1: Register,
    register2: Register,
    assembler: &mut CodeAssembler,
    generator: &mut impl Rng,
) {
    let r1_8 = get_gpr8(sized(register1, 1).unwrap()).unwrap();
    let r1_32 = get_gpr32(sized(register1, 4).unwrap()).unwrap();
    let r1_64 = get_gpr64(sized(register1, 8).unwrap()).unwrap();

    let r2_64 = get_gpr64(sized(register2, 8).unwrap()).unwrap();

    let operation = Operation::random(generator);

    let limit = match size {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        8 => u64::MAX,
        _ => unreachable!(),
    };

    let first = generator.gen::<u32>() as u64;
    let second = generator.gen::<u32>() as u64;

    let flags = flags(operation, first, second, 4);

    let options = [
        (Condition::Carry, flags.carry),
        (Condition::Overflow, flags.overflow),
        (Condition::Sign, flags.sign),
        (Condition::Zero, flags.zero),
        (Condition::Parity, flags.parity),
    ];

    let &(condition, flag) = &options[generator.gen_range(0..options.len())];

    let arithmetic = match operation {
        Operation::Add => first.wrapping_add(second) & 0xFFFF_FFFF,
        Operation::Sub => first.wrapping_sub(second) & 0xFFFF_FFFF,
        Operation::Xor => (first ^ second) & 0xFFFF_FFFF,
    };

    let state = (arithmetic & 0xFFFF_FF00) | flag;

    let state = state.wrapping_mul(state);

    assembler.mov(r1_32, first as i32).unwrap();

    match operation {
        Operation::Add => assembler.add(r1_32, second as i32),
        Operation::Sub => assembler.sub(r1_32, second as i32),
        Operation::Xor => assembler.xor(r1_32, second as i32),
    }
    .unwrap();

    setcc(assembler, r1_8, condition);

    if size == 8 {
        assembler.imul_2(r1_64, r1_64).unwrap();

        let xor1 = generator.gen::<u64>();
        let noise = generator.gen::<u64>();
        let xor2 = immediate ^ state ^ xor1 ^ noise;
        let xor3 = noise;

        assembler.mov(r2_64, xor1 as i64).unwrap();
        assembler.xor(r1_64, r2_64).unwrap();
        assembler.mov(r2_64, xor2 as i64).unwrap();
        assembler.xor(r1_64, r2_64).unwrap();
        assembler.mov(r2_64, xor3 as i64).unwrap();
        assembler.xor(r1_64, r2_64).unwrap();
    } else {
        assembler.imul_2(r1_32, r1_32).unwrap();

        let xor1 = generator.gen::<u32>();
        let xor2 = ((immediate & limit) as u32) ^ (state as u32) ^ xor1;

        assembler.xor(r1_32, xor1 as i32).unwrap();
        assembler.xor(r1_32, xor2 as i32).unwrap();
    }
}

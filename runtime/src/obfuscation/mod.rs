use iced_x86::{
    code_asm::{CodeAssembler, CodeAssemblerResult},
    BlockEncoderOptions, Instruction, Register,
};
use logger::debug;
use rand::{seq::SliceRandom, Rng};

mod immediate;

#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Add,
    Sub,
    Xor,
}

impl Operation {
    pub fn random(rng: &mut impl Rng) -> Self {
        match rng.gen_range(0..3) {
            0 => Operation::Add,
            1 => Operation::Sub,
            _ => Operation::Xor,
        }
    }
}

pub struct Flags {
    pub carry: u64,
    pub overflow: u64,
    pub sign: u64,
    pub zero: u64,
    pub parity: u64,
}

pub fn obfuscate(asm: &mut CodeAssembler, ip: u64) -> (Vec<Instruction>, CodeAssemblerResult) {
    let mut rng = rand::thread_rng();

    let mut instructions = asm.take_instructions();

    let mut chunks = Vec::with_capacity(instructions.len());

    let mut i = instructions.len();

    while i > 0 {
        i -= 1;

        let mut asm = CodeAssembler::new(64).unwrap();

        let ip = instructions[i].ip();
        instructions[i].set_ip(0);

        let consumed =
            None.or_else(|| immediate::obfuscate(&instructions[i..], &mut asm, &mut rng));

        if let Some(consumed) = consumed {
            let mut chunk = asm.take_instructions();

            if let Some(instruction) = chunk.first_mut() {
                instruction.set_ip(ip);
            }

            debug!("OBFUSCATED: {}", instructions[i]);

            for instruction in &chunk {
                debug!("{}{instruction}", " ".repeat(4));
            }

            chunks.push((i, chunk));

            i = i.saturating_sub(consumed - 1);
        } else {
            let mut instruction = instructions[i].clone();
            instruction.set_ip(ip);
            chunks.push((i, vec![instruction]));
        }
    }

    chunks.reverse();

    let mut obfuscated = Vec::new();
    let mut map = vec![0; instructions.len()];

    for (i, chunk) in chunks {
        map[i] = obfuscated.len();
        obfuscated.extend(chunk);
    }

    let mut asm = CodeAssembler::new(64).unwrap();

    for &instruction in &obfuscated {
        asm.add_instruction(instruction).unwrap();
    }

    let mut result = asm
        .assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
        .unwrap();

    let offsets = result.inner.new_instruction_offsets.clone();

    result.inner.new_instruction_offsets = map.iter().map(|&slot| offsets[slot]).collect();

    (obfuscated, result)
}

pub fn flags(operation: Operation, left: u64, right: u64, size: usize) -> Flags {
    let mask = match size {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        8 => u64::MAX,
        _ => unreachable!(),
    };

    let left = left & mask;
    let right = right & mask;

    let result = match operation {
        Operation::Add => left.wrapping_add(right) & mask,
        Operation::Sub => left.wrapping_sub(right) & mask,
        Operation::Xor => left ^ right,
    };

    let bit = size * 8 - 1;

    let (carry, overflow) = match operation {
        Operation::Xor => (0, 0),
        Operation::Add => (
            ((left as u128 + right as u128) > mask as u128) as u64,
            ((!(left ^ right) & (left ^ result)) >> bit) & 1,
        ),
        Operation::Sub => (
            (left < right) as u64,
            (((left ^ right) & (left ^ result)) >> bit) & 1,
        ),
    };

    Flags {
        carry,
        overflow,
        sign: (result >> bit) & 1,
        zero: (result == 0) as u64,
        parity: ((result as u8).count_ones() % 2 == 0) as u64,
    }
}

fn sized(register: Register, size: usize) -> Option<Register> {
    let number = register.number() as usize;

    match size {
        1 => match number {
            0 => Some(Register::AL),
            1 => Some(Register::CL),
            2 => Some(Register::DL),
            3 => Some(Register::BL),
            4 => Some(Register::SPL),
            5 => Some(Register::BPL),
            6 => Some(Register::SIL),
            7 => Some(Register::DIL),
            8 => Some(Register::R8L),
            9 => Some(Register::R9L),
            10 => Some(Register::R10L),
            11 => Some(Register::R11L),
            12 => Some(Register::R12L),
            13 => Some(Register::R13L),
            14 => Some(Register::R14L),
            15 => Some(Register::R15L),
            _ => None,
        },
        2 => {
            let base = register.full_register().number() as u32;
            Some(Register::AX + base)
        }
        4 => {
            let base = register.full_register().number() as u32;
            Some(Register::EAX + base)
        }
        8 => {
            let base = register.full_register().number() as u32;
            Some(Register::RAX + base)
        }
        _ => None,
    }
}

pub fn scratch(excluded: &[Register], rng: &mut impl Rng) -> Register {
    const REGISTERS: [Register; 12] = [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];

    let excluded = excluded
        .iter()
        .map(|r| r.full_register())
        .collect::<Vec<Register>>();

    let registers = REGISTERS
        .iter()
        .cloned()
        .filter(|r| !excluded.contains(r))
        .collect::<Vec<Register>>();

    *registers.choose(rng).unwrap()
}

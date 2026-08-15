use iced_x86::{
    code_asm::{get_gpr16, get_gpr32, get_gpr64, get_gpr8, AsmRegister8, CodeAssembler},
    Code, Instruction, OpCodeOperandKind, OpKind, Register, RflagsBits,
};
use logger::debug;
use rand::Rng;

pub fn obfuscate(instructions: &[Instruction]) -> (Vec<Instruction>, Vec<usize>) {
    let mut asm = CodeAssembler::new(64).unwrap();

    let mut map = Vec::with_capacity(instructions.len());

    let mut mapping = Vec::new();

    let mut rng = rand::thread_rng();

    for &instruction in instructions {
        let before = asm.instructions().len();

        map.push(before);

        let ip = instruction.ip();

        if expand(&instruction, &mut asm, &mut rng) {
            let after = asm.instructions().len();

            mapping.push((before, ip));

            mapping.extend((before + 1..after - 1).map(|index| (index, 0)));

            debug!("OBFUSCATED: {instruction}");

            for instruction in &asm.instructions()[before..] {
                debug!("{}{instruction}", " ".repeat(4));
            }
        } else {
            asm.add_instruction(instruction).unwrap();
        }
    }

    let mut obfuscated = asm.take_instructions();

    for (i, ip) in mapping {
        obfuscated[i].set_ip(ip);
    }

    (obfuscated, map)
}

fn expand<R: Rng>(instruction: &Instruction, asm: &mut CodeAssembler, rng: &mut R) -> bool {
    let count = instruction.op_count();

    let Some(index) = (0..count).find(|&i| is_immediate(instruction.op_kind(i))) else {
        return false;
    };

    let destination = instruction.op_register(0);

    if !matches!(instruction.op0_kind(), OpKind::Register)
        || destination.full_register() == Register::RSP
    {
        return false;
    }

    let (scratch, other) = helpers(destination);
    let Some(rewritten) = rewrite(instruction, scratch) else {
        return false;
    };

    let immediate = instruction.immediate(index);
    let reads = instruction.rflags_read() != RflagsBits::NONE;
    let writes = instruction.rflags_written() != RflagsBits::NONE;

    asm.push(get_gpr64(scratch).unwrap()).unwrap();
    asm.push(get_gpr64(other).unwrap()).unwrap();

    if !writes {
        asm.pushfq().unwrap();
    }
    if reads {
        asm.pushfq().unwrap();
    }

    reconstruct(immediate, destination.size(), scratch, other, asm, rng);

    if reads {
        asm.popfq().unwrap();
    }

    asm.add_instruction(rewritten).unwrap();

    if !writes {
        asm.popfq().unwrap();
    }

    asm.pop(get_gpr64(other).unwrap()).unwrap();
    asm.pop(get_gpr64(scratch).unwrap()).unwrap();

    true
}

fn rewrite(instruction: &Instruction, scratch: Register) -> Option<Instruction> {
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

fn sized(register: Register, size: usize) -> Option<Register> {
    let number = register.number() as u32;

    match size {
        1 => Some(Register::AL + number),
        2 => Some(Register::AX + number),
        4 => Some(Register::EAX + number),
        8 => Some(Register::RAX + number),
        _ => None,
    }
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

#[derive(Clone, Copy)]
enum Operation {
    Add,
    Sub,
    Xor,
}

#[derive(Clone, Copy)]
enum Condition {
    Carry,
    Overflow,
    Sign,
    Zero,
    Parity,
}

struct Flags {
    carry: u64,
    overflow: u64,
    sign: u64,
    zero: u64,
    parity: u64,
}

fn random_operation(rng: &mut impl Rng) -> Operation {
    match rng.gen_range(0..3) {
        0 => Operation::Add,
        1 => Operation::Sub,
        _ => Operation::Xor,
    }
}

fn compute_flags(operation: Operation, left: u64, right: u64, size: usize) -> Flags {
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

fn emit(
    asm: &mut CodeAssembler,
    operation: Operation,
    destination: Register,
    source: Register,
    size: usize,
) {
    match size {
        1 => {
            let destination = get_gpr8(sized(destination, 1).unwrap()).unwrap();
            let source = get_gpr8(sized(source, 1).unwrap()).unwrap();

            match operation {
                Operation::Add => asm.add(destination, source),
                Operation::Sub => asm.sub(destination, source),
                Operation::Xor => asm.xor(destination, source),
            }
        }
        2 => {
            let destination = get_gpr16(sized(destination, 2).unwrap()).unwrap();
            let source = get_gpr16(sized(source, 2).unwrap()).unwrap();

            match operation {
                Operation::Add => asm.add(destination, source),
                Operation::Sub => asm.sub(destination, source),
                Operation::Xor => asm.xor(destination, source),
            }
        }
        4 => {
            let destination = get_gpr32(sized(destination, 4).unwrap()).unwrap();
            let source = get_gpr32(sized(source, 4).unwrap()).unwrap();

            match operation {
                Operation::Add => asm.add(destination, source),
                Operation::Sub => asm.sub(destination, source),
                Operation::Xor => asm.xor(destination, source),
            }
        }
        8 => {
            let destination = get_gpr64(sized(destination, 8).unwrap()).unwrap();
            let source = get_gpr64(sized(source, 8).unwrap()).unwrap();

            match operation {
                Operation::Add => asm.add(destination, source),
                Operation::Sub => asm.sub(destination, source),
                Operation::Xor => asm.xor(destination, source),
            }
        }
        _ => unreachable!(),
    }
    .unwrap();
}

fn setcc(asm: &mut CodeAssembler, destination: AsmRegister8, condition: Condition) {
    match condition {
        Condition::Carry => asm.setc(destination),
        Condition::Overflow => asm.seto(destination),
        Condition::Sign => asm.sets(destination),
        Condition::Zero => asm.setz(destination),
        Condition::Parity => asm.setp(destination),
    }
    .unwrap();
}

fn reconstruct(
    immediate: u64,
    size: usize,
    scratch: Register,
    other: Register,
    asm: &mut CodeAssembler,
    rng: &mut impl Rng,
) {
    let left = get_gpr64(sized(scratch, 8).unwrap()).unwrap();
    let right = get_gpr64(sized(other, 8).unwrap()).unwrap();
    let byte = get_gpr8(sized(other, 1).unwrap()).unwrap();

    let operation = random_operation(rng);

    let limit = match size {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        8 => u64::MAX,
        _ => unreachable!(),
    };

    let first = rng.gen::<u64>() & limit;
    let second = rng.gen::<u64>() & limit;

    let flags = compute_flags(operation, first, second, size);

    let values = [
        (Condition::Carry, flags.carry),
        (Condition::Overflow, flags.overflow),
        (Condition::Sign, flags.sign),
        (Condition::Zero, flags.zero),
        (Condition::Parity, flags.parity),
    ];

    let &(condition, value) = &values[rng.gen_range(0..values.len())];

    let result = match operation {
        Operation::Add => first.wrapping_add(second) & limit,
        Operation::Sub => first.wrapping_sub(second) & limit,
        Operation::Xor => (first ^ second) & limit,
    };

    let key = result ^ 0u64.wrapping_sub(value);
    let encoded = (immediate & limit) ^ key;

    match size {
        1 => {
            asm.mov(get_gpr8(sized(scratch, 1).unwrap()).unwrap(), first as i32)
                .unwrap();
            asm.mov(get_gpr8(sized(other, 1).unwrap()).unwrap(), second as i32)
                .unwrap();
        }
        2 => {
            asm.mov(get_gpr16(sized(scratch, 2).unwrap()).unwrap(), first as i32)
                .unwrap();
            asm.mov(get_gpr16(sized(other, 2).unwrap()).unwrap(), second as i32)
                .unwrap();
        }
        4 => {
            asm.mov(get_gpr32(sized(scratch, 4).unwrap()).unwrap(), first as i32)
                .unwrap();
            asm.mov(get_gpr32(sized(other, 4).unwrap()).unwrap(), second as i32)
                .unwrap();
        }
        8 => {
            asm.mov(left, first as i64).unwrap();
            asm.mov(right, second as i64).unwrap();
        }
        _ => unreachable!(),
    }

    emit(asm, operation, scratch, other, size);

    match size {
        1 => {
            asm.movzx(left, get_gpr8(sized(scratch, 1).unwrap()).unwrap())
                .unwrap();
        }
        2 => {
            asm.movzx(left, get_gpr16(sized(scratch, 2).unwrap()).unwrap())
                .unwrap();
        }
        4 | 8 => {}
        _ => unreachable!(),
    }

    setcc(asm, byte, condition);

    asm.movzx(right, byte).unwrap();

    asm.neg(right).unwrap();
    asm.xor(right, left).unwrap();

    asm.mov(left, encoded as i64).unwrap();
    asm.xor(left, right).unwrap();
}

fn helpers(destination: Register) -> (Register, Register) {
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

    let destination = destination.full_register();

    let mut iterator = REGISTERS
        .iter()
        .filter(|&&register| register != destination);

    (*iterator.next().unwrap(), *iterator.next().unwrap())
}

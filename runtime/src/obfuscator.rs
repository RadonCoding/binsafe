use iced_x86::{
    code_asm::{get_gpr64, get_gpr8, AsmRegister64, AsmRegister8, CodeAssembler},
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

    if !matches!(instruction.op0_kind(), OpKind::Register)
        || matches!(instruction.op0_register(), Register::RSP)
        || instruction.op_register(0).size() != 8
    {
        return false;
    }

    let destination = instruction.op_register(0);
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

    reconstruct(immediate, scratch, other, asm, rng);

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
    let code = Code::values().find(|&c| {
        let info = c.op_code();
        info.mnemonic() == mnemonic
            && info.op_count() == count
            && info.op_kind(index) == OpCodeOperandKind::r64_reg
    })?;
    Instruction::with2(code, destination, scratch).ok()
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

fn compute_flags(operation: Operation, left: u64, right: u64) -> Flags {
    let result = match operation {
        Operation::Add => left.wrapping_add(right),
        Operation::Sub => left.wrapping_sub(right),
        Operation::Xor => left ^ right,
    };
    let (carry, overflow) = match operation {
        Operation::Xor => (0, 0),
        Operation::Add => (
            ((left as u128 + right as u128) > u64::MAX as u128) as u64,
            ((!(left ^ right) & (left ^ result)) >> 63) & 1,
        ),
        Operation::Sub => (
            (left < right) as u64,
            (((left ^ right) & (left ^ result)) >> 63) & 1,
        ),
    };
    Flags {
        carry,
        overflow,
        sign: (result >> 63) & 1,
        zero: (result == 0) as u64,
        parity: ((result as u8).count_ones() % 2 == 0) as u64,
    }
}

fn emit(
    asm: &mut CodeAssembler,
    operation: Operation,
    destination: AsmRegister64,
    source: AsmRegister64,
) {
    match operation {
        Operation::Add => asm.add(destination, source),
        Operation::Sub => asm.sub(destination, source),
        Operation::Xor => asm.xor(destination, source),
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
    scratch: Register,
    other: Register,
    asm: &mut CodeAssembler,
    rng: &mut impl Rng,
) {
    let left = get_gpr64(scratch).unwrap();
    let right = get_gpr64(other).unwrap();
    let byte = get_gpr8(Register::AL + other.number() as u32).unwrap();

    let operation = random_operation(rng);
    let first = rng.gen::<u64>();
    let second = rng.gen::<u64>();

    let flags = compute_flags(operation, first, second);

    let values = [
        (Condition::Carry, flags.carry),
        (Condition::Overflow, flags.overflow),
        (Condition::Sign, flags.sign),
        (Condition::Zero, flags.zero),
        (Condition::Parity, flags.parity),
    ];

    let &(condition, value) = &values[rng.gen_range(0..values.len())];
    let result = match operation {
        Operation::Add => first.wrapping_add(second),
        Operation::Sub => first.wrapping_sub(second),
        Operation::Xor => first ^ second,
    };
    let mask = result ^ (0u64.wrapping_sub(value));
    let encoded = immediate ^ mask;

    asm.mov(left, first as i64).unwrap();
    asm.mov(right, second as i64).unwrap();

    emit(asm, operation, left, right);

    setcc(asm, byte, condition);

    asm.movzx(right, byte).unwrap();

    asm.neg(right).unwrap();
    asm.xor(right, left).unwrap();

    asm.mov(left, encoded as i64).unwrap();
    asm.xor(left, right).unwrap();
}

fn helpers(destination: Register) -> (Register, Register) {
    let pool = [
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
    let mut iterator = pool.iter().filter(|&&register| register != destination);
    (*iterator.next().unwrap(), *iterator.next().unwrap())
}

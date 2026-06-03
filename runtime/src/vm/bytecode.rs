use core::panic;
#[cfg(debug_assertions)]
use std::fmt;
use std::rc::Rc;

use iced_x86::{Instruction, Mnemonic, Register};
use strum_macros::EnumIter;

use crate::mapper::{mapped, Mapper};
use crate::vm::encoders::Encode;
use crate::vm::lifters::{
    add, and, branch, cmov, cmp, dec, imul, inc, lea, mov, movsx, movzx, mul, neg, not, or,
    pcmpeqb, pmovmskb, pop, push, rol, ror, sar, set, shl, shr, sub, test, tzcnt, vmov, xor,
};
use crate::vm::transform::encrypt::Encrypt;
use crate::vm::transform::mutation::Mutation;
use crate::vm::transform::{permute, scramble, Transform};

mapped! {
    VMOp {
        Jcc,
        Ret,
        // Load
        LoadImmediate,
        LoadRegister,
        LoadMemory,
        LoadAddress,
        LoadVector,
        // Store
        StoreRegister,
        StoreMemory,
        StoreVector,
        // Arithmetic
        Add,
        Sub,
        And,
        Or,
        Xor,
        Test,
        Rol,
        Ror,
        Shl,
        Shr,
        Sar,
        Mul,
        Imul,
        Tzcnt,
        // Stack
        Push,
        Pop,
        Discard,
        // Atomic
        Cmpxchg,
        Xadd,
        Xchg,
        // Vector
        Pmovmskb,
        Pcmpeqb,
        // Nop
        Nop,
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum VMFlag {
    Carry = 0,      // CF
    Parity = 2,     // PF
    Auxiliary = 4,  // AF
    Zero = 6,       // ZF
    Sign = 7,       // SF
    Trap = 8,       // TF
    Interrupt = 9,  // IF
    Direction = 10, // DF
    Overflow = 11,  // OF
}

mapped! {
    VMReg {
        None,

        Rax,
        Rcx,
        Rdx,
        Rbx,
        Rsp,
        Rbp,
        Rsi,
        Rdi,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        Flags,

        NEntry, // Native Entry
        NBranch, // Native Branch
        NExit, // Native Exit
        BPointer, // Block Pointer
        BLength, // Block Length
        VImage, // Image Base
        VAtt, // Attestation Key
        VImm, // Immediate Key
        VStack, // Virtual Stack
        VScratch, // Virtual Scratch
    }
}

mapped! {
    VMVec {
        Ymm0,
        Ymm1,
        Ymm2,
        Ymm3,
        Ymm4,
        Ymm5,
        Ymm6,
        Ymm7,
        Ymm8,
        Ymm9,
        Ymm10,
        Ymm11,
        Ymm12,
        Ymm13,
        Ymm14,
        Ymm15
    }
}

impl From<Register> for VMVec {
    fn from(reg: Register) -> Self {
        match reg {
            Register::XMM0 | Register::YMM0 => Self::Ymm0,
            Register::XMM1 | Register::YMM1 => Self::Ymm1,
            Register::XMM2 | Register::YMM2 => Self::Ymm2,
            Register::XMM3 | Register::YMM3 => Self::Ymm3,
            Register::XMM4 | Register::YMM4 => Self::Ymm4,
            Register::XMM5 | Register::YMM5 => Self::Ymm5,
            Register::XMM6 | Register::YMM6 => Self::Ymm6,
            Register::XMM7 | Register::YMM7 => Self::Ymm7,
            Register::XMM8 | Register::YMM8 => Self::Ymm8,
            Register::XMM9 | Register::YMM9 => Self::Ymm9,
            Register::XMM10 | Register::YMM10 => Self::Ymm10,
            Register::XMM11 | Register::YMM11 => Self::Ymm11,
            Register::XMM12 | Register::YMM12 => Self::Ymm12,
            Register::XMM13 | Register::YMM13 => Self::Ymm13,
            Register::XMM14 | Register::YMM14 => Self::Ymm14,
            Register::XMM15 | Register::YMM15 => Self::Ymm15,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

impl From<Register> for VMReg {
    fn from(reg: Register) -> Self {
        match reg {
            Register::None => Self::None,
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Self::Rax,
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Self::Rcx,
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Self::Rdx,
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Self::Rbx,
            Register::RSP | Register::ESP | Register::SP | Register::SPL => Self::Rsp,
            Register::RBP | Register::EBP | Register::BP | Register::BPL => Self::Rbp,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => Self::Rsi,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => Self::Rdi,
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => Self::R8,
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => Self::R9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => Self::R10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => Self::R11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => Self::R12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => Self::R13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => Self::R14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => Self::R15,
            Register::RIP => Self::VImage,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMWidth {
        Lower8,
        Higher8,
        Lower16,
        Lower32,
        Lower64,
        Lower128,
        Lower256,
        SLower8,
        SLower16,
        SLower32,
    }
}

impl VMWidth {
    pub fn size(self) -> usize {
        match self {
            VMWidth::Lower8 | VMWidth::Higher8 | VMWidth::SLower8 => 1,
            VMWidth::Lower16 | VMWidth::SLower16 => 2,
            VMWidth::Lower32 | VMWidth::SLower32 => 4,
            VMWidth::Lower64 => 8,
            VMWidth::Lower128 => 16,
            VMWidth::Lower256 => 32,
        }
    }

    pub fn slots(self) -> i32 {
        (self.size() / 8).max(1) as i32
    }
}

impl From<Register> for VMWidth {
    fn from(reg: Register) -> Self {
        match reg {
            reg if (reg >= Register::AL && reg <= Register::BL)
                || (reg >= Register::SPL && reg <= Register::R15L) =>
            {
                Self::Lower8
            }
            reg if (reg >= Register::AH && reg <= Register::BH) => Self::Higher8,
            reg if (reg >= Register::AX && reg <= Register::R15W) => Self::Lower16,
            reg if (reg >= Register::EAX && reg <= Register::R15D) || reg == Register::EIP => {
                Self::Lower32
            }
            reg if (reg >= Register::RAX && reg <= Register::R15) || reg == Register::RIP => {
                Self::Lower64
            }
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMSeg {
        None,
        Gs,
    }
}

impl From<Register> for VMSeg {
    fn from(reg: Register) -> Self {
        match reg {
            Register::None => Self::None,
            Register::GS => Self::Gs,
            _ => panic!("unsupported segment: {reg:?}"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct VMMem {
    pub base: VMReg,
    pub index: VMReg,
    pub scale: u8,
    pub displacement: i32,
    pub segment: VMSeg,
}

impl Encode for VMMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(mapper.index(self.base));
        bytes.push(mapper.index(self.index));
        bytes.push(self.scale);
        bytes.extend_from_slice(&self.displacement.to_le_bytes());
        bytes.push(mapper.index(self.segment));
        bytes
    }
}

impl From<&Instruction> for VMMem {
    fn from(instruction: &Instruction) -> Self {
        let base = VMReg::from(instruction.memory_base());
        let index = VMReg::from(instruction.memory_index());
        let scale = instruction.memory_index_scale() as u8;
        let displacement = (instruction.memory_displacement64() as i64)
            .try_into()
            .unwrap();
        let segment = VMSeg::from(instruction.segment_prefix());

        Self {
            base,
            index,
            scale,
            displacement,
            segment,
        }
    }
}

mapped! {
    VMTest {
        CMP,
        EQ,
        NEQ,
    }
}

mapped! {
    VMLogic {
        JAND, // JUMP AND
        JOR, // JUMP OR
        JXOR, // JUMP XOR

        CAND, // CALL AND
        COR,// CALL OR
        CXOR, // CALL XOR

        SAND, // SKIP AND
        SOR,  // SKIP OR
        SXOR, // SKIP XOR
    }
}

#[derive(Debug, Clone)]
pub struct VMCondition {
    pub test: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl Encode for VMCondition {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.test), self.lhs, self.rhs]
    }
}

pub struct Bytecode {
    #[cfg(debug_assertions)]
    snapshots: Vec<Snapshot>,

    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Lift,
    Mutation,
    Permute,
    Scramble,
    Encrypt,
}

impl Phase {
    pub fn identifier(&self) -> &'static str {
        match self {
            Self::Lift => "lift",
            Self::Mutation => "mutation",
            Self::Permute => "permute",
            Self::Scramble => "scramble",
            Self::Encrypt => "encrypt",
        }
    }
}

#[cfg(debug_assertions)]
struct Snapshot {
    phase: Phase,
    operations: Vec<(usize, String)>,
}

#[cfg(debug_assertions)]
impl Snapshot {
    fn take(phase: Phase, operations: &[Rc<dyn Encode>]) -> Self {
        Self {
            phase,
            operations: operations
                .iter()
                .map(|operation| (address(operation), format!("{}", operation)))
                .collect(),
        }
    }
}

#[cfg(debug_assertions)]
fn address(operation: &Rc<dyn Encode>) -> usize {
    &**operation as *const dyn Encode as *const () as usize
}

#[cfg(debug_assertions)]
impl Bytecode {
    fn trace(&self, target: usize) -> (Option<usize>, String) {
        let mut original: Option<usize> = None;
        let mut markers = String::new();
        let mut previous: Option<&str> = None;
        let mut closing: Option<usize> = None;

        for (index, snapshot) in self.snapshots.iter().enumerate() {
            let Some((position, (_, current))) = snapshot
                .operations
                .iter()
                .enumerate()
                .find(|(_, (other, _))| *other == target)
            else {
                continue;
            };

            match previous {
                None => {
                    if index == 0 {
                        original = Some(position);
                    } else {
                        markers.push(letter(snapshot.phase));
                    }
                }
                Some(prior) if prior != current.as_str() => {
                    markers.push(letter(snapshot.phase));
                }
                _ => {}
            }

            previous = Some(current.as_str());
            closing = Some(index);
        }

        if let Some(closing) = closing {
            let remover = closing + 1;

            if remover < self.snapshots.len() {
                markers.push(letter(self.snapshots[remover].phase));
            }
        }

        (original, markers)
    }
}

#[cfg(debug_assertions)]
fn letter(phase: Phase) -> char {
    phase
        .identifier()
        .chars()
        .next()
        .unwrap()
        .to_uppercase()
        .next()
        .unwrap()
}

#[cfg(debug_assertions)]
impl fmt::Display for Bytecode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::collections::{HashMap, HashSet};

        let last = self.snapshots.last().unwrap();
        let surviving = last
            .operations
            .iter()
            .map(|(address, _)| *address)
            .collect::<HashSet<usize>>();

        let render = |original: Option<usize>, markers: &str, display: &str| {
            let original = match original {
                Some(value) => format!("{:>3}", value),
                None => "   ".to_string(),
            };
            let display = display.replace('\n', "\n         ");
            format!("{} {:<4} {}", original, markers, display)
        };

        let mut lines = last
            .operations
            .iter()
            .map(|(target, display)| {
                let (original, markers) = self.trace(*target);
                render(original, &markers, display)
            })
            .collect::<Vec<String>>();

        let mut latest = HashMap::new();

        for (snapshot_index, snapshot) in self.snapshots.iter().enumerate() {
            for (position, (address, content)) in snapshot.operations.iter().enumerate() {
                latest.insert(*address, (snapshot_index, position, content.clone()));
            }
        }

        let mut removed = latest
            .into_iter()
            .filter(|(address, _)| !surviving.contains(address))
            .filter_map(|(address, (index, position, content))| {
                let remover = index + 1;

                (remover < self.snapshots.len()).then_some((remover, position, address, content))
            })
            .collect::<Vec<(usize, usize, usize, String)>>();

        removed.sort_by_key(|(remover, position, _, _)| (*remover, *position));

        for (_, _, address, content) in &removed {
            let (original, markers) = self.trace(*address);
            lines.push(render(original, &markers, content));
        }

        write!(f, "{}", lines.join("\n"))
    }
}

impl Bytecode {
    fn new(#[cfg(debug_assertions)] snapshots: Vec<Snapshot>, bytes: Vec<u8>) -> Self {
        Self {
            #[cfg(debug_assertions)]
            snapshots,
            bytes,
        }
    }
}

pub fn lift(mapper: &mut Mapper, instructions: &[Instruction]) -> Option<Vec<Rc<dyn Encode>>> {
    let mut output: Vec<Rc<dyn Encode>> = Vec::new();

    for instruction in instructions {
        let ops = match instruction.mnemonic() {
            Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Je
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jne
            | Mnemonic::Jno
            | Mnemonic::Jnp
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jp
            | Mnemonic::Js
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Ret => branch::encode(instruction)?,
            Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovno
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovns
            | Mnemonic::Cmovo
            | Mnemonic::Cmovp
            | Mnemonic::Cmovs => cmov::encode(mapper, instruction)?,
            Mnemonic::Add => add::encode(instruction)?,
            Mnemonic::Sub => sub::encode(instruction)?,
            Mnemonic::Cmp => cmp::encode(instruction)?,
            Mnemonic::And => and::encode(instruction)?,
            Mnemonic::Or => or::encode(instruction)?,
            Mnemonic::Xor => xor::encode(instruction)?,
            Mnemonic::Test => test::encode(instruction)?,
            Mnemonic::Rol => rol::encode(instruction)?,
            Mnemonic::Ror => ror::encode(instruction)?,
            Mnemonic::Shl => shl::encode(instruction)?,
            Mnemonic::Shr => shr::encode(instruction)?,
            Mnemonic::Sar => sar::encode(instruction)?,
            Mnemonic::Inc => inc::encode(instruction)?,
            Mnemonic::Dec => dec::encode(instruction)?,
            Mnemonic::Neg => neg::encode(instruction)?,
            Mnemonic::Not => not::encode(instruction)?,
            Mnemonic::Mul => mul::encode(instruction)?,
            Mnemonic::Imul => imul::encode(instruction)?,
            Mnemonic::Tzcnt => tzcnt::encode(instruction)?,
            Mnemonic::Lea => lea::encode(instruction)?,
            Mnemonic::Mov => mov::encode(instruction)?,
            Mnemonic::Movaps
            | Mnemonic::Movups
            | Mnemonic::Movapd
            | Mnemonic::Movupd
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu => vmov::encode(instruction)?,
            Mnemonic::Movzx => movzx::encode(instruction)?,
            Mnemonic::Movsx | Mnemonic::Movsxd => movsx::encode(instruction)?,
            Mnemonic::Push => push::encode(instruction)?,
            Mnemonic::Pop => pop::encode(instruction)?,
            Mnemonic::Pmovmskb => pmovmskb::encode(instruction)?,
            Mnemonic::Pcmpeqb => pcmpeqb::encode(instruction)?,
            Mnemonic::Seta
            | Mnemonic::Setae
            | Mnemonic::Setb
            | Mnemonic::Setbe
            | Mnemonic::Sete
            | Mnemonic::Setg
            | Mnemonic::Setge
            | Mnemonic::Setl
            | Mnemonic::Setle
            | Mnemonic::Setne
            | Mnemonic::Setno
            | Mnemonic::Setnp
            | Mnemonic::Setns
            | Mnemonic::Seto
            | Mnemonic::Setp
            | Mnemonic::Sets => set::encode(mapper, instruction)?,
            Mnemonic::Nop | Mnemonic::Int3 | Mnemonic::Ud2 => continue,
            _ => return None,
        };

        output.extend(ops);
    }

    Some(output)
}

pub fn assemble(mapper: &mut Mapper, operations: &[Rc<dyn Encode>]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for operation in operations {
        bytes.extend(operation.encode(mapper));
    }
    bytes
}

pub fn process<F>(mapper: &mut Mapper, operations: Vec<Rc<dyn Encode>>, mut picker: F) -> Bytecode
where
    F: FnMut(&[usize]) -> usize,
{
    let mut operations = operations;

    #[cfg(debug_assertions)]
    let mut snapshots = vec![Snapshot::take(Phase::Lift, &operations)];

    operations = permute::permute(operations, &mut picker);
    #[cfg(debug_assertions)]
    snapshots.push(Snapshot::take(Phase::Permute, &operations));

    operations = scramble::scramble(mapper, operations);
    #[cfg(debug_assertions)]
    snapshots.push(Snapshot::take(Phase::Scramble, &operations));

    operations = Mutation.run(mapper, operations);
    #[cfg(debug_assertions)]
    snapshots.push(Snapshot::take(Mutation.phase(), &operations));

    operations = Encrypt.run(mapper, operations);
    #[cfg(debug_assertions)]
    snapshots.push(Snapshot::take(Encrypt.phase(), &operations));

    operations = permute::permute(operations, &mut picker);
    #[cfg(debug_assertions)]
    snapshots.push(Snapshot::take(Phase::Permute, &operations));

    let bytes = assemble(mapper, &operations);

    Bytecode::new(
        #[cfg(debug_assertions)]
        snapshots,
        bytes,
    )
}

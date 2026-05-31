use core::panic;
use std::rc::Rc;

use iced_x86::{Instruction, Mnemonic, Register};
use strum_macros::EnumIter;

use crate::mapper::{mapped, Mapper};
use crate::vm::encoders::Encode;
use crate::vm::lifters::{
    add, and, cmov, cmp, jcc, lea, mov, movsx, movzx, or, pop, push, set, sub, test, xor,
};

mapped! {
    VMOp {
        Jcc,
        Ret,
        // Load
        LoadImmediate,
        LoadRegister,
        LoadMemory,
        LoadAddress,
        // Store
        StoreRegister,
        StoreMemory,
        // Arithmetic
        Add,
        Sub,
        And,
        Or,
        Xor,
        Test,
        // Stack
        Push,
        Pop,
        Discard,
        // Nop
        Nop,
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
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
        VStack, // Virtual Stack Top
        VScratch, // Virtual Scratch Top
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
        SLower8,
        SLower16,
        SLower32,
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
    lifted: Vec<String>,
    #[cfg(debug_assertions)]
    permuted: Vec<String>,
    #[cfg(debug_assertions)]
    encrypted: Vec<String>,

    pub bytes: Vec<u8>,
}

#[cfg(debug_assertions)]
impl std::fmt::Display for Bytecode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut lifted_positions = std::collections::HashMap::new();

        for (i, line) in self.lifted.iter().enumerate() {
            lifted_positions
                .entry(line.as_str())
                .or_insert_with(std::collections::VecDeque::new)
                .push_back(i);
        }

        let mut permute_additions = std::collections::HashMap::<&str, usize>::new();

        for op in &self.permuted {
            *permute_additions.entry(op.as_str()).or_insert(0) += 1;
        }

        for line in &self.lifted {
            if let Some(count) = permute_additions.get_mut(line.as_str()) {
                *count = count.saturating_sub(1);
            }
        }

        let lines = self
            .encrypted
            .iter()
            .map(|op| {
                if let Some(index) = lifted_positions
                    .get_mut(op.as_str())
                    .and_then(|queue| queue.pop_front())
                {
                    format!("  {:>3}   {}", index, op)
                } else if permute_additions.get(op.as_str()).copied().unwrap_or(0) > 0 {
                    *permute_additions.get_mut(op.as_str()).unwrap() -= 1;
                    format!("    +   {}", op)
                } else {
                    format!("    *   {}", op)
                }
            })
            .collect::<Vec<String>>()
            .join("\n");

        write!(f, "{}", lines)
    }
}

impl Bytecode {
    fn new(
        #[cfg(debug_assertions)] lifted: Vec<String>,
        #[cfg(debug_assertions)] permuted: Vec<String>,
        #[cfg(debug_assertions)] encrypted: Vec<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            #[cfg(debug_assertions)]
            lifted,
            #[cfg(debug_assertions)]
            permuted,
            #[cfg(debug_assertions)]
            encrypted,
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
            | Mnemonic::Ret => jcc::encode(instruction)?,
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
            Mnemonic::Lea => lea::encode(instruction)?,
            Mnemonic::Mov => mov::encode(instruction)?,
            Mnemonic::Movzx => movzx::encode(instruction)?,
            Mnemonic::Movsx | Mnemonic::Movsxd => movsx::encode(instruction)?,
            Mnemonic::Push => push::encode(instruction)?,
            Mnemonic::Pop => pop::encode(instruction)?,
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
            Mnemonic::Nop => continue,
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

/// Annotates the encrypted operation stream against the lifted baseline, marking each operation with its original lifted index, `+` for permuter-added ops, or `*` for encrypter-added ops.
#[cfg(debug_assertions)]
pub fn annotate(lifted: &[String], permuted: &[String], encrypted: &[String]) -> String {
    use std::collections::HashMap;

    let mut lifted_positions = HashMap::new();

    for (i, line) in lifted.iter().enumerate() {
        lifted_positions
            .entry(line.as_str())
            .or_insert_with(std::collections::VecDeque::new)
            .push_back(i);
    }

    let mut permute_additions = HashMap::<&str, usize>::new();

    for op in permuted {
        *permute_additions.entry(op.as_str()).or_insert(0) += 1;
    }

    for line in lifted {
        if let Some(count) = permute_additions.get_mut(line.as_str()) {
            *count = count.saturating_sub(1);
        }
    }

    encrypted
        .iter()
        .map(|op| {
            if let Some(index) = lifted_positions
                .get_mut(op.as_str())
                .and_then(|queue| queue.pop_front())
            {
                format!("  {:>3}   {}", index, op)
            } else if permute_additions.get(op.as_str()).copied().unwrap_or(0) > 0 {
                *permute_additions.get_mut(op.as_str()).unwrap() -= 1;
                format!("    +   {}", op)
            } else {
                format!("    *   {}", op)
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}

pub fn process<F>(mapper: &mut Mapper, operations: Vec<Rc<dyn Encode>>, mut picker: F) -> Bytecode
where
    F: FnMut(&[usize]) -> usize,
{
    let operations = crate::vm::mutation::mutate(operations);

    #[cfg(debug_assertions)]
    let lifted = operations
        .iter()
        .map(|op| format!("{}", op))
        .collect::<Vec<String>>();

    let operations = crate::vm::permute::permute(operations, &mut picker);

    #[cfg(debug_assertions)]
    let permuted = operations
        .iter()
        .map(|op| format!("{}", op))
        .collect::<Vec<String>>();

    let operations = crate::vm::encrypt::encrypt(operations);

    #[cfg(debug_assertions)]
    let encrypted = operations
        .iter()
        .map(|op| format!("{}", op))
        .collect::<Vec<String>>();

    let operations = crate::vm::permute::permute(operations, &mut picker);

    let bytes = assemble(mapper, &operations);

    Bytecode::new(
        #[cfg(debug_assertions)]
        lifted,
        #[cfg(debug_assertions)]
        permuted,
        #[cfg(debug_assertions)]
        encrypted,
        bytes,
    )
}

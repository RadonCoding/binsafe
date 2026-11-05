use std::collections::HashSet;

use crate::vm::bytecode::{Flag, VMReg, VMWidth};

mod allocator;
pub mod builder;
pub mod compiler;
mod obfuscation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Fixed(VMReg),
    Operand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unary {
    Not,
    LowByte,
    Parity,
    Tzcnt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    Equal,
    LessThan,
    GreaterThan,
    BitSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vector {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    AndNot,
    PackedByteEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Value {
    pub node: usize,
    pub output: usize,
}

#[derive(Debug, Clone)]
pub enum Node {
    Input(usize),
    Immediate(u64),
    Register(Register),
    Local(usize),
    Flag(Flag),
    Segment,
    SignBit,
    BitSize,
    ByteMask(usize),
    Memory(Value),
    LoadMemory(Value),
    Unary(Unary, Value),
    Binary(Binary, Value, Value),
    Shift(Shift, Value, Value),
    Compare(Compare, Value, Value),
    Bsr(Value, Value),
    Extend(Value, VMWidth),
    WideMul(Value, Value),
    Div(Value, Value, Value),
    Cpuid(Value, Value),
    Timestamp,
    Exchange(Value, Value),
    ExchangeAdd(Value, Value),
    CompareExchange(Value, Value, Value),
    LoadVector,
    Vector(Vector, Value, Value),
    PackedByteMask(Value),
}

#[derive(Debug, Clone)]
pub enum Statement {
    WriteRegister(Register, Value),
    WriteMemory(Value, Value),
    StoreMemory(Value, Value),
    StoreMerge(Value),
    StoreExtend(Value),
    Assign(usize, Value),
    Read(usize, VMWidth),
    Advance(Value),
    Drop(Value),
    Loop(usize, Vec<Statement>),
    Select(Value, Vec<(Vec<u64>, Vec<Statement>)>),
    When(Value, Vec<Statement>),
}

#[derive(Debug, Clone)]
pub enum Flags {
    Never,
    Always(Vec<(Flag, Value)>),
    When(Value, Vec<(Flag, Value)>),
}

#[derive(Debug)]
pub struct Operation {
    pub nodes: Vec<Node>,
    pub statements: Vec<Statement>,
    pub flags: Flags,
    pub outputs: Option<Vec<Value>>,
    pub widths: &'static [VMWidth],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Slot {
    Input(usize),
    Flags,
    Local(usize),
    Node(usize),
    Temporary(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reference {
    Value(Slot),
    Immediate(i64),
}

impl Node {
    fn results(&self) -> usize {
        match self {
            Node::Cpuid(..) => 4,
            Node::WideMul(..)
            | Node::Div(..)
            | Node::Timestamp
            | Node::ExchangeAdd(..) => 2,
            _ => 1,
        }
    }

    fn operands(&self) -> Vec<Value> {
        match self {
            Node::Input(_)
            | Node::Immediate(_)
            | Node::Register(_)
            | Node::Local(_)
            | Node::Flag(_)
            | Node::Segment
            | Node::SignBit
            | Node::BitSize
            | Node::ByteMask(_)
            | Node::Timestamp
            | Node::LoadVector => vec![],
            &Node::Memory(value)
            | &Node::LoadMemory(value)
            | &Node::Unary(_, value)
            | &Node::Extend(value, _)
            | &Node::PackedByteMask(value) => vec![value],
            &Node::Binary(_, first, second)
            | &Node::Shift(_, first, second)
            | &Node::Compare(_, first, second)
            | &Node::Bsr(first, second)
            | &Node::WideMul(first, second)
            | &Node::Cpuid(first, second)
            | &Node::Exchange(first, second)
            | &Node::ExchangeAdd(first, second)
            | &Node::Vector(_, first, second) => vec![first, second],
            &Node::Div(first, second, third)
            | &Node::CompareExchange(first, second, third) => vec![first, second, third],
        }
    }
}

impl Operation {
    fn operands_count(&self) -> usize {
        let mut value = 0;
        for node in &self.nodes {
            if let &Node::Input(index) = node {
                value = value.max(index + 1);
            }
        }
        value
    }

    fn locals(&self) -> usize {
        let mut value = 0;

        for node in &self.nodes {
            if let &Node::Local(index) = node {
                value = value.max(index + 1);
            }
        }

        fn walk(statements: &[Statement], value: &mut usize) {
            for statement in statements {
                match statement {
                    &Statement::Assign(index, _) | &Statement::Read(index, _) => {
                        *value = (*value).max(index + 1)
                    }
                    Statement::Loop(counter, body) => {
                        *value = (*value).max(counter + 1);
                        walk(body, value);
                    }
                    Statement::When(_, body) => walk(body, value),
                    Statement::Select(_, arms) => {
                        for (_, body) in arms {
                            walk(body, value);
                        }
                    }
                    _ => {}
                }
            }
        }

        walk(&self.statements, &mut value);
        value
    }

    fn node_slots(&self) -> usize {
        self.nodes
            .iter()
            .filter(|node| node.results() > 1)
            .map(Node::results)
            .sum()
    }

    fn subtree(&self, value: Value) -> usize {
        let node = &self.nodes[value.node];
        let base = if node.results() > 1 { 0 } else { 1 };
        base + node
            .operands()
            .into_iter()
            .map(|operand| self.subtree(operand))
            .sum::<usize>()
    }

    fn temporaries(&self) -> usize {
        fn walk(operation: &Operation, statements: &[Statement], total: &mut usize) {
            for statement in statements {
                for value in statement.values() {
                    *total += operation.subtree(value);
                }
                match statement {
                    Statement::Loop(_, body) | Statement::When(_, body) => {
                        walk(operation, body, total)
                    }
                    Statement::Select(_, arms) => {
                        for (_, body) in arms {
                            walk(operation, body, total);
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut total = 0;
        walk(self, &self.statements, &mut total);

        for &(_, value) in self.flags.values() {
            total += self.subtree(value);
        }

        if let Some(&condition) = self.flags.condition() {
            total += self.subtree(condition);
        }

        if let Some(outputs) = &self.outputs {
            for &value in outputs {
                total += self.subtree(value);
            }
        }

        total
    }

    fn pointers(&self) -> HashSet<usize> {
        let mut set = HashSet::new();

        let mut address = |value: Value| {
            if let Node::Input(index) = self.nodes[value.node] {
                set.insert(index);
            }
        };

        for node in &self.nodes {
            if let &Node::Memory(value) | &Node::LoadMemory(value) = node {
                address(value);
            }
        }

        fn walk(statements: &[Statement], address: &mut impl FnMut(Value)) {
            for statement in statements {
                match statement {
                    &Statement::WriteMemory(first, _) | &Statement::StoreMemory(first, _) => {
                        address(first)
                    }
                    Statement::Loop(_, body) | Statement::When(_, body) => walk(body, address),
                    Statement::Select(_, arms) => {
                        for (_, body) in arms {
                            walk(body, address);
                        }
                    }
                    _ => {}
                }
            }
        }

        walk(&self.statements, &mut address);
        set
    }
}

impl Statement {
    fn values(&self) -> Vec<Value> {
        match self {
            &Statement::StoreMemory(first, second) | &Statement::WriteMemory(first, second) => {
                vec![first, second]
            }
            &Statement::WriteRegister(_, value)
            | &Statement::Assign(_, value)
            | &Statement::Advance(value)
            | &Statement::StoreMerge(value)
            | &Statement::StoreExtend(value)
            | &Statement::Drop(value) => vec![value],
            &Statement::Select(selector, _) | &Statement::When(selector, _) => vec![selector],
            Statement::Loop(..) | Statement::Read(..) => vec![],
        }
    }
}

impl Flags {
    fn values(&self) -> &[(Flag, Value)] {
        match self {
            Flags::Never => &[],
            Flags::Always(values) | Flags::When(_, values) => values,
        }
    }

    fn condition(&self) -> Option<&Value> {
        match self {
            Flags::Never | Flags::Always(_) => None,
            Flags::When(condition, _) => Some(condition),
        }
    }

    fn is_empty(&self) -> bool {
        self.values().is_empty()
    }
}

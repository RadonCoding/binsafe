use rand::Rng;

use crate::vm::bytecode::{Flag, VMReg, VMWidth};

mod allocator;
pub mod builder;
pub mod compiler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Input(usize),
    Output(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Fixed(VMReg),
    Operand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Immediate {
    Fixed(u64),
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
    ByteEqual,
    ByteMask,
    LoadVector,
    StoreMerge,
    StoreExtend,
    LoadMemory,
    StoreMemory,
}

#[derive(Debug, Clone)]
pub enum Expression {
    Operand(Operand),
    Register(Register),
    Immediate(Immediate),
    Local(usize),
    Memory(Box<Expression>),
    BitAnd(Box<Expression>, Box<Expression>),
    BitOr(Box<Expression>, Box<Expression>),
    BitXor(Box<Expression>, Box<Expression>),
    BitShr(Box<Expression>, Box<Expression>),
    BitShl(Box<Expression>, Box<Expression>),
    BitNot(Box<Expression>),
    Add(Box<Expression>, Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    Mul(Box<Expression>, Box<Expression>),
    LowByte(Box<Expression>),
    Compare(Box<Compare>),
    Parity(Box<Expression>),
    Flag(Flag),
    SignBit,
    BitSize,
    ByteMask(usize),
    Segment,
    Extend(Box<Expression>, VMWidth),
}

#[derive(Debug, Clone)]
pub enum Effect {
    Add(Expression, Expression),
    Sub(Expression, Expression),
    And(Expression, Expression),
    Or(Expression, Expression),
    Xor(Expression, Expression),
    Shr(Expression, Expression),
    Shl(Expression, Expression),
    Ror(Expression, Expression),
    Rol(Expression, Expression),
    Mul(Expression, Expression),
    Div(Expression, Expression, Expression),
    Push(Expression),
    Sar(Expression, Expression),
    Bsr(Expression),
    Tzcnt(Expression),
    Exchange(Expression, Expression),
    ExchangeAdd(Expression, Expression),
    CompareExchange(Expression, Expression, Expression),
    Register(Register, Expression),
    Memory(Expression, Expression),
    Assign(usize, Expression),
    Read(usize, VMWidth),
    Advance(Expression),
    Drop(Expression),
    Vector(Vector),
    Cpuid,
    Timestamp,
    Loop(usize, Vec<Effect>),
    Select(Expression, Vec<(Vec<u64>, Vec<Effect>)>),
    When(Expression, Vec<Effect>),
}

#[derive(Debug, Clone)]
pub enum Compare {
    Equal(Expression, Expression),
    LessThan(Expression, Expression),
    GreaterThan(Expression, Expression),
    BitSet(Expression, Expression),
}

#[derive(Debug, Clone)]
pub enum Flags {
    Never,
    Always(Vec<(Flag, Expression)>),
    When(Expression, Vec<(Flag, Expression)>),
}

#[derive(Debug)]
pub struct Operation {
    pub effects: Vec<Effect>,
    pub flags: Flags,
    pub stores: Option<Vec<Expression>>,
    pub widths: &'static [VMWidth],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Value {
    Input(usize),
    Output(usize),
    Flags,
    Local(usize),
    Temporary(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reference {
    Value(Value),
    Immediate(i64),
}

fn not(a: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::BitNot(a))
}

fn and(a: Box<Expression>, b: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::BitAnd(a, b))
}

fn or(a: Box<Expression>, b: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::BitOr(a, b))
}

fn xor(a: Box<Expression>, b: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::BitXor(a, b))
}

fn add(a: Box<Expression>, b: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::Add(a, b))
}

fn sub(a: Box<Expression>, b: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::Sub(a, b))
}

fn shl(a: Box<Expression>, b: Box<Expression>) -> Box<Expression> {
    Box::new(Expression::BitShl(a, b))
}

fn imm(value: u64) -> Box<Expression> {
    Box::new(Expression::Immediate(Immediate::Fixed(value)))
}

impl Expression {
    fn obfuscate(self, rng: &mut impl Rng, budget: &mut u32) -> Expression {
        let expression = match self {
            Expression::BitAnd(a, b) => Expression::BitAnd(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::BitOr(a, b) => Expression::BitOr(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::BitXor(a, b) => Expression::BitXor(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::BitShr(a, b) => Expression::BitShr(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::BitShl(a, b) => Expression::BitShl(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::Add(a, b) => Expression::Add(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::Sub(a, b) => Expression::Sub(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::Mul(a, b) => Expression::Mul(
                Box::new(a.obfuscate(rng, budget)),
                Box::new(b.obfuscate(rng, budget)),
            ),
            Expression::BitNot(a) => Expression::BitNot(Box::new(a.obfuscate(rng, budget))),
            Expression::Extend(a, width) => {
                Expression::Extend(Box::new(a.obfuscate(rng, budget)), width)
            }
            Expression::Memory(a) => Expression::Memory(Box::new(a.obfuscate(rng, budget))),
            Expression::LowByte(a) => Expression::LowByte(Box::new(a.obfuscate(rng, budget))),
            Expression::Parity(a) => Expression::Parity(Box::new(a.obfuscate(rng, budget))),
            Expression::Compare(compare) => {
                Expression::Compare(Box::new(compare.obfuscate(rng, budget)))
            }
            leaf => leaf,
        };

        if *budget == 0 {
            return expression;
        }

        match expression {
            Expression::BitXor(a, b) => {
                *budget -= 1;
                match rng.gen_range(0..4) {
                    // (a | b) - (a & b)
                    0 => Expression::Sub(or(a.clone(), b.clone()), and(a, b)),
                    // (a | b) & ~(a & b)
                    1 => Expression::BitAnd(or(a.clone(), b.clone()), not(and(a, b))),
                    // (a & ~b) | (~a & b)
                    2 => Expression::BitOr(and(a.clone(), not(b.clone())), and(not(a), b)),
                    // (a + b) - ((a & b) << 1)
                    _ => Expression::Sub(add(a.clone(), b.clone()), shl(and(a, b), imm(1))),
                }
            }
            Expression::BitOr(a, b) => {
                *budget -= 1;
                match rng.gen_range(0..4) {
                    // ~(~a & ~b)
                    0 => Expression::BitNot(and(not(a), not(b))),
                    // (a & b) + (a ^ b)
                    1 => Expression::Add(and(a.clone(), b.clone()), xor(a, b)),
                    // a + (b & ~a)
                    2 => Expression::Add(a.clone(), and(b, not(a))),
                    // (a + b) - (a & b)
                    _ => Expression::Sub(add(a.clone(), b.clone()), and(a, b)),
                }
            }
            Expression::BitAnd(a, b) => {
                *budget -= 1;
                match rng.gen_range(0..4) {
                    // ~(~a | ~b)
                    0 => Expression::BitNot(or(not(a), not(b))),
                    // (a | b) - (a ^ b)
                    1 => Expression::Sub(or(a.clone(), b.clone()), xor(a, b)),
                    // a - (a & ~b)
                    2 => Expression::Sub(a.clone(), and(a, not(b))),
                    // (a + b) - (a | b)
                    _ => Expression::Sub(add(a.clone(), b.clone()), or(a, b)),
                }
            }
            Expression::BitNot(a) => {
                *budget -= 1;
                match rng.gen_range(0..2) {
                    // -a - 1
                    0 => Expression::Sub(sub(imm(0), a), imm(1)),
                    // a ^ -1
                    _ => Expression::BitXor(a, imm(u64::MAX)),
                }
            }
            Expression::Add(a, b) => {
                *budget -= 1;
                match rng.gen_range(0..3) {
                    // (a ^ b) + ((a & b) << 1)
                    0 => Expression::Add(xor(a.clone(), b.clone()), shl(and(a, b), imm(1))),
                    // (a | b) + (a & b)
                    1 => Expression::Add(or(a.clone(), b.clone()), and(a, b)),
                    // (a - ~b) - 1
                    _ => Expression::Sub(sub(a, not(b)), imm(1)),
                }
            }
            Expression::Sub(a, b) => {
                *budget -= 1;
                match rng.gen_range(0..3) {
                    // (a + ~b) + 1
                    0 => Expression::Add(add(a, not(b)), imm(1)),
                    // a + (0 - b)
                    1 => Expression::Add(a, sub(imm(0), b)),
                    // (a ^ b) - ((~a & b) << 1)
                    _ => Expression::Sub(xor(a.clone(), b.clone()), shl(and(not(a), b), imm(1))),
                }
            }
            Expression::Immediate(Immediate::Fixed(value)) => {
                *budget -= 1;
                let key = rng.gen::<u64>();
                match rng.gen_range(0..3) {
                    // (value ^ key) ^ key
                    0 => Expression::BitXor(imm(value ^ key), imm(key)),
                    // (value + key) - key
                    1 => Expression::Sub(imm(value.wrapping_add(key)), imm(key)),
                    // (value - key) + key
                    _ => Expression::Add(imm(value.wrapping_sub(key)), imm(key)),
                }
            }
            other => other,
        }
    }
}

impl Compare {
    fn obfuscate(self, rng: &mut impl Rng, budget: &mut u32) -> Compare {
        match self {
            Compare::Equal(a, b) => {
                Compare::Equal(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
            Compare::LessThan(a, b) => {
                Compare::LessThan(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
            Compare::GreaterThan(a, b) => {
                Compare::GreaterThan(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
            Compare::BitSet(a, b) => {
                Compare::BitSet(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
        }
    }
}

impl Effect {
    fn obfuscate(self, rng: &mut impl Rng, budget: &mut u32) -> Effect {
        match self {
            Effect::Add(a, b) => Effect::Add(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Sub(a, b) => Effect::Sub(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::And(a, b) => Effect::And(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Or(a, b) => Effect::Or(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Xor(a, b) => Effect::Xor(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Shr(a, b) => Effect::Shr(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Shl(a, b) => Effect::Shl(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Ror(a, b) => Effect::Ror(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Rol(a, b) => Effect::Rol(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Mul(a, b) => Effect::Mul(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Div(a, b, c) => Effect::Div(
                a.obfuscate(rng, budget),
                b.obfuscate(rng, budget),
                c.obfuscate(rng, budget),
            ),
            Effect::Push(a) => Effect::Push(a.obfuscate(rng, budget)),
            Effect::Sar(a, b) => Effect::Sar(a.obfuscate(rng, budget), b.obfuscate(rng, budget)),
            Effect::Bsr(a) => Effect::Bsr(a.obfuscate(rng, budget)),
            Effect::Tzcnt(a) => Effect::Tzcnt(a.obfuscate(rng, budget)),
            Effect::Exchange(a, b) => {
                Effect::Exchange(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
            Effect::ExchangeAdd(a, b) => {
                Effect::ExchangeAdd(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
            Effect::CompareExchange(a, b, c) => Effect::CompareExchange(
                a.obfuscate(rng, budget),
                b.obfuscate(rng, budget),
                c.obfuscate(rng, budget),
            ),
            Effect::Register(register, a) => Effect::Register(register, a.obfuscate(rng, budget)),
            Effect::Memory(a, b) => {
                Effect::Memory(a.obfuscate(rng, budget), b.obfuscate(rng, budget))
            }
            Effect::Assign(local, a) => Effect::Assign(local, a.obfuscate(rng, budget)),
            Effect::Read(local, width) => Effect::Read(local, width),
            Effect::Advance(a) => Effect::Advance(a.obfuscate(rng, budget)),
            Effect::Drop(a) => Effect::Drop(a.obfuscate(rng, budget)),
            Effect::Vector(vector) => Effect::Vector(vector),
            Effect::Cpuid => Effect::Cpuid,
            Effect::Timestamp => Effect::Timestamp,
            Effect::Loop(counter, body) => Effect::Loop(counter, obfuscate(body, rng, budget)),
            Effect::Select(selector, arms) => Effect::Select(
                selector.obfuscate(rng, budget),
                arms.into_iter()
                    .map(|(keys, body)| (keys, obfuscate(body, rng, budget)))
                    .collect(),
            ),
            Effect::When(condition, body) => Effect::When(
                condition.obfuscate(rng, budget),
                obfuscate(body, rng, budget),
            ),
        }
    }
}

fn obfuscate(effects: Vec<Effect>, rng: &mut impl Rng, budget: &mut u32) -> Vec<Effect> {
    effects
        .into_iter()
        .map(|effect| effect.obfuscate(rng, budget))
        .collect()
}

impl Operation {
    fn operands(&self) -> usize {
        let mut value = 0;

        for effect in &self.effects {
            effect.operands(&mut value);
        }

        self.flags.operands(&mut value);

        if let Some(stores) = &self.stores {
            for store in stores {
                store.operands(&mut value);
            }
        }

        value
    }

    fn outputs(&self) -> usize {
        let mut value = 0;

        for effect in &self.effects {
            effect.outputs(&mut value);
        }

        if let Some(stores) = &self.stores {
            value = value.max(stores.len());
        }

        value
    }

    fn locals(&self) -> usize {
        let mut value = 0;

        for effect in &self.effects {
            effect.locals(&mut value);
        }

        self.flags.locals(&mut value);

        if let Some(stores) = &self.stores {
            for store in stores {
                store.locals(&mut value);
            }
        }

        value
    }

    fn temporaries(&self) -> usize {
        let effects = self.effects.iter().map(Effect::temporary).sum::<usize>();
        let flags = self.flags.temporary();
        let stores = self
            .stores
            .as_ref()
            .map(|stores| stores.iter().map(Expression::temporary).sum::<usize>())
            .unwrap_or(0);

        effects + flags + stores
    }
}

impl Flags {
    fn values(&self) -> &[(Flag, Expression)] {
        match self {
            Flags::Never => &[],
            Flags::Always(values) | Flags::When(_, values) => values,
        }
    }

    fn condition(&self) -> Option<&Expression> {
        match self {
            Flags::Never | Flags::Always(_) => None,
            Flags::When(condition, _) => Some(condition),
        }
    }

    fn is_empty(&self) -> bool {
        self.values().is_empty()
    }

    fn operands(&self, value: &mut usize) {
        if let Some(condition) = self.condition() {
            condition.operands(value);
        }

        for (_, expression) in self.values() {
            expression.operands(value);
        }
    }

    fn temporary(&self) -> usize {
        let condition = self.condition().map(Expression::temporary).unwrap_or(0);
        let values = self
            .values()
            .iter()
            .map(|(_, expression)| expression.temporary())
            .sum::<usize>();

        condition + values
    }

    fn locals(&self, value: &mut usize) {
        if let Some(condition) = self.condition() {
            condition.locals(value);
        }

        for (_, expression) in self.values() {
            expression.locals(value);
        }
    }
}

impl Expression {
    fn operands(&self, value: &mut usize) {
        match self {
            Expression::Operand(Operand::Input(index)) => {
                *value = (*value).max(*index + 1);
            }
            Expression::Operand(Operand::Output(_))
            | Expression::Register(_)
            | Expression::Immediate(_)
            | Expression::Local(_)
            | Expression::Flag(_)
            | Expression::SignBit
            | Expression::BitSize
            | Expression::ByteMask(_)
            | Expression::Segment => {}
            Expression::BitAnd(first, second)
            | Expression::BitOr(first, second)
            | Expression::BitXor(first, second)
            | Expression::BitShr(first, second)
            | Expression::BitShl(first, second)
            | Expression::Add(first, second)
            | Expression::Sub(first, second)
            | Expression::Mul(first, second) => {
                first.operands(value);
                second.operands(value);
            }
            Expression::BitNot(inner)
            | Expression::LowByte(inner)
            | Expression::Parity(inner)
            | Expression::Extend(inner, _)
            | Expression::Memory(inner) => {
                inner.operands(value);
            }
            Expression::Compare(compare) => compare.operands(value),
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Expression::Operand(_)
            | Expression::Immediate(Immediate::Fixed(_))
            | Expression::SignBit
            | Expression::BitSize
            | Expression::ByteMask(_) => 0,
            Expression::Register(_)
            | Expression::Local(_)
            | Expression::Flag(_)
            | Expression::Segment => 1,
            Expression::BitAnd(first, second)
            | Expression::BitOr(first, second)
            | Expression::BitXor(first, second)
            | Expression::BitShr(first, second)
            | Expression::BitShl(first, second)
            | Expression::Add(first, second)
            | Expression::Sub(first, second)
            | Expression::Mul(first, second) => 1 + first.temporary() + second.temporary(),
            Expression::BitNot(inner)
            | Expression::LowByte(inner)
            | Expression::Parity(inner)
            | Expression::Extend(inner, _)
            | Expression::Memory(inner) => 1 + inner.temporary(),
            Expression::Compare(compare) => 1 + compare.temporary(),
        }
    }

    fn locals(&self, value: &mut usize) {
        match self {
            Expression::Local(index) => {
                *value = (*value).max(*index + 1);
            }
            Expression::Operand(_)
            | Expression::Register(_)
            | Expression::Immediate(_)
            | Expression::Flag(_)
            | Expression::SignBit
            | Expression::BitSize
            | Expression::ByteMask(_)
            | Expression::Segment => {}
            Expression::BitAnd(first, second)
            | Expression::BitOr(first, second)
            | Expression::BitXor(first, second)
            | Expression::BitShr(first, second)
            | Expression::BitShl(first, second)
            | Expression::Add(first, second)
            | Expression::Sub(first, second)
            | Expression::Mul(first, second) => {
                first.locals(value);
                second.locals(value);
            }
            Expression::BitNot(inner)
            | Expression::LowByte(inner)
            | Expression::Parity(inner)
            | Expression::Extend(inner, _)
            | Expression::Memory(inner) => {
                inner.locals(value);
            }
            Expression::Compare(compare) => compare.locals(value),
        }
    }
}

impl Effect {
    fn operands(&self, value: &mut usize) {
        match self {
            Effect::Add(first, second)
            | Effect::Sub(first, second)
            | Effect::And(first, second)
            | Effect::Or(first, second)
            | Effect::Xor(first, second)
            | Effect::Shr(first, second)
            | Effect::Shl(first, second)
            | Effect::Ror(first, second)
            | Effect::Rol(first, second)
            | Effect::Mul(first, second)
            | Effect::Sar(first, second)
            | Effect::Exchange(first, second)
            | Effect::ExchangeAdd(first, second) => {
                first.operands(value);
                second.operands(value);
            }
            Effect::Div(first, second, third) => {
                first.operands(value);
                second.operands(value);
                third.operands(value);
            }
            Effect::CompareExchange(first, second, third) => {
                first.operands(value);
                second.operands(value);
                third.operands(value);
            }
            Effect::Memory(first, second) => {
                first.operands(value);
                second.operands(value);
            }
            Effect::Push(expression)
            | Effect::Bsr(expression)
            | Effect::Tzcnt(expression)
            | Effect::Register(_, expression)
            | Effect::Assign(_, expression)
            | Effect::Advance(expression)
            | Effect::Drop(expression) => {
                expression.operands(value);
            }
            Effect::Select(selector, arms) => {
                selector.operands(value);
                for (_, body) in arms {
                    for effect in body {
                        effect.operands(value);
                    }
                }
            }
            Effect::When(condition, body) => {
                condition.operands(value);
                for effect in body {
                    effect.operands(value);
                }
            }
            Effect::Loop(_, body) => {
                for effect in body {
                    effect.operands(value);
                }
            }
            Effect::Read(..) | Effect::Vector(_) | Effect::Cpuid | Effect::Timestamp => {}
        }
    }

    fn locals(&self, value: &mut usize) {
        match self {
            Effect::Assign(index, expression) => {
                *value = (*value).max(*index + 1);
                expression.locals(value);
            }
            Effect::Read(index, _) => {
                *value = (*value).max(*index + 1);
            }
            Effect::Loop(counter, body) => {
                *value = (*value).max(*counter + 1);
                for effect in body {
                    effect.locals(value);
                }
            }
            Effect::Add(first, second)
            | Effect::Sub(first, second)
            | Effect::And(first, second)
            | Effect::Or(first, second)
            | Effect::Xor(first, second)
            | Effect::Shr(first, second)
            | Effect::Shl(first, second)
            | Effect::Ror(first, second)
            | Effect::Rol(first, second)
            | Effect::Mul(first, second)
            | Effect::Sar(first, second)
            | Effect::Exchange(first, second)
            | Effect::ExchangeAdd(first, second)
            | Effect::Memory(first, second) => {
                first.locals(value);
                second.locals(value);
            }
            Effect::Div(first, second, third) | Effect::CompareExchange(first, second, third) => {
                first.locals(value);
                second.locals(value);
                third.locals(value);
            }
            Effect::Push(expression)
            | Effect::Bsr(expression)
            | Effect::Tzcnt(expression)
            | Effect::Register(_, expression)
            | Effect::Advance(expression)
            | Effect::Drop(expression) => {
                expression.locals(value);
            }
            Effect::Select(selector, arms) => {
                selector.locals(value);
                for (_, body) in arms {
                    for effect in body {
                        effect.locals(value);
                    }
                }
            }
            Effect::When(condition, body) => {
                condition.locals(value);
                for effect in body {
                    effect.locals(value);
                }
            }
            Effect::Vector(_) | Effect::Cpuid | Effect::Timestamp => {}
        }
    }

    fn outputs(&self, value: &mut usize) {
        match self {
            Effect::Add(..)
            | Effect::Sub(..)
            | Effect::And(..)
            | Effect::Or(..)
            | Effect::Xor(..)
            | Effect::Shr(..)
            | Effect::Shl(..)
            | Effect::Ror(..)
            | Effect::Rol(..)
            | Effect::Sar(..)
            | Effect::Push(..)
            | Effect::Bsr(..)
            | Effect::Tzcnt(..)
            | Effect::Exchange(..)
            | Effect::CompareExchange(..) => {
                *value = (*value).max(1);
            }
            Effect::Mul(..) | Effect::Div(..) | Effect::ExchangeAdd(..) => {
                *value = (*value).max(2);
            }
            Effect::Select(_, arms) => {
                for (_, body) in arms {
                    for effect in body {
                        effect.outputs(value);
                    }
                }
            }
            Effect::When(_, body) | Effect::Loop(_, body) => {
                for effect in body {
                    effect.outputs(value);
                }
            }
            Effect::Register(..)
            | Effect::Memory(..)
            | Effect::Assign(..)
            | Effect::Read(..)
            | Effect::Advance(..)
            | Effect::Drop(..)
            | Effect::Vector(..)
            | Effect::Cpuid
            | Effect::Timestamp => {}
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Effect::Add(first, second)
            | Effect::Sub(first, second)
            | Effect::And(first, second)
            | Effect::Or(first, second)
            | Effect::Xor(first, second)
            | Effect::Shr(first, second)
            | Effect::Shl(first, second)
            | Effect::Ror(first, second)
            | Effect::Rol(first, second)
            | Effect::Mul(first, second)
            | Effect::Sar(first, second)
            | Effect::Exchange(first, second)
            | Effect::ExchangeAdd(first, second) => first.temporary() + second.temporary(),
            Effect::Div(first, second, third) => {
                first.temporary() + second.temporary() + third.temporary()
            }
            Effect::CompareExchange(first, second, third) => {
                first.temporary() + second.temporary() + third.temporary()
            }
            Effect::Memory(first, second) => first.temporary() + second.temporary(),
            Effect::Push(expression)
            | Effect::Bsr(expression)
            | Effect::Tzcnt(expression)
            | Effect::Register(_, expression)
            | Effect::Assign(_, expression)
            | Effect::Advance(expression)
            | Effect::Drop(expression) => expression.temporary(),
            Effect::Select(selector, arms) => {
                selector.temporary()
                    + arms
                        .iter()
                        .flat_map(|(_, body)| body)
                        .map(Effect::temporary)
                        .sum::<usize>()
            }
            Effect::When(condition, body) => {
                condition.temporary() + body.iter().map(Effect::temporary).sum::<usize>()
            }
            Effect::Loop(_, body) => body.iter().map(Effect::temporary).sum::<usize>(),
            Effect::Read(..) | Effect::Vector(_) | Effect::Cpuid | Effect::Timestamp => 0,
        }
    }
}

impl Compare {
    fn operands(&self, value: &mut usize) {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => {
                first.operands(value);
                second.operands(value);
            }
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => first.temporary() + second.temporary(),
        }
    }

    fn locals(&self, value: &mut usize) {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => {
                first.locals(value);
                second.locals(value);
            }
        }
    }
}

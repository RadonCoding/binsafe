use crate::vm::bytecode::{Flag, VMWidth};

mod allocator;
pub mod compiler;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Input(usize),
    Output(usize),
}

#[derive(Debug, Clone)]
pub enum Expression {
    Operand(Operand),
    Constant(u64),
    BitAnd(Box<Expression>, Box<Expression>),
    BitOr(Box<Expression>, Box<Expression>),
    BitXor(Box<Expression>, Box<Expression>),
    BitShr(Box<Expression>, Box<Expression>),
    BitShl(Box<Expression>, Box<Expression>),
    BitNot(Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    LowByte(Box<Expression>),
    Compare(Box<Compare>),
    Parity(Box<Expression>),
    Flag(Flag),
    SignBit,
    BitSize,
    ByteMask(usize),
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
    Assign(Expression),
    Sar(Expression, Expression),
    Bsr(Expression),
    Tzcnt(Expression),
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
    Temporary(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reference {
    Value(Value),
    Immediate(i64),
}

// TODO: Implement a mixed-boolean-arithmetic engine!

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
            Flags::Always(values) | Flags::When(_, values) => values,
        }
    }

    fn condition(&self) -> Option<&Expression> {
        match self {
            Flags::Always(_) => None,
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
}

impl Expression {
    fn operands(&self, value: &mut usize) {
        match self {
            Expression::Operand(Operand::Input(index)) => {
                *value = (*value).max(*index + 1);
            }
            Expression::Operand(Operand::Output(_))
            | Expression::Constant(_)
            | Expression::Flag(_)
            | Expression::SignBit
            | Expression::BitSize
            | Expression::ByteMask(_) => {}
            Expression::BitAnd(lhs, rhs)
            | Expression::BitOr(lhs, rhs)
            | Expression::BitXor(lhs, rhs)
            | Expression::BitShr(lhs, rhs)
            | Expression::BitShl(lhs, rhs)
            | Expression::Sub(lhs, rhs) => {
                lhs.operands(value);
                rhs.operands(value);
            }
            Expression::BitNot(inner) | Expression::LowByte(inner) | Expression::Parity(inner) => {
                inner.operands(value);
            }
            Expression::Compare(compare) => compare.operands(value),
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Expression::Operand(_)
            | Expression::Constant(_)
            | Expression::SignBit
            | Expression::BitSize
            | Expression::ByteMask(_) => 0,
            Expression::Flag(_) => 1,
            Expression::BitAnd(lhs, rhs)
            | Expression::BitOr(lhs, rhs)
            | Expression::BitXor(lhs, rhs)
            | Expression::BitShr(lhs, rhs)
            | Expression::BitShl(lhs, rhs)
            | Expression::Sub(lhs, rhs) => 1 + lhs.temporary() + rhs.temporary(),
            Expression::BitNot(inner) | Expression::LowByte(inner) | Expression::Parity(inner) => {
                1 + inner.temporary()
            }
            Expression::Compare(compare) => 1 + compare.temporary(),
        }
    }
}

impl Effect {
    fn operands(&self, value: &mut usize) {
        match self {
            Effect::Add(lhs, rhs)
            | Effect::Sub(lhs, rhs)
            | Effect::And(lhs, rhs)
            | Effect::Or(lhs, rhs)
            | Effect::Xor(lhs, rhs)
            | Effect::Shr(lhs, rhs)
            | Effect::Shl(lhs, rhs)
            | Effect::Ror(lhs, rhs)
            | Effect::Rol(lhs, rhs)
            | Effect::Mul(lhs, rhs)
            | Effect::Sar(lhs, rhs) => {
                lhs.operands(value);
                rhs.operands(value);
            }
            Effect::Div(divisor, low, high) => {
                divisor.operands(value);
                low.operands(value);
                high.operands(value);
            }
            Effect::Assign(expression) | Effect::Bsr(expression) | Effect::Tzcnt(expression) => {
                expression.operands(value);
            }
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
            | Effect::Assign(..)
            | Effect::Bsr(..)
            | Effect::Tzcnt(..) => {
                *value = (*value).max(1);
            }
            Effect::Mul(..) | Effect::Div(..) => {
                *value = (*value).max(2);
            }
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Effect::Add(lhs, rhs)
            | Effect::Sub(lhs, rhs)
            | Effect::And(lhs, rhs)
            | Effect::Or(lhs, rhs)
            | Effect::Xor(lhs, rhs)
            | Effect::Shr(lhs, rhs)
            | Effect::Shl(lhs, rhs)
            | Effect::Ror(lhs, rhs)
            | Effect::Rol(lhs, rhs)
            | Effect::Mul(lhs, rhs)
            | Effect::Sar(lhs, rhs) => lhs.temporary() + rhs.temporary(),
            Effect::Div(divisor, low, high) => {
                divisor.temporary() + low.temporary() + high.temporary()
            }
            Effect::Assign(expression) | Effect::Bsr(expression) | Effect::Tzcnt(expression) => {
                expression.temporary()
            }
        }
    }
}

impl Compare {
    fn operands(&self, value: &mut usize) {
        match self {
            Compare::Equal(lhs, rhs)
            | Compare::LessThan(lhs, rhs)
            | Compare::GreaterThan(lhs, rhs)
            | Compare::BitSet(lhs, rhs) => {
                lhs.operands(value);
                rhs.operands(value);
            }
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Compare::Equal(lhs, rhs)
            | Compare::LessThan(lhs, rhs)
            | Compare::GreaterThan(lhs, rhs)
            | Compare::BitSet(lhs, rhs) => lhs.temporary() + rhs.temporary(),
        }
    }
}

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{
            self, Compare, Effect, Expression, Flags, Immediate, Operand, Operation,
        },
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Xor(
            Expression::Operand(Operand::Input(0)),
            Expression::Operand(Operand::Input(1)),
        )],
        flags: Flags::Always(vec![
            (
                Flag::Carry,
                Expression::Compare(Box::new(Compare::Equal(
                    Expression::Immediate(Immediate::Fixed(1)),
                    Expression::Immediate(Immediate::Fixed(0)),
                ))),
            ),
            (
                Flag::Overflow,
                Expression::Compare(Box::new(Compare::Equal(
                    Expression::Immediate(Immediate::Fixed(1)),
                    Expression::Immediate(Immediate::Fixed(0)),
                ))),
            ),
            (
                Flag::Sign,
                Expression::Compare(Box::new(Compare::BitSet(
                    Expression::Operand(Operand::Output(0)),
                    Expression::SignBit,
                ))),
            ),
            (
                Flag::Zero,
                Expression::Compare(Box::new(Compare::Equal(
                    Expression::Operand(Operand::Output(0)),
                    Expression::Immediate(Immediate::Fixed(0)),
                ))),
            ),
            (
                Flag::Parity,
                Expression::Parity(Box::new(Expression::Operand(Operand::Output(0)))),
            ),
        ]),
        stores: None,
        widths: &[
            VMWidth::Lower64,
            VMWidth::Lower32,
            VMWidth::Lower16,
            VMWidth::Lower8,
        ],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

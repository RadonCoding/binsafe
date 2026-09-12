use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Effect, Expression, Condition, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![Effect::Or(
                Expression::Operand(Operand::InputA),
                Expression::Operand(Operand::InputB),
            )],
            flags: vec![
                (
                    Flag::Carry,
                    Condition::Compare(Compare::Equal(
                        Expression::Constant(1),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Overflow,
                    Condition::Compare(Compare::Equal(
                        Expression::Constant(1),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Sign,
                    Condition::Compare(Compare::BitSet(
                        Expression::Operand(Operand::OutputA),
                        Expression::SignBit,
                    )),
                ),
                (
                    Flag::Zero,
                    Condition::Compare(Compare::Equal(
                        Expression::Operand(Operand::OutputA),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Parity,
                    Condition::Parity(Expression::Operand(Operand::OutputA)),
                ),
            ],
            stores: None,
            widths: &[
                VMWidth::Lower64,
                VMWidth::Lower32,
                VMWidth::Lower16,
                VMWidth::Lower8,
            ],
            operands: 2,
        },
    );
}

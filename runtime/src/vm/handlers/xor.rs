use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Effect, Expression, FlagDef, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![Effect::Xor(
                Expression::Operand(Operand::A),
                Expression::Operand(Operand::B),
            )],
            flags: vec![
                (
                    Flag::Carry,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Constant(1),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Overflow,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Constant(1),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Sign,
                    FlagDef::Compare(Compare::BitSet(
                        Expression::Operand(Operand::Result),
                        Expression::Constant(63),
                    )),
                ),
                (
                    Flag::Zero,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Operand(Operand::Result),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Parity,
                    FlagDef::Parity(Expression::Operand(Operand::Result)),
                ),
            ],
            store: None,
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

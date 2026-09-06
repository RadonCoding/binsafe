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
            effects: vec![Effect::Sub(
                Expression::Operand(Operand::A),
                Expression::Operand(Operand::B),
            )],
            flags: vec![
                (
                    Flag::Zero,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Operand(Operand::Result),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Sign,
                    FlagDef::Compare(Compare::BitSet(
                        Expression::Operand(Operand::Result),
                        Expression::SignBit,
                    )),
                ),
                (
                    Flag::Carry,
                    FlagDef::Compare(Compare::LessThan(
                        Expression::Operand(Operand::A),
                        Expression::Operand(Operand::B),
                    )),
                ),
                (
                    Flag::Overflow,
                    FlagDef::Compare(Compare::BitSet(
                        Expression::BitAnd(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::A)),
                                Box::new(Expression::Operand(Operand::B)),
                            )),
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::A)),
                                Box::new(Expression::Operand(Operand::Result)),
                            )),
                        ),
                        Expression::SignBit,
                    )),
                ),
                (
                    Flag::Parity,
                    FlagDef::Parity(Expression::Operand(Operand::Result)),
                ),
                (
                    Flag::Auxiliary,
                    FlagDef::Compare(Compare::BitSet(
                        Expression::BitXor(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::A)),
                                Box::new(Expression::Operand(Operand::B)),
                            )),
                            Box::new(Expression::Operand(Operand::Result)),
                        ),
                        Expression::Constant(4),
                    )),
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

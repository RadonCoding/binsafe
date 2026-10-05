use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Effect, Expression, Flags, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(
        rt,
        &Operation {
            effects: vec![Effect::Sub(
                Expression::Operand(Operand::Input(0)),
                Expression::Sub(
                    Box::new(Expression::Sub(
                        Box::new(Expression::Operand(Operand::Input(1))),
                        Box::new(Expression::BitNot(Box::new(Expression::Flag(Flag::Carry)))),
                    )),
                    Box::new(Expression::Constant(1)),
                ),
            )],
            flags: Flags::Always(vec![
                (
                    Flag::Zero,
                    Expression::Compare(Box::new(Compare::Equal(
                        Expression::Operand(Operand::Output(0)),
                        Expression::Constant(0),
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
                    Flag::Carry,
                    Expression::Compare(Box::new(Compare::BitSet(
                        Expression::BitOr(
                            Box::new(Expression::BitAnd(
                                Box::new(Expression::BitNot(Box::new(Expression::Operand(
                                    Operand::Input(0),
                                )))),
                                Box::new(Expression::Operand(Operand::Input(1))),
                            )),
                            Box::new(Expression::BitAnd(
                                Box::new(Expression::BitNot(Box::new(Expression::BitXor(
                                    Box::new(Expression::Operand(Operand::Input(0))),
                                    Box::new(Expression::Operand(Operand::Input(1))),
                                )))),
                                Box::new(Expression::Operand(Operand::Output(0))),
                            )),
                        ),
                        Expression::SignBit,
                    ))),
                ),
                (
                    Flag::Overflow,
                    Expression::Compare(Box::new(Compare::BitSet(
                        Expression::BitAnd(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::Input(0))),
                                Box::new(Expression::Operand(Operand::Input(1))),
                            )),
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::Input(0))),
                                Box::new(Expression::Operand(Operand::Output(0))),
                            )),
                        ),
                        Expression::SignBit,
                    ))),
                ),
                (
                    Flag::Parity,
                    Expression::Parity(Box::new(Expression::Operand(Operand::Output(0)))),
                ),
                (
                    Flag::Auxiliary,
                    Expression::Compare(Box::new(Compare::BitSet(
                        Expression::BitXor(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::Input(0))),
                                Box::new(Expression::Operand(Operand::Input(1))),
                            )),
                            Box::new(Expression::Operand(Operand::Output(0))),
                        ),
                        Expression::Constant(4),
                    ))),
                ),
            ]),
            stores: None,
            widths: &[
                VMWidth::Lower64,
                VMWidth::Lower32,
                VMWidth::Lower16,
                VMWidth::Lower8,
            ],
        },
    );
}

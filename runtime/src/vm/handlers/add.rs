use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Condition, Effect, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![Effect::Add(
                Expression::Operand(Operand::Input(0)),
                Expression::Operand(Operand::Input(1)),
            )],
            flags: vec![
                (
                    Flag::Zero,
                    Condition::Compare(Compare::Equal(
                        Expression::Operand(Operand::Output(0)),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Sign,
                    Condition::Compare(Compare::BitSet(
                        Expression::Operand(Operand::Output(0)),
                        Expression::SignBit,
                    )),
                ),
                (
                    Flag::Carry,
                    Condition::Compare(Compare::LessThan(
                        Expression::Operand(Operand::Output(0)),
                        Expression::Operand(Operand::Input(0)),
                    )),
                ),
                (
                    Flag::Overflow,
                    Condition::Compare(Compare::BitSet(
                        Expression::BitAnd(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::Input(0))),
                                Box::new(Expression::Operand(Operand::Output(0))),
                            )),
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::Input(1))),
                                Box::new(Expression::Operand(Operand::Output(0))),
                            )),
                        ),
                        Expression::SignBit,
                    )),
                ),
                (
                    Flag::Parity,
                    Condition::Parity(Expression::Operand(Operand::Output(0))),
                ),
                (
                    Flag::Auxiliary,
                    Condition::Compare(Compare::BitSet(
                        Expression::BitXor(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::Input(0))),
                                Box::new(Expression::Operand(Operand::Input(1))),
                            )),
                            Box::new(Expression::Operand(Operand::Output(0))),
                        ),
                        Expression::Constant(4),
                    )),
                ),
            ],
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

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
            effects: vec![Effect::Sub(
                Expression::Operand(Operand::InputA),
                Expression::Operand(Operand::InputB),
            )],
            flags: vec![
                (
                    Flag::Zero,
                    Condition::Compare(Compare::Equal(
                        Expression::Operand(Operand::OutputA),
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
                    Flag::Carry,
                    Condition::Compare(Compare::LessThan(
                        Expression::Operand(Operand::InputA),
                        Expression::Operand(Operand::InputB),
                    )),
                ),
                (
                    Flag::Overflow,
                    Condition::Compare(Compare::BitSet(
                        Expression::BitAnd(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::InputA)),
                                Box::new(Expression::Operand(Operand::InputB)),
                            )),
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::InputA)),
                                Box::new(Expression::Operand(Operand::OutputA)),
                            )),
                        ),
                        Expression::SignBit,
                    )),
                ),
                (
                    Flag::Parity,
                    Condition::Parity(Expression::Operand(Operand::OutputA)),
                ),
                (
                    Flag::Auxiliary,
                    Condition::Compare(Compare::BitSet(
                        Expression::BitXor(
                            Box::new(Expression::BitXor(
                                Box::new(Expression::Operand(Operand::InputA)),
                                Box::new(Expression::Operand(Operand::InputB)),
                            )),
                            Box::new(Expression::Operand(Operand::OutputA)),
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
            operands: 2,
        },
    );
}

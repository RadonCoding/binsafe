use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Condition, Effect, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(
        rt,
        &Operation {
            effects: vec![Effect::Mul(
                Expression::Operand(Operand::Input(0)),
                Expression::Operand(Operand::Input(1)),
            )],
            flags: vec![
                (
                    Flag::Carry,
                    Condition::Compare(Compare::GreaterThan(
                        Expression::Sub(
                            Box::new(Expression::Operand(Operand::Output(1))),
                            Box::new(Expression::Sub(
                                Box::new(Expression::Constant(0)),
                                Box::new(Expression::BitShr(
                                    Box::new(Expression::Operand(Operand::Output(0))),
                                    Box::new(Expression::SignBit),
                                )),
                            )),
                        ),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Overflow,
                    Condition::Compare(Compare::GreaterThan(
                        Expression::Sub(
                            Box::new(Expression::Operand(Operand::Output(1))),
                            Box::new(Expression::Sub(
                                Box::new(Expression::Constant(0)),
                                Box::new(Expression::BitShr(
                                    Box::new(Expression::Operand(Operand::Output(0))),
                                    Box::new(Expression::SignBit),
                                )),
                            )),
                        ),
                        Expression::Constant(0),
                    )),
                ),
            ],
            stores: None,
            widths: &[
                VMWidth::Lower64,
                VMWidth::Lower32,
                VMWidth::Lower16,
                VMWidth::Lower8,
                VMWidth::SLower64,
                VMWidth::SLower32,
                VMWidth::SLower16,
                VMWidth::SLower8,
            ],
        },
    );
}

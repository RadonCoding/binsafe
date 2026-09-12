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
            effects: vec![Effect::Or(
                Expression::Operand(Operand::InputA),
                Expression::BitShl(
                    Box::new(Expression::Constant(1)),
                    Box::new(Expression::Operand(Operand::InputB)),
                ),
            )],
            flags: vec![(
                Flag::Carry,
                Condition::Compare(Compare::BitSet(
                    Expression::Operand(Operand::InputA),
                    Expression::Operand(Operand::InputB),
                )),
            )],
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

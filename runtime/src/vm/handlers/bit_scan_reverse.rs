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
            effects: vec![Effect::Bsr(Expression::Operand(Operand::InputA))],
            flags: vec![(
                Flag::Zero,
                Condition::Compare(Compare::Equal(
                    Expression::Operand(Operand::InputA),
                    Expression::Constant(0),
                )),
            )],
            stores: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
            operands: 1,
        },
    );
}

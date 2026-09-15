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
            effects: vec![Effect::Bsr(Expression::Operand(Operand::Input(0)))],
            flags: vec![(
                Flag::Zero,
                Condition::Compare(Compare::Equal(
                    Expression::Operand(Operand::Input(0)),
                    Expression::Constant(0),
                )),
            )],
            stores: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
        },
    );
}

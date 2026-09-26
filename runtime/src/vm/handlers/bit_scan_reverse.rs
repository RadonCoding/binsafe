use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Flags, Compare, Effect, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(
        rt,
        &Operation {
            effects: vec![
                Effect::Assign(Expression::Operand(Operand::Input(0))),
                Effect::Bsr(Expression::Operand(Operand::Input(1))),
            ],
            flags: Flags::Always(vec![(
                Flag::Zero,
                Expression::Compare(Box::new(Compare::Equal(
                    Expression::Operand(Operand::Input(1)),
                    Expression::Constant(0),
                ))),
            )]),
            stores: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
        },
    );
}

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{
            self, Compare, Effect, Expression, Flags, Immediate, Operand, Operation,
        },
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![
            Effect::Push(Expression::Operand(Operand::Input(0))),
            Effect::Bsr(Expression::Operand(Operand::Input(1))),
        ],
        flags: Flags::Always(vec![(
            Flag::Zero,
            Expression::Compare(Box::new(Compare::Equal(
                Expression::Operand(Operand::Input(1)),
                Expression::Immediate(Immediate::Fixed(0)),
            ))),
        )]),
        stores: None,
        widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

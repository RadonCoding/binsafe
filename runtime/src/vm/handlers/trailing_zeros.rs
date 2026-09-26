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
            effects: vec![Effect::Tzcnt(Expression::Operand(Operand::Input(0)))],
            flags: Flags::Always(vec![
                (
                    Flag::Carry,
                    Expression::Compare(Box::new(Compare::Equal(
                        Expression::Operand(Operand::Input(0)),
                        Expression::Constant(0),
                    ))),
                ),
                (
                    Flag::Zero,
                    Expression::Compare(Box::new(Compare::Equal(
                        Expression::Operand(Operand::Output(0)),
                        Expression::Constant(0),
                    ))),
                ),
            ]),
            stores: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
        },
    );
}

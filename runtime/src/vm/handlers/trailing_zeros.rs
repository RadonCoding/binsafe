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
            effects: vec![Effect::Tzcnt(Expression::Operand(Operand::Input(0)))],
            flags: vec![
                (
                    Flag::Carry,
                    Condition::Compare(Compare::Equal(
                        Expression::Operand(Operand::Input(0)),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Zero,
                    Condition::Compare(Compare::Equal(
                        Expression::Operand(Operand::Output(0)),
                        Expression::Constant(0),
                    )),
                ),
            ],
            stores: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
        },
    );
}

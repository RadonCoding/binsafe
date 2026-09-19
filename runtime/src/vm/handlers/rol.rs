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
            effects: vec![Effect::Rol(
                Expression::Operand(Operand::Input(0)),
                Expression::Operand(Operand::Input(1)),
            )],
            flags: vec![
                (
                    Flag::Carry,
                    Condition::Compare(Compare::BitSet(
                        Expression::Operand(Operand::Output(0)),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Overflow,
                    Condition::Compare(Compare::Equal(
                        Expression::Constant(1),
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
            ],
        },
    );
}

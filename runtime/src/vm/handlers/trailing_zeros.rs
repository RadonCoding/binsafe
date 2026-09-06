use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Effect, Expression, FlagDef, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![Effect::Tzcnt(Expression::Operand(Operand::A))],
            flags: vec![
                (
                    Flag::Carry,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Operand(Operand::A),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Zero,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Operand(Operand::Result),
                        Expression::Constant(0),
                    )),
                ),
            ],
            store: None,
            widths: &[
                VMWidth::Lower64,
                VMWidth::Lower32,
                VMWidth::Lower16,
                VMWidth::Lower8,
            ],
            operands: 1,
        },
    );
}

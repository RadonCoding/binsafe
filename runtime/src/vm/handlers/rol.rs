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
            effects: vec![Effect::Rol(
                Expression::Operand(Operand::A),
                Expression::Operand(Operand::B),
            )],
            flags: vec![
                (
                    Flag::Carry,
                    FlagDef::Compare(Compare::BitSet(
                        Expression::Operand(Operand::Result),
                        Expression::Constant(0),
                    )),
                ),
                (
                    Flag::Overflow,
                    FlagDef::Compare(Compare::Equal(
                        Expression::Constant(1),
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
            operands: 2,
        },
    );
}

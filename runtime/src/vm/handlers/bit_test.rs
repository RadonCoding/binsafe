use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Expression, FlagDef, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![],
            flags: vec![(
                Flag::Carry,
                FlagDef::Compare(Compare::BitSet(
                    Expression::Operand(Operand::A),
                    Expression::Operand(Operand::B),
                )),
            )],
            store: Some(Expression::Operand(Operand::A)),
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

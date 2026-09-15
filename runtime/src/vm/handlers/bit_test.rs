use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Condition, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![],
            flags: vec![(
                Flag::Carry,
                Condition::Compare(Compare::BitSet(
                    Expression::Operand(Operand::Input(0)),
                    Expression::Operand(Operand::Input(1)),
                )),
            )],
            stores: Some(vec![Expression::Operand(Operand::Input(0))]),
            widths: &[
                VMWidth::Lower64,
                VMWidth::Lower32,
                VMWidth::Lower16,
                VMWidth::Lower8,
            ],
        },
    );
}

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
            effects: vec![Effect::Bsr(Expression::Operand(Operand::A))],
            flags: vec![(
                Flag::Zero,
                FlagDef::Compare(Compare::Equal(
                    Expression::Operand(Operand::A),
                    Expression::Constant(0),
                )),
            )],
            store: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
            operands: 1,
        },
    );
}

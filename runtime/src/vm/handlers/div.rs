use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, Effect, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(
        rt,
        &Operation {
            effects: vec![Effect::Div(
                Expression::Operand(Operand::Input(0)),
                Expression::Operand(Operand::Input(1)),
                Expression::Operand(Operand::Input(2)),
            )],
            flags: vec![],
            stores: None,
            widths: &[
                VMWidth::Lower64,
                VMWidth::Lower32,
                VMWidth::Lower16,
                VMWidth::Lower8,
                VMWidth::SLower64,
                VMWidth::SLower32,
                VMWidth::SLower16,
                VMWidth::SLower8,
            ],
        },
    );
}

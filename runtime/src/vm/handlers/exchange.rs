use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, Effect, Expression, Flags, Operand, Operation},
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Exchange(
            Expression::Operand(Operand::Input(0)),
            Expression::Operand(Operand::Input(1)),
        )],
        flags: Flags::Never,
        stores: None,
        widths: &[
            VMWidth::Lower64,
            VMWidth::Lower32,
            VMWidth::Lower16,
            VMWidth::Lower8,
        ],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

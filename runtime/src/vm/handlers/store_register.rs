use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, Effect, Expression, Flags, Operand, Operation, Register},
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Register(
            Register::Operand,
            Expression::Operand(Operand::Input(0)),
        )],
        flags: Flags::Never,
        stores: None,
        widths: &[
            VMWidth::Lower64,
            VMWidth::Lower32,
            VMWidth::Lower16,
            VMWidth::Higher8,
            VMWidth::Lower8,
        ],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

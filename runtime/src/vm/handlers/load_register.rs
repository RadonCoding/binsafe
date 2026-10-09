use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, Effect, Expression, Flags, Operation, Register},
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Push(Expression::Register(Register::Operand))],
        flags: Flags::Never,
        stores: None,
        widths: &[
            VMWidth::Lower64,
            VMWidth::Lower32,
            VMWidth::Lower16,
            VMWidth::Higher8,
            VMWidth::Lower8,
            VMWidth::SLower64,
            VMWidth::SLower32,
            VMWidth::SLower16,
            VMWidth::SLower8,
        ],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

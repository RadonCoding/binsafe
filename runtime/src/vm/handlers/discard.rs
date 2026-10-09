use crate::{
    runtime::Runtime,
    vm::handlers::semantic::{self, Effect, Expression, Flags, Operand, Operation},
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Drop(Expression::Operand(Operand::Input(0)))],
        flags: Flags::Never,
        stores: None,
        widths: &[],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

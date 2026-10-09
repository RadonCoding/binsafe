use crate::{
    runtime::Runtime,
    vm::handlers::semantic::{self, Effect, Flags, Operation, Vector},
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Vector(Vector::Mul)],
        flags: Flags::Never,
        stores: None,
        widths: &[],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

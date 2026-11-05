use crate::{
    runtime::Runtime,
    vm::handlers::semantic::{self, builder, Operation},
};

pub fn operation() -> Operation {
    builder::build(|b| {
        b.drop(b.input(0));
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

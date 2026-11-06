use crate::{
    runtime::Runtime,
    vm::handlers::semantic::{self, builder, Operation},
};

pub fn operation() -> Operation {
    builder::build(|b| {
        let (low, high) = b.timestamp();

        b.outputs(vec![low, high]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

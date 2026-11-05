use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, builder, Operation},
    },
};

pub fn operation() -> Operation {
    builder::build(|b| {
        b.widths(&[
            VMWidth::Lower64,
            VMWidth::Lower32,
            VMWidth::Lower16,
            VMWidth::Higher8,
            VMWidth::Lower8,
            VMWidth::Lower128,
            VMWidth::Lower256,
        ]);

        b.store_memory(b.input(1), b.input(0));
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

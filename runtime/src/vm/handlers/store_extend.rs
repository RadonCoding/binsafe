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
            VMWidth::Lower128,
            VMWidth::Lower256,
        ]);

        b.store_extend(b.input(0));
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

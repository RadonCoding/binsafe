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
            VMWidth::Lower8,
        ]);

        let output = b.exchange(b.input(0), b.input(1));

        b.outputs(vec![output]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

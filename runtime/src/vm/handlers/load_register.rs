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
            VMWidth::SLower64,
            VMWidth::SLower32,
            VMWidth::SLower16,
            VMWidth::SLower8,
        ]);

        b.outputs(vec![b.read_register()]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

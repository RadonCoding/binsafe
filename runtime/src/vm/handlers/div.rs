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
            VMWidth::SLower64,
            VMWidth::SLower32,
            VMWidth::SLower16,
            VMWidth::SLower8,
        ]);

        let (quotient, remainder) = b.div(b.input(0), b.input(1), b.input(2));

        b.outputs(vec![remainder, quotient]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, builder, Operation},
    },
};

pub fn operation() -> Operation {
    builder::build(|b| {
        b.widths(&[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16]);

        b.outputs(vec![b.bsr(b.input(0), b.input(1))]);

        b.flags_always(vec![(Flag::Zero, b.equal(b.input(1), b.constant(0)))]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

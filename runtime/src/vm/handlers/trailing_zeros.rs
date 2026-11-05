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

        let output = b.bind(b.tzcnt(b.input(0)));

        b.outputs(vec![output]);

        b.flags_always(vec![
            (Flag::Carry, b.equal(b.input(0), b.constant(0))),
            (Flag::Zero, b.equal(output, b.constant(0))),
        ]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

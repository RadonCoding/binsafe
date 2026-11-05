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

        let base = b.input(0);

        b.flags_always(vec![(
            Flag::Carry,
            b.bit_set(base, b.bit_and(b.input(1), b.sign_bit())),
        )]);

        b.outputs(vec![base]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

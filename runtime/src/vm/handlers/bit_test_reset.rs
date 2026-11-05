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
        let offset = b.input(1);

        b.outputs(vec![b.bit_and(
            base,
            b.bit_not(b.bit_shl(b.constant(1), b.bit_and(offset, b.sign_bit()))),
        )]);

        b.flags_always(vec![(
            Flag::Carry,
            b.bit_set(base, b.bit_and(offset, b.sign_bit())),
        )]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

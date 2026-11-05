use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
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

        let output = b.bind(b.bit_and(b.input(0), b.input(1)));

        b.outputs(vec![output]);

        let cleared = b.constant(0);
        let sign = b.bit_set(output, b.sign_bit());
        let zero = b.equal(output, b.constant(0));
        let parity = b.parity(output);

        b.flags_always(vec![
            (Flag::Carry, cleared),
            (Flag::Overflow, cleared),
            (Flag::Sign, sign),
            (Flag::Zero, zero),
            (Flag::Parity, parity),
        ]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

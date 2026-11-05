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

        let (sum, previous) = b.exchange_add(b.input(0), b.input(1));

        let input = b.input(0);

        let zero = b.equal(sum, b.constant(0));
        let sign = b.bit_set(sum, b.sign_bit());
        let carried = b.less_than(sum, input);
        let overflow = b.bit_set(
            b.bit_and(b.bit_xor(input, sum), b.bit_xor(previous, sum)),
            b.sign_bit(),
        );
        let parity = b.parity(sum);
        let auxiliary = b.bit_set(b.bit_xor(b.bit_xor(input, previous), sum), b.constant(4));

        b.flags_always(vec![
            (Flag::Zero, zero),
            (Flag::Sign, sign),
            (Flag::Carry, carried),
            (Flag::Overflow, overflow),
            (Flag::Parity, parity),
            (Flag::Auxiliary, auxiliary),
        ]);

        b.outputs(vec![previous]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

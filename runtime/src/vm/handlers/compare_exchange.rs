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

        let accumulator = b.input(0);

        let actual = b.compare_exchange(accumulator, b.input(1), b.input(2));

        let difference = b.sub(accumulator, actual);

        let zero = b.equal(difference, b.constant(0));
        let sign = b.bit_set(difference, b.sign_bit());
        let borrowed = b.less_than(accumulator, actual);
        let overflow = b.bit_set(
            b.bit_and(
                b.bit_xor(accumulator, actual),
                b.bit_xor(accumulator, difference),
            ),
            b.sign_bit(),
        );
        let parity = b.parity(difference);
        let auxiliary = b.bit_set(
            b.bit_xor(b.bit_xor(accumulator, actual), difference),
            b.constant(4),
        );

        b.flags_always(vec![
            (Flag::Zero, zero),
            (Flag::Sign, sign),
            (Flag::Carry, borrowed),
            (Flag::Overflow, overflow),
            (Flag::Parity, parity),
            (Flag::Auxiliary, auxiliary),
        ]);

        b.outputs(vec![actual]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

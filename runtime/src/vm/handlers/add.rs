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

        let lhs = b.input(0);
        let rhs = b.input(1);

        let output = b.bind(b.add(lhs, rhs));

        b.outputs(vec![output]);

        let zero = b.equal(output, b.constant(0));
        let sign = b.bit_set(output, b.sign_bit());
        let carry = b.less_than(output, lhs);
        let overflow = b.bit_set(
            b.bit_and(b.bit_xor(lhs, output), b.bit_xor(rhs, output)),
            b.sign_bit(),
        );
        let parity = b.parity(output);
        let auxiliary = b.bit_set(b.bit_xor(b.bit_xor(lhs, rhs), output), b.constant(4));

        b.flags_always(vec![
            (Flag::Zero, zero),
            (Flag::Sign, sign),
            (Flag::Carry, carry),
            (Flag::Overflow, overflow),
            (Flag::Parity, parity),
            (Flag::Auxiliary, auxiliary),
        ]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

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

        let value = b.input(0);
        let amount = b.input(1);

        let output = b.bind(b.bit_shr(value, amount));

        b.outputs(vec![output]);
        let count = b.bit_and(amount, b.bit_or(b.sign_bit(), b.constant(0x1f)));

        let carry = b.bit_set(value, b.sub(count, b.constant(1)));
        let overflow = b.bit_set(value, b.sign_bit());
        let sign = b.bit_set(output, b.sign_bit());
        let zero = b.equal(output, b.constant(0));
        let parity = b.parity(output);

        b.flags_when(
            count,
            vec![
                (Flag::Carry, carry),
                (Flag::Overflow, overflow),
                (Flag::Sign, sign),
                (Flag::Zero, zero),
                (Flag::Parity, parity),
            ],
        );
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

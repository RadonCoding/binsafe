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

        let output = b.bind(b.bit_rol(value, amount));

        b.outputs(vec![output]);

        let rotated = b.bit_and(amount, b.bit_or(b.sign_bit(), b.constant(0x1f)));

        let carry = b.bit_set(output, b.constant(0));
        let overflow = b.greater_than(
            b.bit_xor(
                b.bit_shr(output, b.sign_bit()),
                b.bit_and(output, b.constant(1)),
            ),
            b.constant(0),
        );

        b.flags_when(
            rotated,
            vec![(Flag::Carry, carry), (Flag::Overflow, overflow)],
        );
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

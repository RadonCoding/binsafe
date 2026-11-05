use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, builder, Operation},
    },
};

pub fn operation() -> Operation {
    builder::build(|b| {
        b.widths(&[VMWidth::Lower64, VMWidth::Lower32]);

        let value = b.input(0);

        let output = b.variable();
        b.set(
            output,
            b.bit_and(
                b.bit_shr(value, b.sub(b.bit_size(), b.constant(8))),
                b.constant(0xFF),
            ),
        );

        for (bits, mask) in [(24, 0xFF00), (40, 0xFF_0000), (56, 0xFF_000000)] {
            b.set(
                output,
                b.bit_or(
                    b.get(output),
                    b.bit_and(
                        b.bit_shr(value, b.sub(b.bit_size(), b.constant(bits))),
                        b.constant(mask),
                    ),
                ),
            );
        }

        for (bits, lane) in [(56, 3), (40, 2), (24, 1), (8, 0)] {
            b.set(
                output,
                b.bit_or(
                    b.get(output),
                    b.bit_and(
                        b.bit_shl(value, b.sub(b.bit_size(), b.constant(bits))),
                        b.byte_mask(lane),
                    ),
                ),
            );
        }

        b.outputs(vec![b.get(output)]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

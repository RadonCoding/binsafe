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
            VMWidth::SLower64,
            VMWidth::SLower32,
            VMWidth::SLower16,
            VMWidth::SLower8,
        ]);

        let (low, high) = b.mul_wide(b.input(0), b.input(1));

        b.outputs(vec![high, low]);

        let overflowed = b.greater_than(high, b.constant(0));

        b.flags_always(vec![
            (Flag::Carry, overflowed),
            (Flag::Overflow, overflowed),
        ]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

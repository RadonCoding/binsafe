use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, builder, Operation},
    },
};

const WIDTHS: [VMWidth; 8] = [
    VMWidth::Lower64,
    VMWidth::Lower32,
    VMWidth::Lower16,
    VMWidth::Lower8,
    VMWidth::SLower64,
    VMWidth::SLower32,
    VMWidth::SLower16,
    VMWidth::SLower8,
];

pub fn operation(rt: &mut Runtime) -> Operation {
    let keys = WIDTHS.map(|width| rt.mapper.index(width) as u64);

    builder::build(|b| {
        let selector = b.read(VMWidth::Lower8);

        let value = b.select(selector, |s| {
            for (width, key) in WIDTHS.into_iter().zip(keys) {
                s.on(vec![key], move |b| b.immediate(width));
            }
        });

        b.produce(value);
    })
}

pub fn build(rt: &mut Runtime) {
    let operation = operation(rt);
    semantic::compiler::compile(rt, &operation);
}

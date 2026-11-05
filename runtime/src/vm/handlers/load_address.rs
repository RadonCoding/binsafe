use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMSeg, VMWidth},
        handlers::semantic::{self, builder, Operation},
    },
};

pub fn operation(rt: &mut Runtime) -> Operation {
    let none = vec![rt.mapper.index(VMSeg::None) as u64];
    let gs = vec![rt.mapper.index(VMSeg::Gs) as u64];

    builder::build(|b| {
        let base = b.read_register();
        let index = b.read_register();
        let scale = b.read(VMWidth::Lower8);
        let displacement = b.immediate(VMWidth::SLower32);

        let selector = b.read(VMWidth::Lower8);
        let segment = b.select(selector, |s| {
            s.on(none, |b| b.constant(0));
            s.on(gs, |b| b.segment());
        });

        let output = b.add(
            b.add(b.add(base, b.mul(index, scale)), displacement),
            segment,
        );

        b.outputs(vec![output]);
    })
}

pub fn build(rt: &mut Runtime) {
    let operation = operation(rt);
    semantic::compiler::compile(rt, &operation);
}

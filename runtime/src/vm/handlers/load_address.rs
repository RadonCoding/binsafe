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
        let base = b.register_operand();
        let index = b.register_operand();
        let scale = b.read(VMWidth::Lower8);
        let displacement = b.immediate(VMWidth::SLower32);

        let selector = b.read(VMWidth::Lower8);
        let segment = b.select(selector, |s| {
            s.on(none, |b| b.constant(0));
            s.on(gs, |b| b.segment());
        });

        let scaled = b.mul(index, scale);
        let address = b.add(base, scaled);
        let address = b.add(address, displacement);
        let address = b.add(address, segment);

        b.produce(address);
    })
}

pub fn build(rt: &mut Runtime) {
    let operation = operation(rt);
    semantic::compiler::compile(rt, &operation);
}

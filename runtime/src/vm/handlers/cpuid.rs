use crate::{
    runtime::Runtime,
    vm::handlers::semantic::{self, builder, Operation},
};

pub fn operation() -> Operation {
    builder::build(|b| {
        let (eax, ebx, ecx, edx) = b.cpuid(b.input(0), b.input(1));

        b.outputs(vec![edx, ecx, ebx, eax]);
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

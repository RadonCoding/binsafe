use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        handlers::semantic::{self, builder, Operation},
    },
};

pub fn operation() -> Operation {
    builder::build(|b| {
        b.write_register(VMReg::NBranch, b.memory(b.register(VMReg::Rsp)));
        b.write_register(
            VMReg::Rsp,
            b.add(b.register(VMReg::Rsp), b.add(b.constant(8), b.input(0))),
        );
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

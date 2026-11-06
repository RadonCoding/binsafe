use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        handlers::semantic::{self, builder, Operation},
    },
};

pub fn operation() -> Operation {
    builder::build(|b| {
        let output = b.bind(b.memory(b.register(VMReg::Rsp)));

        b.outputs(vec![output]);

        b.write_register(VMReg::Rsp, b.add(b.register(VMReg::Rsp), b.constant(8)));
    })
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

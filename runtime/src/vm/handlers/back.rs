use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        handlers::semantic::{
            self, Effect, Expression, Flags, Immediate, Operand, Operation, Register,
        },
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![
            Effect::Register(
                Register::Fixed(VMReg::NBranch),
                Expression::Memory(Box::new(Expression::Register(Register::Fixed(VMReg::Rsp)))),
            ),
            Effect::Register(
                Register::Fixed(VMReg::Rsp),
                Expression::Add(
                    Box::new(Expression::Register(Register::Fixed(VMReg::Rsp))),
                    Box::new(Expression::Add(
                        Box::new(Expression::Immediate(Immediate::Fixed(8))),
                        Box::new(Expression::Operand(Operand::Input(0))),
                    )),
                ),
            ),
        ],
        flags: Flags::Never,
        stores: None,
        widths: &[],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

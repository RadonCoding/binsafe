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
                Register::Fixed(VMReg::Rsp),
                Expression::Sub(
                    Box::new(Expression::Register(Register::Fixed(VMReg::Rsp))),
                    Box::new(Expression::Immediate(Immediate::Fixed(8))),
                ),
            ),
            Effect::Memory(
                Expression::Register(Register::Fixed(VMReg::Rsp)),
                Expression::Operand(Operand::Input(0)),
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

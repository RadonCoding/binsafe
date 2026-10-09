use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, Effect, Expression, Flags, Immediate, Operand, Operation},
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![
            Effect::Push(Expression::BitAnd(
                Box::new(Expression::BitShr(
                    Box::new(Expression::Operand(Operand::Input(0))),
                    Box::new(Expression::Sub(
                        Box::new(Expression::BitSize),
                        Box::new(Expression::Immediate(Immediate::Fixed(8))),
                    )),
                )),
                Box::new(Expression::Immediate(Immediate::Fixed(0xFF))),
            )),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShr(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(24))),
                        )),
                    )),
                    Box::new(Expression::Immediate(Immediate::Fixed(0xFF00))),
                ),
            ),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShr(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(40))),
                        )),
                    )),
                    Box::new(Expression::Immediate(Immediate::Fixed(0xFF_0000))),
                ),
            ),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShr(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(56))),
                        )),
                    )),
                    Box::new(Expression::Immediate(Immediate::Fixed(0xFF_000000))),
                ),
            ),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShl(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(56))),
                        )),
                    )),
                    Box::new(Expression::ByteMask(3)),
                ),
            ),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShl(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(40))),
                        )),
                    )),
                    Box::new(Expression::ByteMask(2)),
                ),
            ),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShl(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(24))),
                        )),
                    )),
                    Box::new(Expression::ByteMask(1)),
                ),
            ),
            Effect::Or(
                Expression::Operand(Operand::Output(0)),
                Expression::BitAnd(
                    Box::new(Expression::BitShl(
                        Box::new(Expression::Operand(Operand::Input(0))),
                        Box::new(Expression::Sub(
                            Box::new(Expression::BitSize),
                            Box::new(Expression::Immediate(Immediate::Fixed(8))),
                        )),
                    )),
                    Box::new(Expression::ByteMask(0)),
                ),
            ),
        ],
        flags: Flags::Never,
        stores: None,
        widths: &[VMWidth::Lower64, VMWidth::Lower32],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

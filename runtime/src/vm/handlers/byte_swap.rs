use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{self, Effect, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::build(
        rt,
        &Operation {
            effects: vec![
                Effect::Assign(Expression::BitAnd(
                    Box::new(Expression::BitShr(
                        Box::new(Expression::Operand(Operand::A)),
                        Box::new(Expression::Constant(56)),
                    )),
                    Box::new(Expression::Constant(0xFF)),
                )),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShr(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(40)),
                        )),
                        Box::new(Expression::Constant(0xFF00)),
                    ),
                ),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShr(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(24)),
                        )),
                        Box::new(Expression::Constant(0xFF_0000)),
                    ),
                ),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShr(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(8)),
                        )),
                        Box::new(Expression::Constant(0xFF_000000)),
                    ),
                ),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShl(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(8)),
                        )),
                        Box::new(Expression::Constant(0xFF_00000000)),
                    ),
                ),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShl(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(24)),
                        )),
                        Box::new(Expression::Constant(0xFF_0000000000)),
                    ),
                ),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShl(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(40)),
                        )),
                        Box::new(Expression::Constant(0xFF_000000000000)),
                    ),
                ),
                Effect::Or(
                    Expression::Operand(Operand::Result),
                    Expression::BitAnd(
                        Box::new(Expression::BitShl(
                            Box::new(Expression::Operand(Operand::A)),
                            Box::new(Expression::Constant(56)),
                        )),
                        Box::new(Expression::Constant(0xFF_00000000000000)),
                    ),
                ),
            ],
            flags: vec![],
            store: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32],
            operands: 1,
        },
    );
}

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{
            self, Compare, Effect, Expression, Flags, Immediate, Operand, Operation,
        },
    },
};

pub fn operation() -> Operation {
    Operation {
        effects: vec![Effect::Xor(
            Expression::Operand(Operand::Input(0)),
            Expression::BitShl(
                Box::new(Expression::Immediate(Immediate::Fixed(1))),
                Box::new(Expression::BitAnd(
                    Box::new(Expression::Operand(Operand::Input(1))),
                    Box::new(Expression::SignBit),
                )),
            ),
        )],
        flags: Flags::Always(vec![(
            Flag::Carry,
            Expression::Compare(Box::new(Compare::BitSet(
                Expression::Operand(Operand::Input(0)),
                Expression::BitAnd(
                    Box::new(Expression::Operand(Operand::Input(1))),
                    Box::new(Expression::SignBit),
                ),
            ))),
        )]),
        stores: None,
        widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
    }
}

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(rt, &operation());
}

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMWidth},
        handlers::semantic::{self, Compare, Condition, Effect, Expression, Operand, Operation},
    },
};

pub fn build(rt: &mut Runtime) {
    semantic::compiler::compile(
        rt,
        &Operation {
            effects: vec![Effect::Xor(
                Expression::Operand(Operand::Input(0)),
                Expression::BitShl(
                    Box::new(Expression::Constant(1)),
                    Box::new(Expression::BitAnd(
                        Box::new(Expression::Operand(Operand::Input(1))),
                        Box::new(Expression::SignBit),
                    )),
                ),
            )],
            flags: vec![(
                Flag::Carry,
                Condition::Compare(Compare::BitSet(
                    Expression::Operand(Operand::Input(0)),
                    Expression::BitAnd(
                        Box::new(Expression::Operand(Operand::Input(1))),
                        Box::new(Expression::SignBit),
                    ),
                )),
            )],
            stores: None,
            widths: &[VMWidth::Lower64, VMWidth::Lower32, VMWidth::Lower16],
        },
    );
}

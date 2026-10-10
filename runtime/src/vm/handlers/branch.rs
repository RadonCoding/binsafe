use crate::{
    mapper::Mappable,
    runtime::Runtime,
    vm::{
        bytecode::{VMLogic, VMReg, VMTest, VMWidth},
        handlers::semantic::{
            self,
            builder::{self, Builder, Value},
            Operation,
        },
    },
};

fn keys<T: Mappable>(rt: &mut Runtime, variants: &[T]) -> Vec<u64> {
    variants
        .iter()
        .map(|variant| rt.mapper.index(*variant) as u64)
        .collect()
}

pub fn build(rt: &mut Runtime) {
    let operation = operation(rt);
    semantic::compiler::compile(rt, &operation);
}

pub fn operation(rt: &mut Runtime) -> Operation {
    let all = keys(rt, &[VMLogic::JAND, VMLogic::CAND, VMLogic::SAND]);
    let any = keys(rt, &[VMLogic::JOR, VMLogic::COR, VMLogic::SOR]);
    let parity = keys(rt, &[VMLogic::JXOR, VMLogic::CXOR, VMLogic::SXOR]);

    let jump = keys(rt, &[VMLogic::JAND, VMLogic::JOR, VMLogic::JXOR]);
    let call = keys(rt, &[VMLogic::CAND, VMLogic::COR, VMLogic::CXOR]);
    let skip = keys(rt, &[VMLogic::SAND, VMLogic::SOR, VMLogic::SXOR]);

    let compare = keys(rt, &[VMTest::CMP]);
    let equal = keys(rt, &[VMTest::EQ]);
    let unequal = keys(rt, &[VMTest::NEQ]);

    builder::build(|b| {
        let logic = b.read(VMWidth::Lower8);
        let accumulator = b.variable();

        b.dispatch(logic, |s| {
            s.on(all.clone(), |b| {
                let value = b.constant(1);
                b.set(accumulator, value);
            });
            s.on([any.clone(), parity.clone()].concat(), |b| {
                let value = b.constant(0);
                b.set(accumulator, value);
            });
        });

        b.repeat(|b| {
            let test = b.read(VMWidth::Lower8);
            let lhs = b.read(VMWidth::Lower8);
            let lhs = b.decrypt(lhs);
            let rhs = b.read(VMWidth::Lower8);
            let rhs = b.decrypt(rhs);

            let condition = b.select(test, |s| {
                s.on(compare, |b| {
                    let lhs = b.flag(lhs);
                    b.equal(lhs, rhs)
                });
                s.on(equal, |b| {
                    let lhs = b.flag(lhs);
                    let rhs = b.flag(rhs);
                    b.equal(lhs, rhs)
                });
                s.on(unequal, |b| {
                    let lhs = b.flag(lhs);
                    let rhs = b.flag(rhs);
                    b.unequal(lhs, rhs)
                });
            });

            let fold = |b: &mut Builder, folded: Value| b.set(accumulator, folded);

            b.dispatch(logic, |s| {
                s.on(all.clone(), |b| {
                    let accumulator = b.get(accumulator);
                    let folded = b.and(accumulator, condition);
                    fold(b, folded);
                });
                s.on(any.clone(), |b| {
                    let accumulator = b.get(accumulator);
                    let folded = b.or(accumulator, condition);
                    fold(b, folded);
                });
                s.on(parity.clone(), |b| {
                    let accumulator = b.get(accumulator);
                    let folded = b.xor(accumulator, condition);
                    fold(b, folded);
                });
            });
        });

        let taken = b.get(accumulator);

        b.when(taken, |b| {
            b.dispatch(logic, |s| {
                s.on(jump, |b| {
                    let target = b.input(0);
                    b.store(VMReg::NBranch, target);
                });
                s.on(call, |b| {
                    let target = b.input(0);
                    b.store(VMReg::NBranch, target);
                    let exit = b.register(VMReg::NExit);
                    b.push(exit);
                });
                s.on(skip, |b| {
                    let distance = b.input(0);
                    b.advance(distance);
                });
            });
        });
    })
}

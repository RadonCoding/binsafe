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
            s.on(all.clone(), |b| b.set(accumulator, b.constant(1)));
            s.on([any.clone(), parity.clone()].concat(), |b| {
                b.set(accumulator, b.constant(0))
            });
        });

        b.repeat(|b| {
            let test = b.read(VMWidth::Lower8);
            let lhs = b.read(VMWidth::Lower8);
            let lhs = b.decrypt(lhs);
            let rhs = b.read(VMWidth::Lower8);
            let rhs = b.decrypt(rhs);

            let condition = b.select(test, |s| {
                s.on(compare, |b| b.equal(b.flag_set(lhs), rhs));
                s.on(equal, |b| b.equal(b.flag_set(lhs), b.flag_set(rhs)));
                s.on(unequal, |b| b.unequal(b.flag_set(lhs), b.flag_set(rhs)));
            });

            let fold = |b: &Builder, folded: Value| b.set(accumulator, folded);

            b.dispatch(logic, |s| {
                s.on(all.clone(), |b| {
                    fold(b, b.bit_and(b.get(accumulator), condition))
                });
                s.on(any.clone(), |b| {
                    fold(b, b.bit_or(b.get(accumulator), condition))
                });
                s.on(parity.clone(), |b| {
                    fold(b, b.bit_xor(b.get(accumulator), condition))
                });
            });
        });

        b.when(b.get(accumulator), |b| {
            b.dispatch(logic, |s| {
                s.on(jump, |b| b.write_register(VMReg::NBranch, b.input(0)));
                s.on(call, |b| {
                    b.write_register(VMReg::NBranch, b.input(0));
                    b.push(b.register(VMReg::NExit));
                });
                s.on(skip, |b| b.advance(b.input(0)));
            });
        });
    })
}

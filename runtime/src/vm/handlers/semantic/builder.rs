use crate::vm::{
    bytecode::{VMReg, VMWidth},
    handlers::semantic::{
        Compare, Effect, Expression, Flags, Immediate, Operand, Operation, Register,
    },
};

#[derive(Clone, Copy)]
pub struct Value(usize);

#[derive(Clone, Copy)]
pub struct Variable(usize);

pub struct Builder {
    effects: Vec<Effect>,
    values: Vec<Expression>,
    locals: usize,
}

pub struct Select<'a> {
    builder: &'a mut Builder,
    result: usize,
    arms: Vec<(Vec<u64>, Vec<Effect>)>,
}

pub struct Dispatch<'a> {
    builder: &'a mut Builder,
    arms: Vec<(Vec<u64>, Vec<Effect>)>,
}

pub fn build(program: impl FnOnce(&mut Builder)) -> Operation {
    let mut builder = Builder {
        effects: Vec::new(),
        values: Vec::new(),
        locals: 0,
    };

    program(&mut builder);

    Operation {
        effects: builder.effects,
        flags: Flags::Never,
        stores: None,
        widths: &[],
    }
}

impl Builder {
    fn local(&mut self) -> usize {
        let index = self.locals;
        self.locals += 1;
        index
    }

    fn define(&mut self, expression: Expression) -> Value {
        let value = Value(self.values.len());
        self.values.push(expression);
        value
    }

    fn expression(&self, value: Value) -> Expression {
        self.values[value.0].clone()
    }

    fn block(&mut self, body: impl FnOnce(&mut Self)) -> Vec<Effect> {
        let outer = std::mem::take(&mut self.effects);
        body(self);
        std::mem::replace(&mut self.effects, outer)
    }

    fn bind(&mut self, expression: Expression) -> Value {
        let local = self.local();
        self.effects.push(Effect::Assign(local, expression));
        self.define(Expression::Local(local))
    }

    pub fn read(&mut self, width: VMWidth) -> Value {
        let local = self.local();
        self.effects.push(Effect::Read(local, width));
        self.define(Expression::Local(local))
    }

    pub fn register_operand(&mut self) -> Value {
        self.bind(Expression::Register(Register::Operand))
    }

    pub fn segment(&mut self) -> Value {
        self.define(Expression::Segment)
    }

    pub fn add(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::Add(Box::new(first), Box::new(second)))
    }

    pub fn sub(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::Sub(Box::new(first), Box::new(second)))
    }

    pub fn mul(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::Mul(Box::new(first), Box::new(second)))
    }

    pub fn extend(&mut self, value: Value, width: VMWidth) -> Value {
        let value = self.expression(value);
        self.define(Expression::Extend(Box::new(value), width))
    }

    pub fn produce(&mut self, value: Value) {
        let value = self.expression(value);
        self.effects.push(Effect::Push(value));
    }

    pub fn input(&mut self, index: usize) -> Value {
        self.define(Expression::Operand(Operand::Input(index)))
    }

    pub fn register(&mut self, register: VMReg) -> Value {
        self.define(Expression::Register(Register::Fixed(register)))
    }

    pub fn decrypt(&mut self, cipher: Value) -> Value {
        let cipher = self.expression(cipher);
        self.bind(Expression::LowByte(Box::new(Expression::Sub(
            Box::new(Expression::Mul(
                Box::new(cipher),
                Box::new(Expression::Register(Register::Fixed(VMReg::VImmMul))),
            )),
            Box::new(Expression::Register(Register::Fixed(VMReg::VImmAdd))),
        ))))
    }

    pub fn flag(&mut self, index: Value) -> Value {
        let index = self.expression(index);
        self.define(Expression::Compare(Box::new(Compare::BitSet(
            Expression::Register(Register::Fixed(VMReg::Flags)),
            index,
        ))))
    }

    pub fn equal(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::Compare(Box::new(Compare::Equal(first, second))))
    }

    pub fn unequal(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::BitXor(Box::new(first), Box::new(second)))
    }

    pub fn constant(&mut self, value: u64) -> Value {
        self.define(Expression::Immediate(Immediate::Fixed(value)))
    }

    pub fn immediate(&mut self, width: VMWidth) -> Value {
        let cipher = self.read(width);

        let multiplier = self.register(VMReg::VImmMul);
        let product = self.mul(cipher, multiplier);
        let addend = self.register(VMReg::VImmAdd);
        let decrypted = self.sub(product, addend);

        self.extend(decrypted, width)
    }

    pub fn and(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::BitAnd(Box::new(first), Box::new(second)))
    }

    pub fn or(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::BitOr(Box::new(first), Box::new(second)))
    }

    pub fn xor(&mut self, first: Value, second: Value) -> Value {
        let first = self.expression(first);
        let second = self.expression(second);
        self.define(Expression::BitXor(Box::new(first), Box::new(second)))
    }

    pub fn variable(&mut self) -> Variable {
        Variable(self.local())
    }

    pub fn set(&mut self, variable: Variable, value: Value) {
        let value = self.expression(value);
        self.effects.push(Effect::Assign(variable.0, value));
    }

    pub fn get(&mut self, variable: Variable) -> Value {
        self.define(Expression::Local(variable.0))
    }

    pub fn store(&mut self, register: VMReg, value: Value) {
        let value = self.expression(value);
        self.effects
            .push(Effect::Register(Register::Fixed(register), value));
    }

    pub fn push(&mut self, value: Value) {
        let value = self.expression(value);
        self.effects.push(Effect::Register(
            Register::Fixed(VMReg::Rsp),
            Expression::Sub(
                Box::new(Expression::Register(Register::Fixed(VMReg::Rsp))),
                Box::new(Expression::Immediate(Immediate::Fixed(8))),
            ),
        ));
        self.effects.push(Effect::Memory(
            Expression::Register(Register::Fixed(VMReg::Rsp)),
            value,
        ));
    }

    pub fn advance(&mut self, value: Value) {
        let value = self.expression(value);
        self.effects.push(Effect::Advance(value));
    }

    pub fn select(&mut self, selector: Value, build: impl FnOnce(&mut Select)) -> Value {
        let result = self.local();
        let selector = self.expression(selector);

        let arms = {
            let mut select = Select {
                builder: self,
                result,
                arms: Vec::new(),
            };
            build(&mut select);
            select.arms
        };

        self.effects.push(Effect::Select(selector, arms));
        self.define(Expression::Local(result))
    }

    pub fn dispatch(&mut self, selector: Value, build: impl FnOnce(&mut Dispatch)) {
        let selector = self.expression(selector);

        let arms = {
            let mut dispatch = Dispatch {
                builder: self,
                arms: Vec::new(),
            };
            build(&mut dispatch);
            dispatch.arms
        };

        self.effects.push(Effect::Select(selector, arms));
    }

    pub fn when(&mut self, condition: Value, body: impl FnOnce(&mut Self)) {
        let condition = self.expression(condition);
        let body = self.block(body);
        self.effects.push(Effect::When(condition, body));
    }

    pub fn repeat(&mut self, body: impl FnOnce(&mut Self)) {
        let counter = self.local();
        self.effects.push(Effect::Read(counter, VMWidth::Lower8));
        let body = self.block(body);
        self.effects.push(Effect::Loop(counter, body));
    }
}

impl Select<'_> {
    pub fn on(&mut self, keys: Vec<u64>, body: impl FnOnce(&mut Builder) -> Value) {
        let result = self.result;
        let effects = self.builder.block(|builder| {
            let value = body(builder);
            let value = builder.expression(value);
            builder.effects.push(Effect::Assign(result, value));
        });
        self.arms.push((keys, effects));
    }
}

impl Dispatch<'_> {
    pub fn on(&mut self, keys: Vec<u64>, body: impl FnOnce(&mut Builder)) {
        let effects = self.builder.block(body);
        self.arms.push((keys, effects));
    }
}

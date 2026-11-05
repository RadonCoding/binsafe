use std::cell::{Cell, RefCell};

use crate::vm::{
    bytecode::{Flag, VMReg, VMWidth},
    handlers::semantic::{
        Binary, Compare, Flags, Node, Operation, Register, Shift, Statement, Unary, Vector,
    },
};

pub use crate::vm::handlers::semantic::Value;

#[derive(Clone, Copy)]
pub struct Variable(usize);

pub struct Builder {
    nodes: RefCell<Vec<Node>>,
    statements: RefCell<Vec<Statement>>,
    locals: Cell<usize>,
    flags: RefCell<Flags>,
    outputs: RefCell<Option<Vec<Value>>>,
    widths: Cell<&'static [VMWidth]>,
}

pub struct Select<'a> {
    builder: &'a Builder,
    result: usize,
    arms: Vec<(Vec<u64>, Vec<Statement>)>,
}

pub struct Dispatch<'a> {
    builder: &'a Builder,
    arms: Vec<(Vec<u64>, Vec<Statement>)>,
}

pub fn build(program: impl FnOnce(&Builder)) -> Operation {
    let builder = Builder {
        nodes: RefCell::new(Vec::new()),
        statements: RefCell::new(Vec::new()),
        locals: Cell::new(0),
        flags: RefCell::new(Flags::Never),
        outputs: RefCell::new(None),
        widths: Cell::new(&[]),
    };

    program(&builder);

    Operation {
        nodes: builder.nodes.into_inner(),
        statements: builder.statements.into_inner(),
        flags: builder.flags.into_inner(),
        outputs: builder.outputs.into_inner(),
        widths: builder.widths.get(),
    }
}

impl Builder {
    fn local(&self) -> usize {
        let index = self.locals.get();
        self.locals.set(index + 1);
        index
    }

    fn define(&self, node: Node) -> Vec<Value> {
        let outputs = node.results();
        let mut nodes = self.nodes.borrow_mut();
        let index = nodes.len();
        nodes.push(node);
        (0..outputs)
            .map(|output| Value {
                node: index,
                output,
            })
            .collect()
    }

    fn emit(&self, statement: Statement) {
        self.statements.borrow_mut().push(statement);
    }

    fn block(&self, body: impl FnOnce(&Self)) -> Vec<Statement> {
        let outer = std::mem::take(&mut *self.statements.borrow_mut());
        body(self);
        std::mem::replace(&mut *self.statements.borrow_mut(), outer)
    }

    pub fn bind(&self, value: Value) -> Value {
        let local = self.local();
        self.emit(Statement::Assign(local, value));
        self.define(Node::Local(local))[0]
    }

    pub fn widths(&self, widths: &'static [VMWidth]) {
        self.widths.set(widths);
    }

    pub fn flags_always(&self, values: Vec<(Flag, Value)>) {
        *self.flags.borrow_mut() = Flags::Always(values);
    }

    pub fn flags_when(&self, condition: Value, values: Vec<(Flag, Value)>) {
        *self.flags.borrow_mut() = Flags::When(condition, values);
    }

    pub fn outputs(&self, values: Vec<Value>) {
        *self.outputs.borrow_mut() = Some(values);
    }

    pub fn read(&self, width: VMWidth) -> Value {
        let local = self.local();
        self.emit(Statement::Read(local, width));
        self.define(Node::Local(local))[0]
    }

    pub fn read_register(&self) -> Value {
        let value = self.define(Node::Register(Register::Operand))[0];
        self.bind(value)
    }

    pub fn segment(&self) -> Value {
        self.define(Node::Segment)[0]
    }

    pub fn input(&self, index: usize) -> Value {
        self.define(Node::Input(index))[0]
    }

    pub fn register(&self, register: VMReg) -> Value {
        self.define(Node::Register(Register::Fixed(register)))[0]
    }

    pub fn constant(&self, value: u64) -> Value {
        self.define(Node::Immediate(value))[0]
    }

    pub fn flag(&self, flag: Flag) -> Value {
        self.define(Node::Flag(flag))[0]
    }

    pub fn sign_bit(&self) -> Value {
        self.define(Node::SignBit)[0]
    }

    pub fn bit_size(&self) -> Value {
        self.define(Node::BitSize)[0]
    }

    pub fn byte_mask(&self, index: usize) -> Value {
        self.define(Node::ByteMask(index))[0]
    }

    pub fn memory(&self, address: Value) -> Value {
        self.define(Node::Memory(address))[0]
    }

    pub fn add(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::Add, first, second))[0]
    }

    pub fn sub(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::Sub, first, second))[0]
    }

    pub fn mul(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::Mul, first, second))[0]
    }

    pub fn mul_wide(&self, first: Value, second: Value) -> (Value, Value) {
        let results = self.define(Node::WideMul(first, second));
        (results[0], results[1])
    }

    pub fn div(&self, first: Value, second: Value, third: Value) -> (Value, Value) {
        let results = self.define(Node::Div(first, second, third));
        (results[0], results[1])
    }

    pub fn bit_and(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::And, first, second))[0]
    }

    pub fn bit_or(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::Or, first, second))[0]
    }

    pub fn bit_xor(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::Xor, first, second))[0]
    }

    pub fn bit_not(&self, value: Value) -> Value {
        self.define(Node::Unary(Unary::Not, value))[0]
    }

    pub fn bit_shl(&self, first: Value, second: Value) -> Value {
        self.define(Node::Shift(Shift::Shl, first, second))[0]
    }

    pub fn bit_shr(&self, first: Value, second: Value) -> Value {
        self.define(Node::Shift(Shift::Shr, first, second))[0]
    }

    pub fn bit_sar(&self, first: Value, second: Value) -> Value {
        self.define(Node::Shift(Shift::Sar, first, second))[0]
    }

    pub fn bit_rol(&self, first: Value, second: Value) -> Value {
        self.define(Node::Shift(Shift::Rol, first, second))[0]
    }

    pub fn bit_ror(&self, first: Value, second: Value) -> Value {
        self.define(Node::Shift(Shift::Ror, first, second))[0]
    }

    pub fn bsr(&self, destination: Value, source: Value) -> Value {
        self.define(Node::Bsr(destination, source))[0]
    }

    pub fn tzcnt(&self, value: Value) -> Value {
        self.define(Node::Unary(Unary::Tzcnt, value))[0]
    }

    pub fn extend(&self, value: Value, width: VMWidth) -> Value {
        self.define(Node::Extend(value, width))[0]
    }

    pub fn parity(&self, value: Value) -> Value {
        self.define(Node::Unary(Unary::Parity, value))[0]
    }

    pub fn decrypt(&self, cipher: Value) -> Value {
        let multiplier = self.register(VMReg::VImmMul);
        let product = self.mul(cipher, multiplier);
        let addend = self.register(VMReg::VImmAdd);
        let difference = self.sub(product, addend);
        let low = self.define(Node::Unary(Unary::LowByte, difference))[0];
        self.bind(low)
    }

    pub fn immediate(&self, width: VMWidth) -> Value {
        let cipher = self.read(width);

        let multiplier = self.register(VMReg::VImmMul);
        let product = self.mul(cipher, multiplier);
        let addend = self.register(VMReg::VImmAdd);
        let decrypted = self.sub(product, addend);

        self.extend(decrypted, width)
    }

    pub fn equal(&self, first: Value, second: Value) -> Value {
        self.define(Node::Compare(Compare::Equal, first, second))[0]
    }

    pub fn less_than(&self, first: Value, second: Value) -> Value {
        self.define(Node::Compare(Compare::LessThan, first, second))[0]
    }

    pub fn greater_than(&self, first: Value, second: Value) -> Value {
        self.define(Node::Compare(Compare::GreaterThan, first, second))[0]
    }

    pub fn bit_set(&self, value: Value, index: Value) -> Value {
        self.define(Node::Compare(Compare::BitSet, value, index))[0]
    }

    pub fn flag_set(&self, index: Value) -> Value {
        let flags = self.register(VMReg::Flags);
        self.define(Node::Compare(Compare::BitSet, flags, index))[0]
    }

    pub fn unequal(&self, first: Value, second: Value) -> Value {
        self.define(Node::Binary(Binary::Xor, first, second))[0]
    }

    pub fn variable(&self) -> Variable {
        Variable(self.local())
    }

    pub fn set(&self, variable: Variable, value: Value) {
        self.emit(Statement::Assign(variable.0, value));
    }

    pub fn get(&self, variable: Variable) -> Value {
        self.define(Node::Local(variable.0))[0]
    }

    pub fn vector_and(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::And, first, second))[0]
    }

    pub fn vector_or(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::Or, first, second))[0]
    }

    pub fn vector_xor(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::Xor, first, second))[0]
    }

    pub fn vector_and_not(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::AndNot, first, second))[0]
    }

    pub fn vector_add(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::Add, first, second))[0]
    }

    pub fn vector_sub(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::Sub, first, second))[0]
    }

    pub fn packed_byte_equal(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::PackedByteEqual, first, second))[0]
    }

    pub fn vector_mul(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::Mul, first, second))[0]
    }

    pub fn vector_div(&self, first: Value, second: Value) -> Value {
        self.define(Node::Vector(Vector::Div, first, second))[0]
    }

    pub fn packed_byte_mask(&self, value: Value) -> Value {
        self.define(Node::PackedByteMask(value))[0]
    }

    pub fn load_vector(&self) -> Value {
        self.define(Node::LoadVector)[0]
    }

    pub fn store_merge(&self, value: Value) {
        self.emit(Statement::StoreMerge(value));
    }

    pub fn store_extend(&self, value: Value) {
        self.emit(Statement::StoreExtend(value));
    }

    pub fn load_memory(&self, address: Value) -> Value {
        self.define(Node::LoadMemory(address))[0]
    }

    pub fn store_memory(&self, address: Value, value: Value) {
        self.emit(Statement::StoreMemory(address, value));
    }

    pub fn exchange(&self, first: Value, second: Value) -> Value {
        let value = self.define(Node::Exchange(first, second))[0];
        self.bind(value)
    }

    pub fn exchange_add(&self, first: Value, second: Value) -> (Value, Value) {
        let results = self.define(Node::ExchangeAdd(first, second));
        (results[0], results[1])
    }

    pub fn compare_exchange(&self, first: Value, second: Value, third: Value) -> Value {
        let value = self.define(Node::CompareExchange(first, second, third))[0];
        self.bind(value)
    }

    pub fn drop(&self, value: Value) {
        self.emit(Statement::Drop(value));
    }

    pub fn write_register(&self, register: VMReg, value: Value) {
        self.emit(Statement::WriteRegister(Register::Fixed(register), value));
    }

    pub fn write_operand(&self, value: Value) {
        self.emit(Statement::WriteRegister(Register::Operand, value));
    }

    pub fn write_memory(&self, address: Value, value: Value) {
        self.emit(Statement::WriteMemory(address, value));
    }

    pub fn push(&self, value: Value) {
        let stack = self.register(VMReg::Rsp);
        let width = self.constant(8);
        let decremented = self.sub(stack, width);
        self.emit(Statement::WriteRegister(
            Register::Fixed(VMReg::Rsp),
            decremented,
        ));

        let stack = self.register(VMReg::Rsp);
        self.emit(Statement::WriteMemory(stack, value));
    }

    pub fn advance(&self, value: Value) {
        self.emit(Statement::Advance(value));
    }

    pub fn cpuid(&self, leaf: Value, subleaf: Value) -> (Value, Value, Value, Value) {
        let results = self.define(Node::Cpuid(leaf, subleaf));
        (results[0], results[1], results[2], results[3])
    }

    pub fn timestamp(&self) -> (Value, Value) {
        let results = self.define(Node::Timestamp);
        (results[0], results[1])
    }

    pub fn select(&self, selector: Value, build: impl FnOnce(&mut Select)) -> Value {
        let result = self.local();

        let arms = {
            let mut select = Select {
                builder: self,
                result,
                arms: Vec::new(),
            };
            build(&mut select);
            select.arms
        };

        self.emit(Statement::Select(selector, arms));
        self.define(Node::Local(result))[0]
    }

    pub fn dispatch(&self, selector: Value, build: impl FnOnce(&mut Dispatch)) {
        let arms = {
            let mut dispatch = Dispatch {
                builder: self,
                arms: Vec::new(),
            };
            build(&mut dispatch);
            dispatch.arms
        };

        self.emit(Statement::Select(selector, arms));
    }

    pub fn when(&self, condition: Value, body: impl FnOnce(&Self)) {
        let body = self.block(body);
        self.emit(Statement::When(condition, body));
    }

    pub fn repeat(&self, body: impl FnOnce(&Self)) {
        let counter = self.local();
        self.emit(Statement::Read(counter, VMWidth::Lower8));
        let body = self.block(body);
        self.emit(Statement::Loop(counter, body));
    }
}

impl Select<'_> {
    pub fn on(&mut self, keys: Vec<u64>, body: impl FnOnce(&Builder) -> Value) {
        let result = self.result;
        let statements = self.builder.block(|builder| {
            let value = body(builder);
            builder.emit(Statement::Assign(result, value));
        });
        self.arms.push((keys, statements));
    }
}

impl Dispatch<'_> {
    pub fn on(&mut self, keys: Vec<u64>, body: impl FnOnce(&Builder)) {
        let statements = self.builder.block(body);
        self.arms.push((keys, statements));
    }
}

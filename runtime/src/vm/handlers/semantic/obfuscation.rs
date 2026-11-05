use rand::{rngs::ThreadRng, Rng};

use crate::vm::handlers::semantic::{
    Binary, Flags, Node, Operation, Shift, Statement, Unary, Value, Vector,
};

struct Rewriter {
    nodes: Vec<Node>,
    map: Vec<usize>,
    rng: ThreadRng,
    budget: u32,
}

pub fn operation(operation: &Operation) -> Operation {
    let mut rewriter = Rewriter {
        nodes: Vec::new(),
        map: vec![0; operation.nodes.len()],
        rng: rand::thread_rng(),
        budget: rand::thread_rng().gen_range(1..4),
    };

    for (index, node) in operation.nodes.iter().enumerate() {
        rewriter.map[index] = rewriter.rewrite(node);
    }

    let statements = operation
        .statements
        .iter()
        .map(|statement| rewriter.statement(statement))
        .collect();
    let flags = rewriter.flags(&operation.flags);
    let outputs = operation
        .outputs
        .as_ref()
        .map(|outputs| outputs.iter().map(|&value| rewriter.value(value)).collect());

    Operation {
        nodes: rewriter.nodes,
        statements,
        flags,
        outputs,
        widths: operation.widths,
    }
}

impl Rewriter {
    fn push(&mut self, node: Node) -> usize {
        let index = self.nodes.len();
        self.nodes.push(node);
        index
    }

    fn value(&self, value: Value) -> Value {
        Value {
            node: self.map[value.node],
            output: value.output,
        }
    }

    fn define(&mut self, node: Node) -> Value {
        Value {
            node: self.push(node),
            output: 0,
        }
    }

    fn binary(&mut self, operator: Binary, first: Value, second: Value) -> Value {
        self.define(Node::Binary(operator, first, second))
    }

    fn not(&mut self, value: Value) -> Value {
        self.define(Node::Unary(Unary::Not, value))
    }

    fn shift(&mut self, operator: Shift, first: Value, second: Value) -> Value {
        self.define(Node::Shift(operator, first, second))
    }

    fn vector(&mut self, operator: Vector, first: Value, second: Value) -> Value {
        self.define(Node::Vector(operator, first, second))
    }

    fn immediate(&mut self, value: u64) -> Value {
        self.define(Node::Immediate(value))
    }

    fn reconstruct(&self, node: &Node) -> Node {
        match node {
            &Node::Memory(value) => Node::Memory(self.value(value)),
            &Node::LoadMemory(value) => Node::LoadMemory(self.value(value)),
            &Node::Unary(operator, value) => Node::Unary(operator, self.value(value)),
            &Node::Extend(value, width) => Node::Extend(self.value(value), width),
            &Node::PackedByteMask(value) => Node::PackedByteMask(self.value(value)),
            &Node::Binary(operator, first, second) => {
                Node::Binary(operator, self.value(first), self.value(second))
            }
            &Node::Shift(operator, first, second) => {
                Node::Shift(operator, self.value(first), self.value(second))
            }
            &Node::Compare(operator, first, second) => {
                Node::Compare(operator, self.value(first), self.value(second))
            }
            &Node::Vector(operator, first, second) => {
                Node::Vector(operator, self.value(first), self.value(second))
            }
            &Node::Bsr(first, second) => Node::Bsr(self.value(first), self.value(second)),
            &Node::WideMul(first, second) => Node::WideMul(self.value(first), self.value(second)),
            &Node::Cpuid(first, second) => Node::Cpuid(self.value(first), self.value(second)),
            &Node::Exchange(first, second) => Node::Exchange(self.value(first), self.value(second)),
            &Node::ExchangeAdd(first, second) => {
                Node::ExchangeAdd(self.value(first), self.value(second))
            }
            &Node::Div(first, second, third) => {
                Node::Div(self.value(first), self.value(second), self.value(third))
            }
            &Node::CompareExchange(first, second, third) => {
                Node::CompareExchange(self.value(first), self.value(second), self.value(third))
            }
            Node::Input(_)
            | Node::Immediate(_)
            | Node::Register(_)
            | Node::Local(_)
            | Node::Flag(_)
            | Node::Segment
            | Node::SignBit
            | Node::BitSize
            | Node::ByteMask(_)
            | Node::Timestamp
            | Node::LoadVector => node.clone(),
        }
    }

    fn rewrite(&mut self, node: &Node) -> usize {
        let node = self.reconstruct(node);

        if self.budget == 0 {
            return self.push(node);
        }

        match node {
            Node::Binary(Binary::Xor, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..4) {
                    0 => {
                        let or = self.binary(Binary::Or, a, b);
                        let and = self.binary(Binary::And, a, b);
                        self.push(Node::Binary(Binary::Sub, or, and))
                    }
                    1 => {
                        let or = self.binary(Binary::Or, a, b);
                        let and = self.binary(Binary::And, a, b);
                        let not = self.not(and);
                        self.push(Node::Binary(Binary::And, or, not))
                    }
                    2 => {
                        let not_b = self.not(b);
                        let left = self.binary(Binary::And, a, not_b);
                        let not_a = self.not(a);
                        let right = self.binary(Binary::And, not_a, b);
                        self.push(Node::Binary(Binary::Or, left, right))
                    }
                    _ => {
                        let add = self.binary(Binary::Add, a, b);
                        let and = self.binary(Binary::And, a, b);
                        let one = self.immediate(1);
                        let shifted = self.shift(Shift::Shl, and, one);
                        self.push(Node::Binary(Binary::Sub, add, shifted))
                    }
                }
            }
            Node::Binary(Binary::Or, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..4) {
                    0 => {
                        let not_a = self.not(a);
                        let not_b = self.not(b);
                        let and = self.binary(Binary::And, not_a, not_b);
                        self.push(Node::Unary(Unary::Not, and))
                    }
                    1 => {
                        let and = self.binary(Binary::And, a, b);
                        let xor = self.binary(Binary::Xor, a, b);
                        self.push(Node::Binary(Binary::Add, and, xor))
                    }
                    2 => {
                        let not_a = self.not(a);
                        let and = self.binary(Binary::And, b, not_a);
                        self.push(Node::Binary(Binary::Add, a, and))
                    }
                    _ => {
                        let add = self.binary(Binary::Add, a, b);
                        let and = self.binary(Binary::And, a, b);
                        self.push(Node::Binary(Binary::Sub, add, and))
                    }
                }
            }
            Node::Binary(Binary::And, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..4) {
                    0 => {
                        let not_a = self.not(a);
                        let not_b = self.not(b);
                        let or = self.binary(Binary::Or, not_a, not_b);
                        self.push(Node::Unary(Unary::Not, or))
                    }
                    1 => {
                        let or = self.binary(Binary::Or, a, b);
                        let xor = self.binary(Binary::Xor, a, b);
                        self.push(Node::Binary(Binary::Sub, or, xor))
                    }
                    2 => {
                        let not_b = self.not(b);
                        let and = self.binary(Binary::And, a, not_b);
                        self.push(Node::Binary(Binary::Sub, a, and))
                    }
                    _ => {
                        let add = self.binary(Binary::Add, a, b);
                        let or = self.binary(Binary::Or, a, b);
                        self.push(Node::Binary(Binary::Sub, add, or))
                    }
                }
            }
            Node::Unary(Unary::Not, a) => {
                self.budget -= 1;

                match self.rng.gen_range(0..2) {
                    0 => {
                        let zero = self.immediate(0);
                        let negated = self.binary(Binary::Sub, zero, a);
                        let one = self.immediate(1);
                        self.push(Node::Binary(Binary::Sub, negated, one))
                    }
                    _ => {
                        let mask = self.immediate(u64::MAX);
                        self.push(Node::Binary(Binary::Xor, a, mask))
                    }
                }
            }
            Node::Binary(Binary::Add, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..3) {
                    0 => {
                        let xor = self.binary(Binary::Xor, a, b);
                        let and = self.binary(Binary::And, a, b);
                        let one = self.immediate(1);
                        let shifted = self.shift(Shift::Shl, and, one);
                        self.push(Node::Binary(Binary::Add, xor, shifted))
                    }
                    1 => {
                        let or = self.binary(Binary::Or, a, b);
                        let and = self.binary(Binary::And, a, b);
                        self.push(Node::Binary(Binary::Add, or, and))
                    }
                    _ => {
                        let not_b = self.not(b);
                        let difference = self.binary(Binary::Sub, a, not_b);
                        let one = self.immediate(1);
                        self.push(Node::Binary(Binary::Sub, difference, one))
                    }
                }
            }
            Node::Binary(Binary::Sub, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..3) {
                    0 => {
                        let not_b = self.not(b);
                        let sum = self.binary(Binary::Add, a, not_b);
                        let one = self.immediate(1);
                        self.push(Node::Binary(Binary::Add, sum, one))
                    }
                    1 => {
                        let zero = self.immediate(0);
                        let negated = self.binary(Binary::Sub, zero, b);
                        self.push(Node::Binary(Binary::Add, a, negated))
                    }
                    _ => {
                        let xor = self.binary(Binary::Xor, a, b);
                        let not_a = self.not(a);
                        let and = self.binary(Binary::And, not_a, b);
                        let one = self.immediate(1);
                        let shifted = self.shift(Shift::Shl, and, one);
                        self.push(Node::Binary(Binary::Sub, xor, shifted))
                    }
                }
            }
            Node::Immediate(value) => {
                self.budget -= 1;

                let key = self.rng.gen::<u64>();

                match self.rng.gen_range(0..3) {
                    0 => {
                        let masked = self.immediate(value ^ key);
                        let key = self.immediate(key);
                        self.push(Node::Binary(Binary::Xor, masked, key))
                    }
                    1 => {
                        let offset = self.immediate(value.wrapping_add(key));
                        let key = self.immediate(key);
                        self.push(Node::Binary(Binary::Sub, offset, key))
                    }
                    _ => {
                        let offset = self.immediate(value.wrapping_sub(key));
                        let key = self.immediate(key);
                        self.push(Node::Binary(Binary::Add, offset, key))
                    }
                }
            }
            Node::Vector(Vector::Xor, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..2) {
                    0 => {
                        let and = self.vector(Vector::And, a, b);
                        let or = self.vector(Vector::Or, a, b);
                        self.push(Node::Vector(Vector::AndNot, and, or))
                    }
                    _ => {
                        let left = self.vector(Vector::AndNot, b, a);
                        let right = self.vector(Vector::AndNot, a, b);
                        self.push(Node::Vector(Vector::Or, left, right))
                    }
                }
            }
            Node::Vector(Vector::Or, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..2) {
                    0 => {
                        let and = self.vector(Vector::And, a, b);
                        let xor = self.vector(Vector::Xor, a, b);
                        self.push(Node::Vector(Vector::Xor, and, xor))
                    }
                    _ => {
                        let and = self.vector(Vector::AndNot, b, a);
                        self.push(Node::Vector(Vector::Or, b, and))
                    }
                }
            }
            Node::Vector(Vector::And, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..2) {
                    0 => {
                        let or = self.vector(Vector::Or, a, b);
                        let xor = self.vector(Vector::Xor, a, b);
                        self.push(Node::Vector(Vector::Xor, or, xor))
                    }
                    _ => {
                        let and = self.vector(Vector::AndNot, a, b);
                        self.push(Node::Vector(Vector::Xor, b, and))
                    }
                }
            }
            Node::Vector(Vector::AndNot, a, b) => {
                self.budget -= 1;

                match self.rng.gen_range(0..2) {
                    0 => {
                        let or = self.vector(Vector::Or, a, b);
                        self.push(Node::Vector(Vector::Xor, or, a))
                    }
                    _ => {
                        let and = self.vector(Vector::And, a, b);
                        self.push(Node::Vector(Vector::Xor, b, and))
                    }
                }
            }
            node => self.push(node),
        }
    }

    fn statement(&self, statement: &Statement) -> Statement {
        match statement {
            &Statement::WriteRegister(register, value) => {
                Statement::WriteRegister(register, self.value(value))
            }
            &Statement::WriteMemory(address, value) => {
                Statement::WriteMemory(self.value(address), self.value(value))
            }
            &Statement::StoreMemory(address, value) => {
                Statement::StoreMemory(self.value(address), self.value(value))
            }
            &Statement::StoreMerge(value) => Statement::StoreMerge(self.value(value)),
            &Statement::StoreExtend(value) => Statement::StoreExtend(self.value(value)),
            &Statement::Assign(local, value) => Statement::Assign(local, self.value(value)),
            &Statement::Read(local, width) => Statement::Read(local, width),
            &Statement::Advance(value) => Statement::Advance(self.value(value)),
            &Statement::Drop(value) => Statement::Drop(self.value(value)),
            Statement::Loop(counter, body) => Statement::Loop(
                *counter,
                body.iter().map(|statement| self.statement(statement)).collect(),
            ),
            Statement::Select(selector, arms) => Statement::Select(
                self.value(*selector),
                arms.iter()
                    .map(|(keys, body)| {
                        (
                            keys.clone(),
                            body.iter().map(|statement| self.statement(statement)).collect(),
                        )
                    })
                    .collect(),
            ),
            Statement::When(condition, body) => Statement::When(
                self.value(*condition),
                body.iter().map(|statement| self.statement(statement)).collect(),
            ),
        }
    }

    fn flags(&self, flags: &Flags) -> Flags {
        match flags {
            Flags::Never => Flags::Never,
            Flags::Always(values) => Flags::Always(
                values
                    .iter()
                    .map(|&(flag, value)| (flag, self.value(value)))
                    .collect(),
            ),
            Flags::When(condition, values) => Flags::When(
                self.value(*condition),
                values
                    .iter()
                    .map(|&(flag, value)| (flag, self.value(value)))
                    .collect(),
            ),
        }
    }
}

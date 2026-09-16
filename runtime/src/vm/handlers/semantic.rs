use iced_x86::code_asm::{
    cl, get_gpr16, get_gpr32, get_gpr8, qword_ptr, r12, r13, r14, r14d, r8, r9, rax, rbp, rcx, rdx,
    rsp, AsmRegister64, CodeLabel,
};

use std::collections::HashSet;

use crate::{
    register,
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMReg, VMWidth},
        utils::{bytecode, scratch, vreg},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Input(usize),
    Output(usize),
}

#[derive(Debug, Clone)]
pub enum Expression {
    Operand(Operand),
    Constant(u64),
    BitAnd(Box<Expression>, Box<Expression>),
    BitOr(Box<Expression>, Box<Expression>),
    BitXor(Box<Expression>, Box<Expression>),
    BitShr(Box<Expression>, Box<Expression>),
    BitShl(Box<Expression>, Box<Expression>),
    BitNot(Box<Expression>),
    Sub(Box<Expression>, Box<Expression>),
    LowByte(Box<Expression>),
    SignBit,
}

#[derive(Debug, Clone)]
pub enum Effect {
    Add(Expression, Expression),
    Sub(Expression, Expression),
    And(Expression, Expression),
    Or(Expression, Expression),
    Xor(Expression, Expression),
    Shr(Expression, Expression),
    Shl(Expression, Expression),
    Ror(Expression, Expression),
    Rol(Expression, Expression),
    Mul(Expression, Expression),
    Assign(Expression),
    Sar(Expression, Expression),
    Bsr(Expression),
    Tzcnt(Expression),
}

#[derive(Debug, Clone)]
pub enum Compare {
    Equal(Expression, Expression),
    LessThan(Expression, Expression),
    GreaterThan(Expression, Expression),
    BitSet(Expression, Expression),
}

#[derive(Debug, Clone)]
pub enum Condition {
    Compare(Compare),
    Parity(Expression),
}

#[derive(Debug)]
pub struct Operation {
    pub effects: Vec<Effect>,
    pub flags: Vec<(Flag, Condition)>,
    pub stores: Option<Vec<Expression>>,
    pub widths: &'static [VMWidth],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Value {
    Input(usize),
    Output(usize),
    Flags,
    Temporary(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueRef {
    Value(Value),
    Immediate(i64),
}

#[derive(Clone)]
struct Allocator {
    tracked: Vec<(AsmRegister64, Value)>,
    dirty: HashSet<Value>,
    temporary: usize,
    inputs: usize,
    outputs: usize,
    flags: bool,
}

impl Allocator {
    const REGISTERS: [AsmRegister64; 5] = [rax, rcx, rdx, r8, r9];

    fn new(inputs: usize, outputs: usize, flags: bool) -> Self {
        Self {
            tracked: Vec::new(),
            dirty: HashSet::new(),
            temporary: 0,
            inputs,
            outputs,
            flags,
        }
    }

    fn track(&mut self, register: AsmRegister64, value: Value, dirty: bool) {
        assert!(
            self.tracked.iter().all(|(r, _)| *r != register),
            "register {:?} is already tracked",
            register
        );
        assert!(
            self.tracked.iter().all(|(_, v)| *v != value),
            "value {:?} is already tracked",
            value
        );
        self.tracked.push((register, value));

        if dirty {
            self.dirty.insert(value);
        } else {
            self.dirty.remove(&value);
        }
    }

    fn untrack(&mut self, register: AsmRegister64) -> Option<Value> {
        let index = self.tracked.iter().position(|(r, _)| *r == register)?;
        Some(self.tracked.swap_remove(index).1)
    }

    fn tracked_register(&self, value: Value) -> Option<AsmRegister64> {
        self.tracked
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(r, _)| *r)
    }

    fn tracked_value(&self, register: AsmRegister64) -> Option<Value> {
        self.tracked
            .iter()
            .find(|(r, _)| *r == register)
            .map(|(_, v)| *v)
    }

    fn temporary(&mut self) -> Value {
        let value = Value::Temporary(self.temporary);
        self.temporary += 1;
        value
    }

    fn offset(inputs: usize, outputs: usize, flags: bool, value: Value) -> i32 {
        let flags = flags as usize;
        let slot = match value {
            Value::Input(index) => index,
            Value::Output(index) => inputs + index,
            Value::Flags => inputs + outputs,
            Value::Temporary(index) => inputs + outputs + flags + index,
        };
        (slot as i32 + 1) * 8
    }

    fn spill(&mut self, rt: &mut Runtime, register: AsmRegister64) {
        let Some(value) = self.tracked_value(register) else {
            return;
        };

        if self.dirty.remove(&value) {
            rt.asm
                .mov(
                    qword_ptr(rbp - Self::offset(self.inputs, self.outputs, self.flags, value)),
                    register,
                )
                .unwrap();
        }

        self.untrack(register);
    }

    fn dump(&mut self, rt: &mut Runtime) {
        let registers = self
            .tracked
            .iter()
            .map(|(register, _)| *register)
            .collect::<Vec<AsmRegister64>>();

        for register in registers {
            self.spill(rt, register);
        }
    }

    fn acquire(
        &mut self,
        rt: &mut Runtime,
        pinned: &[Value],
        avoid: &[AsmRegister64],
    ) -> AsmRegister64 {
        if let Some(register) = Self::REGISTERS
            .iter()
            .copied()
            .find(|register| !avoid.contains(register) && self.tracked_value(*register).is_none())
        {
            return register;
        }

        if let Some(register) = Self::REGISTERS.iter().copied().find(|register| {
            if avoid.contains(register) {
                return false;
            }

            match self.tracked_value(*register) {
                Some(value) => !pinned.contains(&value),
                None => true,
            }
        }) {
            self.spill(rt, register);
            return register;
        }

        let register = Self::REGISTERS
            .iter()
            .copied()
            .find(|register| !avoid.contains(register))
            .expect("allocator has no usable register");
        self.spill(rt, register);
        register
    }

    fn copy(&mut self, rt: &mut Runtime, value: ValueRef, register: AsmRegister64) {
        self.spill(rt, register);

        match value {
            ValueRef::Immediate(value) => {
                rt.asm.mov(register, value).unwrap();
            }
            ValueRef::Value(value) => {
                if let Some(source) = self.tracked_register(value) {
                    rt.asm.mov(register, source).unwrap();
                } else {
                    rt.asm
                        .mov(
                            register,
                            qword_ptr(
                                rbp - Self::offset(self.inputs, self.outputs, self.flags, value),
                            ),
                        )
                        .unwrap();
                }
            }
        }
    }

    fn mutable(
        &mut self,
        rt: &mut Runtime,
        value: Value,
        avoid: &[AsmRegister64],
    ) -> AsmRegister64 {
        if let Some(register) = self.tracked_register(value) {
            if !avoid.contains(&register) {
                return register;
            }
        }

        let register = self.acquire(rt, &[], avoid);
        rt.asm
            .mov(
                register,
                qword_ptr(rbp - Self::offset(self.inputs, self.outputs, self.flags, value)),
            )
            .unwrap();
        self.track(register, value, false);
        register
    }

    fn replace(&mut self, register: AsmRegister64, value: Value, dirty: bool) {
        self.untrack(register);

        if let Some(old) = self
            .tracked
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(r, _)| *r)
        {
            self.untrack(old);
        }

        self.track(register, value, dirty);
    }

    fn consume(&mut self, value: ValueRef) {
        let ValueRef::Value(value) = value else {
            return;
        };
        if matches!(value, Value::Temporary(_)) {
            if let Some(register) = self.tracked_register(value) {
                self.untrack(register);
            }
            self.dirty.remove(&value);
        }
    }
}

// TODO: Implement a mixed-boolean-arithmetic engine!

impl Operation {
    fn operands(&self) -> usize {
        let mut value = 0;

        for effect in &self.effects {
            effect.operands(&mut value);
        }

        for (_, condition) in &self.flags {
            condition.operands(&mut value);
        }

        if let Some(stores) = &self.stores {
            for store in stores {
                store.operands(&mut value);
            }
        }

        value
    }

    fn outputs(&self) -> usize {
        let mut value = 0;

        for effect in &self.effects {
            effect.outputs(&mut value);
        }

        for (_, condition) in &self.flags {
            condition.outputs(&mut value);
        }

        match &self.stores {
            Some(stores) => {
                value = value.max(stores.len());
                for store in stores {
                    store.outputs(&mut value);
                }
            }
            None if !self.effects.is_empty() => value = value.max(1),
            None => {}
        }

        value
    }

    fn temporaries(&self) -> usize {
        let effects = self.effects.iter().map(Effect::temporary).sum::<usize>();
        let flags = self
            .flags
            .iter()
            .map(|(_, condition)| condition.temporary())
            .sum::<usize>();
        let stores = self
            .stores
            .as_ref()
            .map(|stores| stores.iter().map(Expression::temporary).sum::<usize>())
            .unwrap_or(0);

        effects + flags + stores
    }
}

impl Expression {
    fn operands(&self, value: &mut usize) {
        match self {
            Expression::Operand(Operand::Input(n)) => {
                *value = (*value).max(*n + 1);
            }
            Expression::Operand(Operand::Output(_))
            | Expression::Constant(_)
            | Expression::SignBit => {}
            Expression::BitAnd(first, second)
            | Expression::BitOr(first, second)
            | Expression::BitXor(first, second)
            | Expression::BitShr(first, second)
            | Expression::BitShl(first, second)
            | Expression::Sub(first, second) => {
                first.operands(value);
                second.operands(value);
            }
            Expression::BitNot(inner) | Expression::LowByte(inner) => {
                inner.operands(value);
            }
        }
    }

    fn outputs(&self, value: &mut usize) {
        match self {
            Expression::Operand(Operand::Output(index)) => {
                *value = (*value).max(*index + 1);
            }
            Expression::Operand(Operand::Input(_))
            | Expression::Constant(_)
            | Expression::SignBit => {}
            Expression::BitAnd(first, second)
            | Expression::BitOr(first, second)
            | Expression::BitXor(first, second)
            | Expression::BitShr(first, second)
            | Expression::BitShl(first, second)
            | Expression::Sub(first, second) => {
                first.outputs(value);
                second.outputs(value);
            }
            Expression::BitNot(inner) | Expression::LowByte(inner) => {
                inner.outputs(value);
            }
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Expression::Operand(_) | Expression::Constant(_) | Expression::SignBit => 0,
            Expression::BitAnd(first, second)
            | Expression::BitOr(first, second)
            | Expression::BitXor(first, second)
            | Expression::BitShr(first, second)
            | Expression::BitShl(first, second)
            | Expression::Sub(first, second) => 1 + first.temporary() + second.temporary(),
            Expression::BitNot(inner) | Expression::LowByte(inner) => 1 + inner.temporary(),
        }
    }
}

impl Effect {
    fn operands(&self, value: &mut usize) {
        match self {
            Effect::Add(first, second)
            | Effect::Sub(first, second)
            | Effect::And(first, second)
            | Effect::Or(first, second)
            | Effect::Xor(first, second)
            | Effect::Shr(first, second)
            | Effect::Shl(first, second)
            | Effect::Ror(first, second)
            | Effect::Rol(first, second)
            | Effect::Mul(first, second)
            | Effect::Sar(first, second) => {
                first.operands(value);
                second.operands(value);
            }
            Effect::Assign(expression) | Effect::Bsr(expression) | Effect::Tzcnt(expression) => {
                expression.operands(value);
            }
        }
    }

    fn outputs(&self, value: &mut usize) {
        match self {
            Effect::Add(first, second)
            | Effect::Sub(first, second)
            | Effect::And(first, second)
            | Effect::Or(first, second)
            | Effect::Xor(first, second)
            | Effect::Shr(first, second)
            | Effect::Shl(first, second)
            | Effect::Ror(first, second)
            | Effect::Rol(first, second)
            | Effect::Mul(first, second)
            | Effect::Sar(first, second) => {
                first.outputs(value);
                second.outputs(value);
            }
            Effect::Assign(expression) | Effect::Bsr(expression) | Effect::Tzcnt(expression) => {
                expression.outputs(value);
            }
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Effect::Add(first, second)
            | Effect::Sub(first, second)
            | Effect::And(first, second)
            | Effect::Or(first, second)
            | Effect::Xor(first, second)
            | Effect::Shr(first, second)
            | Effect::Shl(first, second)
            | Effect::Ror(first, second)
            | Effect::Rol(first, second)
            | Effect::Mul(first, second)
            | Effect::Sar(first, second) => first.temporary() + second.temporary(),
            Effect::Assign(expression) | Effect::Bsr(expression) | Effect::Tzcnt(expression) => {
                expression.temporary()
            }
        }
    }
}

impl Condition {
    fn operands(&self, value: &mut usize) {
        match self {
            Condition::Compare(compare) => compare.operands(value),
            Condition::Parity(expression) => expression.operands(value),
        }
    }

    fn outputs(&self, value: &mut usize) {
        match self {
            Condition::Compare(compare) => compare.outputs(value),
            Condition::Parity(expression) => expression.outputs(value),
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Condition::Compare(compare) => compare.temporary(),
            Condition::Parity(expression) => expression.temporary(),
        }
    }
}

impl Compare {
    fn operands(&self, value: &mut usize) {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => {
                first.operands(value);
                second.operands(value);
            }
        }
    }

    fn outputs(&self, value: &mut usize) {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => {
                first.outputs(value);
                second.outputs(value);
            }
        }
    }

    fn temporary(&self) -> usize {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => first.temporary() + second.temporary(),
        }
    }
}

pub fn build(rt: &mut Runtime, operation: &Operation) {
    let mut epilogue = rt.asm.create_label();
    let operands = operation.operands();
    let outputs = operation.outputs();
    let flags = !operation.flags.is_empty();
    let temporaries = operation.temporaries();
    let slots = operands + outputs + flags as usize + temporaries;
    let size = ((slots as i32 * 8) + 15) & !15;

    rt.asm.push(r13).unwrap();
    rt.asm.push(r14).unwrap();
    rt.asm.push(rbp).unwrap();
    rt.asm.mov(rbp, rsp).unwrap();
    rt.asm.sub(rsp, size).unwrap();

    rt.asm.mov(r13, rcx).unwrap();

    bytecode::read_byte_zx(rt, r13, r14d);

    for index in (0..operands).rev() {
        scratch::load(rt, r12, rax);

        rt.asm
            .mov(
                qword_ptr(rbp - Allocator::offset(operands, outputs, flags, Value::Input(index))),
                rax,
            )
            .unwrap();
    }

    let handlers = operation
        .widths
        .iter()
        .map(|&width| {
            let actions = operation.effects.clone();
            let rules = operation.flags.clone();
            (
                width,
                Box::new(move |rt: &mut Runtime, allocator: &mut Allocator| {
                    compile_effects(rt, allocator, &actions, width);

                    for index in 0..outputs {
                        let output = Value::Output(index);
                        let register = allocator.mutable(rt, output, &[]);
                        let mask = allocator.acquire(rt, &[output], &[register]);

                        rt.asm.mov(mask, width.mask() as i64).unwrap();
                        rt.asm.and(register, mask).unwrap();

                        allocator.spill(rt, mask);
                        allocator.dirty.insert(output);
                    }

                    if !rules.is_empty() {
                        compile_flags(rt, allocator, &rules, width);
                    }
                }) as Box<dyn FnOnce(&mut Runtime, &mut Allocator)>,
            )
        })
        .collect::<Vec<(VMWidth, Box<dyn FnOnce(&mut Runtime, &mut Allocator)>)>>();

    let cases = handlers
        .iter()
        .map(
            |(width, _function): &(VMWidth, Box<dyn FnOnce(&mut Runtime, &mut Allocator)>)| {
                (rt.mapper.index(*width) as u8, rt.asm.create_label())
            },
        )
        .collect::<Vec<(u8, CodeLabel)>>();

    rt.jumps(
        r14,
        cases
            .iter()
            .map(|(key, label): &(u8, CodeLabel)| (*key, *label))
            .collect::<Vec<(u8, CodeLabel)>>(),
    );

    for ((_key, mut label), (_width, handler)) in cases.into_iter().zip(handlers.into_iter()) {
        rt.asm.set_label(&mut label).unwrap();

        let mut local = Allocator::new(operands, outputs, flags);

        handler(rt, &mut local);

        local.dump(rt);

        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();

    match &operation.stores {
        Some(stores) => {
            let mut allocator = Allocator::new(operands, outputs, flags);
            for expression in stores {
                let result = compile_expression(rt, &mut allocator, expression, VMWidth::Lower64);
                let register = allocator.acquire(rt, &[], &[]);

                allocator.copy(rt, result, register);
                scratch::store(rt, r12, register);

                allocator.spill(rt, register);
                allocator.consume(result);
            }
        }
        None => {
            let mut allocator = Allocator::new(operands, outputs, flags);

            for index in (0..outputs).rev() {
                let output = allocator.acquire(rt, &[], &[]);
                allocator.copy(rt, ValueRef::Value(Value::Output(index)), output);
                scratch::store(rt, r12, output);
                allocator.spill(rt, output);
            }
        }
    }

    rt.asm.mov(rax, r13).unwrap();

    rt.asm.add(rsp, size).unwrap();
    rt.asm.pop(rbp).unwrap();
    rt.asm.pop(r14).unwrap();
    rt.asm.pop(r13).unwrap();
    rt.asm.ret().unwrap();
}

fn compile_effects(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    effects: &[Effect],
    width: VMWidth,
) {
    for effect in effects {
        compile_effect(rt, allocator, effect, width);
    }
}

fn compile_binary<F>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
    operation: F,
) where
    F: FnOnce(&mut Runtime, AsmRegister64, AsmRegister64),
{
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, width);

    let pinned = [first, second]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let result = allocator.acquire(rt, &pinned, &[]);
    allocator.copy(rt, first, result);

    let other = allocator.acquire(rt, &pinned, &[result]);
    allocator.copy(rt, second, other);

    operation(rt, result, other);

    allocator.replace(result, Value::Output(0), true);
    allocator.consume(first);
    allocator.consume(second);
}

fn compile_mul(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
) {
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, width);

    let pinned = [first, second]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let rhs = allocator.acquire(rt, &pinned, &[rax]);
    allocator.copy(rt, second, rhs);
    allocator.copy(rt, first, rax);

    let signed = width == width.signed();

    match width.size() {
        8 => {
            if signed {
                rt.asm.imul(rhs).unwrap();
            } else {
                rt.asm.mul(rhs).unwrap();
            }
        }
        4 => {
            let dword = get_gpr32(register::sized(rhs.into(), 4).unwrap()).unwrap();

            if signed {
                rt.asm.imul(dword).unwrap();
            } else {
                rt.asm.mul(dword).unwrap();
            }
        }
        2 => {
            let word = get_gpr16(register::sized(rhs.into(), 2).unwrap()).unwrap();

            if signed {
                rt.asm.imul(word).unwrap();
            } else {
                rt.asm.mul(word).unwrap();
            }
        }
        1 => {
            let byte = get_gpr8(register::sized(rhs.into(), 1).unwrap()).unwrap();

            if signed {
                rt.asm.imul(byte).unwrap();
            } else {
                rt.asm.mul(byte).unwrap();
            }
        }
        _ => unreachable!(),
    }

    allocator.replace(rax, Value::Output(0), true);
    allocator.replace(rdx, Value::Output(1), true);

    allocator.consume(first);
    allocator.consume(second);
}

fn compile_shift<F>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
    operation: F,
) where
    F: FnOnce(&mut Runtime, AsmRegister64),
{
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, width);

    let pinned = [first, second]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    allocator.copy(rt, second, rcx);

    let result = allocator.acquire(rt, &pinned, &[rcx]);
    allocator.copy(rt, first, result);

    operation(rt, result);

    allocator.replace(result, Value::Output(0), true);
    allocator.consume(first);
    allocator.consume(second);
}

fn compile_effect(rt: &mut Runtime, allocator: &mut Allocator, effect: &Effect, width: VMWidth) {
    match effect {
        Effect::Add(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, left, right| {
                rt.asm.add(left, right).unwrap();
            })
        }
        Effect::Sub(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, left, right| {
                rt.asm.sub(left, right).unwrap();
            })
        }
        Effect::And(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, left, right| {
                rt.asm.and(left, right).unwrap();
            })
        }
        Effect::Or(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, left, right| {
                rt.asm.or(left, right).unwrap();
            })
        }
        Effect::Xor(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, left, right| {
                rt.asm.xor(left, right).unwrap();
            })
        }
        Effect::Mul(first, second) => compile_mul(rt, allocator, first, second, width),
        Effect::Shr(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, result| {
                rt.asm.shr(result, cl).unwrap();
            })
        }
        Effect::Shl(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, result| {
                rt.asm.shl(result, cl).unwrap();
            })
        }
        Effect::Ror(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, result| {
                rt.asm.ror(result, cl).unwrap();
            })
        }
        Effect::Rol(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, result| {
                rt.asm.rol(result, cl).unwrap();
            })
        }
        Effect::Sar(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, result| {
                rt.asm.sar(result, cl).unwrap();
            })
        }
        Effect::Assign(expression) => {
            let value = compile_expression(rt, allocator, expression, width);
            let register = allocator.acquire(rt, &[], &[]);
            allocator.copy(rt, value, register);

            allocator.replace(register, Value::Output(0), true);
            allocator.consume(value);
        }
        Effect::Bsr(expression) => {
            compile_unary(rt, allocator, expression, width, |rt, result, source| {
                rt.asm.bsr(result, source).unwrap();
            })
        }
        Effect::Tzcnt(expression) => {
            compile_unary(rt, allocator, expression, width, |rt, result, source| {
                rt.asm.tzcnt(result, source).unwrap();
            })
        }
    }
}

fn compile_unary<F>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    expression: &Expression,
    width: VMWidth,
    operation: F,
) where
    F: FnOnce(&mut Runtime, AsmRegister64, AsmRegister64),
{
    let value = compile_expression(rt, allocator, expression, width);
    let src = allocator.acquire(rt, &[], &[]);

    allocator.copy(rt, value, src);

    let mask = allocator.acquire(rt, &[], &[src]);

    rt.asm.mov(mask, width.mask() as i64).unwrap();
    rt.asm.and(src, mask).unwrap();

    allocator.spill(rt, mask);

    let dst = allocator.mutable(rt, Value::Output(0), &[src]);

    operation(rt, dst, src);

    allocator.dirty.insert(Value::Output(0));
    allocator.consume(value);
}

fn compile_expression(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    expression: &Expression,
    width: VMWidth,
) -> ValueRef {
    match expression {
        Expression::Operand(Operand::Input(index)) => ValueRef::Value(Value::Input(*index)),
        Expression::Operand(Operand::Output(index)) => ValueRef::Value(Value::Output(*index)),
        Expression::Constant(value) => ValueRef::Immediate(*value as i64),
        Expression::SignBit => ValueRef::Immediate(width.mask().ilog2() as i64),
        Expression::Sub(first, second)
        | Expression::BitAnd(first, second)
        | Expression::BitOr(first, second)
        | Expression::BitXor(first, second) => {
            let first = compile_expression(rt, allocator, first, width);
            let second = compile_expression(rt, allocator, second, width);

            let pinned = [first, second]
                .into_iter()
                .filter_map(|value| match value {
                    ValueRef::Value(value) => Some(value),
                    ValueRef::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            let result = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, first, result);

            let other = allocator.acquire(rt, &pinned, &[result]);
            allocator.copy(rt, second, other);

            match expression {
                Expression::Sub(_, _) => rt.asm.sub(result, other).unwrap(),
                Expression::BitAnd(_, _) => rt.asm.and(result, other).unwrap(),
                Expression::BitOr(_, _) => rt.asm.or(result, other).unwrap(),
                Expression::BitXor(_, _) => rt.asm.xor(result, other).unwrap(),
                _ => unreachable!(),
            }

            allocator.consume(first);
            allocator.consume(second);

            if other != result {
                allocator.spill(rt, other);
            }

            let value = allocator.temporary();
            allocator.replace(result, value, true);

            ValueRef::Value(value)
        }
        Expression::BitShr(first, second) | Expression::BitShl(first, second) => {
            let first = compile_expression(rt, allocator, first, width);
            let second = compile_expression(rt, allocator, second, width);

            let pinned = [first, second]
                .into_iter()
                .filter_map(|value| match value {
                    ValueRef::Value(value) => Some(value),
                    ValueRef::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            allocator.copy(rt, second, rcx);

            let result = allocator.acquire(rt, &pinned, &[rcx]);
            allocator.copy(rt, first, result);

            match expression {
                Expression::BitShr(_, _) => rt.asm.shr(result, cl).unwrap(),
                Expression::BitShl(_, _) => rt.asm.shl(result, cl).unwrap(),
                _ => unreachable!(),
            }

            allocator.consume(first);
            allocator.consume(second);

            let value = allocator.temporary();
            allocator.replace(result, value, true);

            ValueRef::Value(value)
        }
        Expression::BitNot(inner) | Expression::LowByte(inner) => {
            let inner = compile_expression(rt, allocator, inner, width);
            let result = allocator.acquire(rt, &[], &[]);

            allocator.copy(rt, inner, result);

            match expression {
                Expression::BitNot(_) => rt.asm.not(result).unwrap(),
                Expression::LowByte(_) => {
                    let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();
                    rt.asm.movzx(result, byte).unwrap();
                }
                _ => unreachable!(),
            }

            allocator.consume(inner);

            let value = allocator.temporary();
            allocator.replace(result, value, true);

            ValueRef::Value(value)
        }
    }
}

fn compile_flags(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    rules: &[(Flag, Condition)],
    width: VMWidth,
) {
    rt.asm
        .mov(
            qword_ptr(
                rbp - Allocator::offset(
                    allocator.inputs,
                    allocator.outputs,
                    allocator.flags,
                    Value::Flags,
                ),
            ),
            0x0,
        )
        .unwrap();

    for (flag, condition) in rules {
        match condition {
            Condition::Compare(item) => compile_comparison(rt, allocator, *flag, item, width),
            Condition::Parity(node) => compile_parity(rt, allocator, *flag, node, width),
        }
    }

    let register = allocator.acquire(rt, &[], &[]);

    rt.asm
        .mov(
            register,
            qword_ptr(
                rbp - Allocator::offset(
                    allocator.inputs,
                    allocator.outputs,
                    allocator.flags,
                    Value::Flags,
                ),
            ),
        )
        .unwrap();
    vreg::store_reg(rt, r12, register, VMReg::Flags);

    allocator.untrack(register);
}

fn compile_comparison(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    flag: Flag,
    compare: &Compare,
    width: VMWidth,
) {
    let (first, second, condition) = match compare {
        Compare::Equal(first, second) => (first, second, 0u8),
        Compare::LessThan(first, second) => (first, second, 1u8),
        Compare::GreaterThan(first, second) => (first, second, 2u8),
        Compare::BitSet(first, second) => (first, second, 3u8),
    };

    let left = compile_expression(rt, allocator, first, width);
    let right = compile_expression(rt, allocator, second, width);

    let pinned = [left, right]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let lhs = allocator.acquire(rt, &pinned, &[]);
    allocator.copy(rt, left, lhs);

    let rhs = allocator.acquire(rt, &pinned, &[lhs]);
    allocator.copy(rt, right, rhs);

    let result = allocator.acquire(rt, &pinned, &[lhs, rhs]);
    let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();

    match condition {
        0 | 1 | 2 => rt.asm.cmp(lhs, rhs).unwrap(),
        3 => rt.asm.bt(lhs, rhs).unwrap(),
        _ => unreachable!(),
    }

    match condition {
        0 => rt.asm.sete(byte).unwrap(),
        1 => rt.asm.setb(byte).unwrap(),
        2 => rt.asm.seta(byte).unwrap(),
        3 => rt.asm.setc(byte).unwrap(),
        _ => unreachable!(),
    }

    rt.asm.movzx(result, byte).unwrap();
    rt.asm
        .shl(result, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm
        .or(
            qword_ptr(
                rbp - Allocator::offset(
                    allocator.inputs,
                    allocator.outputs,
                    allocator.flags,
                    Value::Flags,
                ),
            ),
            result,
        )
        .unwrap();

    allocator.spill(rt, result);
    allocator.consume(left);
    allocator.consume(right);
    allocator.spill(rt, lhs);

    if rhs != lhs {
        allocator.spill(rt, rhs);
    }
}

fn compile_parity(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    flag: Flag,
    node: &Expression,
    width: VMWidth,
) {
    let value = compile_expression(rt, allocator, node, width);
    let register = allocator.acquire(rt, &[], &[]);

    allocator.copy(rt, value, register);

    let byte = get_gpr8(register::sized(register.into(), 1).unwrap()).unwrap();
    rt.asm.movzx(register, byte).unwrap();
    rt.asm.popcnt(register, register).unwrap();
    rt.asm.not(register).unwrap();
    rt.asm.and(register, 0x1).unwrap();
    rt.asm
        .shl(register, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm
        .or(
            qword_ptr(
                rbp - Allocator::offset(
                    allocator.inputs,
                    allocator.outputs,
                    allocator.flags,
                    Value::Flags,
                ),
            ),
            register,
        )
        .unwrap();

    allocator.untrack(register);
    allocator.consume(value);
}

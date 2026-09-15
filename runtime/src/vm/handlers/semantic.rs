use iced_x86::code_asm::{
    cl, get_gpr8, qword_ptr, r12, r13, r14, r14d, r8, r9, rax, rbp, rcx, rdx, rsp, AsmRegister64,
    CodeLabel,
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
    Input(u8),
    Output(u8),
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
    InputA,
    InputB,
    OutputA,
    Flags,
    Temporary(u32),
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
    temporary: u32,
    slots: u32,
}

impl Allocator {
    const REGISTERS: [AsmRegister64; 5] = [rax, rcx, rdx, r8, r9];

    fn new(slots: u32) -> Self {
        Self {
            tracked: Vec::new(),
            dirty: HashSet::new(),
            temporary: 0,
            slots,
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

    fn mark_dirty(&mut self, value: Value) {
        self.dirty.insert(value);
    }

    fn temp(&mut self) -> Value {
        let value = Value::Temporary(self.temporary);
        self.temporary += 1;
        assert!(
            self.temporary <= self.slots,
            "allocator ran out of temporary slots"
        );
        value
    }

    fn offset(value: Value) -> i32 {
        let slot = match value {
            Value::InputA => 0,
            Value::InputB => 1,
            Value::OutputA => 2,
            Value::Flags => 3,
            Value::Temporary(index) => 4 + index,
        };
        (slot as i32 + 1) * 8
    }

    fn spill_register(&mut self, rt: &mut Runtime, register: AsmRegister64) {
        let Some(value) = self.tracked_value(register) else {
            return;
        };

        if self.dirty.remove(&value) {
            rt.asm
                .mov(qword_ptr(rbp - Self::offset(value)), register)
                .unwrap();
        }

        self.untrack(register);
    }

    fn spill_registers(&mut self, rt: &mut Runtime) {
        let registers = self
            .tracked
            .iter()
            .map(|(register, _)| *register)
            .collect::<Vec<AsmRegister64>>();

        for register in registers {
            self.spill_register(rt, register);
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
            self.spill_register(rt, register);
            return register;
        }

        let register = Self::REGISTERS
            .iter()
            .copied()
            .find(|register| !avoid.contains(register))
            .expect("allocator has no usable register");
        self.spill_register(rt, register);
        register
    }

    fn copy_to_register(&mut self, rt: &mut Runtime, value: ValueRef, register: AsmRegister64) {
        self.spill_register(rt, register);

        match value {
            ValueRef::Immediate(value) => {
                rt.asm.mov(register, value).unwrap();
            }
            ValueRef::Value(value) => {
                if let Some(source) = self.tracked_register(value) {
                    rt.asm.mov(register, source).unwrap();
                } else {
                    rt.asm
                        .mov(register, qword_ptr(rbp - Self::offset(value)))
                        .unwrap();
                }
            }
        }
    }

    fn load_mutable(
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
            .mov(register, qword_ptr(rbp - Self::offset(value)))
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

#[derive(Clone, Copy)]
struct Context {
    input_a: Value,
    input_b: Value,
    output_a: Value,
}

// TODO: Implement a mixed-boolean-arithmetic engine!

fn operands(effects: &[Effect], flags: &[(Flag, Condition)]) -> u8 {
    let mut value = 0;

    for effect in effects {
        effect.operands(&mut value);
    }

    for (_, condition) in flags {
        condition.operands(&mut value);
    }

    value
}

impl Expression {
    fn operands(&self, value: &mut u8) {
        match self {
            Expression::Operand(Operand::Input(n)) => {
                *value = (*value).max(n + 1);
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

    fn temporary(&self) -> u32 {
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
    fn operands(&self, value: &mut u8) {
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

    fn temporary(&self) -> u32 {
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
    fn operands(&self, value: &mut u8) {
        match self {
            Condition::Compare(compare) => compare.operands(value),
            Condition::Parity(expression) => expression.operands(value),
        }
    }

    fn temporary(&self) -> u32 {
        match self {
            Condition::Compare(compare) => compare.temporary(),
            Condition::Parity(expression) => expression.temporary(),
        }
    }
}

impl Compare {
    fn operands(&self, value: &mut u8) {
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

    fn temporary(&self) -> u32 {
        match self {
            Compare::Equal(first, second)
            | Compare::LessThan(first, second)
            | Compare::GreaterThan(first, second)
            | Compare::BitSet(first, second) => first.temporary() + second.temporary(),
        }
    }
}

fn temporaries(operation: &Operation) -> u32 {
    let effects = operation.effects.iter().map(Effect::temporary).sum::<u32>();
    let flags = operation
        .flags
        .iter()
        .map(|(_, condition)| condition.temporary())
        .sum::<u32>();
    let stores = operation
        .stores
        .as_ref()
        .map(|stores| stores.iter().map(Expression::temporary).sum::<u32>())
        .unwrap_or(0);

    effects + flags + stores
}

pub fn build(rt: &mut Runtime, operation: &Operation) {
    let mut epilogue = rt.asm.create_label();
    let operand_count = operands(&operation.effects, &operation.flags);
    let temporaries = temporaries(operation);
    let slots = 4 + temporaries;
    let size = ((slots as i32 * 8) + 15) & !15;

    rt.asm.push(r13).unwrap();
    rt.asm.push(r14).unwrap();
    rt.asm.push(rbp).unwrap();
    rt.asm.mov(rbp, rsp).unwrap();
    rt.asm.sub(rsp, size).unwrap();

    rt.asm.mov(r13, rcx).unwrap();

    bytecode::read_byte_zx(rt, r13, r14d);

    let context = Context {
        input_a: Value::InputA,
        input_b: Value::InputB,
        output_a: Value::OutputA,
    };

    if operand_count > 1 {
        scratch::load(rt, r12, rax);

        rt.asm
            .mov(qword_ptr(rbp - Allocator::offset(Value::InputB)), rax)
            .unwrap();
    }

    scratch::load(rt, r12, rax);

    rt.asm
        .mov(qword_ptr(rbp - Allocator::offset(Value::InputA)), rax)
        .unwrap();

    let handlers = operation
        .widths
        .iter()
        .map(|&width| {
            let actions = operation.effects.clone();
            let rules = operation.flags.clone();
            (
                width,
                Box::new(move |rt: &mut Runtime, allocator: &mut Allocator| {
                    compile_effects(rt, allocator, &context, &actions, width);

                    let output = allocator.load_mutable(rt, context.output_a, &[]);
                    let mask = allocator.acquire(rt, &[context.output_a], &[output]);

                    rt.asm.mov(mask, width.mask() as i64).unwrap();
                    rt.asm.and(output, mask).unwrap();

                    allocator.spill_register(rt, mask);
                    allocator.mark_dirty(context.output_a);

                    compile_flags(rt, allocator, &context, &rules, width);
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

        let mut local = Allocator::new(temporaries);

        handler(rt, &mut local);

        local.spill_registers(rt);

        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();

    match &operation.stores {
        Some(stores) => {
            let mut allocator = Allocator::new(temporaries);
            for expression in stores {
                let result =
                    compile_expression(rt, &mut allocator, &context, expression, VMWidth::Lower64);
                let register = allocator.acquire(rt, &[], &[]);

                allocator.copy_to_register(rt, result, register);
                scratch::store(rt, r12, register);

                allocator.spill_register(rt, register);
                allocator.consume(result);
            }
        }
        None => {
            let mut allocator = Allocator::new(temporaries);
            let register = allocator.acquire(rt, &[], &[]);

            allocator.copy_to_register(rt, ValueRef::Value(context.output_a), register);
            scratch::store(rt, r12, register);

            allocator.spill_register(rt, register);
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
    context: &Context,
    effects: &[Effect],
    width: VMWidth,
) {
    for effect in effects {
        compile_effect(rt, allocator, context, effect, width);
    }
}

fn compile_binary<F>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
    operation: F,
) where
    F: FnOnce(&mut Runtime, AsmRegister64, AsmRegister64),
{
    let first = compile_expression(rt, allocator, context, first, width);
    let second = compile_expression(rt, allocator, context, second, width);

    let pinned = [first, second]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let result = allocator.acquire(rt, &pinned, &[]);
    allocator.copy_to_register(rt, first, result);

    let other = allocator.acquire(rt, &pinned, &[result]);
    allocator.copy_to_register(rt, second, other);

    operation(rt, result, other);

    allocator.replace(result, context.output_a, true);
    allocator.consume(first);
    allocator.consume(second);
}

fn compile_shift<F>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
    operation: F,
) where
    F: FnOnce(&mut Runtime, AsmRegister64),
{
    let first = compile_expression(rt, allocator, context, first, width);
    let second = compile_expression(rt, allocator, context, second, width);

    let pinned = [first, second]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    allocator.copy_to_register(rt, second, rcx);

    let result = allocator.acquire(rt, &pinned, &[rcx]);
    allocator.copy_to_register(rt, first, result);

    operation(rt, result);

    allocator.replace(result, context.output_a, true);
    allocator.consume(first);
    allocator.consume(second);
}

fn compile_effect(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    effect: &Effect,
    width: VMWidth,
) {
    match effect {
        Effect::Add(first, second) => compile_binary(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, left, right| {
                rt.asm.add(left, right).unwrap();
            },
        ),
        Effect::Sub(first, second) => compile_binary(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, left, right| {
                rt.asm.sub(left, right).unwrap();
            },
        ),
        Effect::And(first, second) => compile_binary(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, left, right| {
                rt.asm.and(left, right).unwrap();
            },
        ),
        Effect::Or(first, second) => compile_binary(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, left, right| {
                rt.asm.or(left, right).unwrap();
            },
        ),
        Effect::Xor(first, second) => compile_binary(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, left, right| {
                rt.asm.xor(left, right).unwrap();
            },
        ),
        Effect::Mul(first, second) => compile_binary(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, left, right| {
                rt.asm.imul_2(left, right).unwrap();
            },
        ),
        Effect::Shr(first, second) => compile_shift(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, result| {
                rt.asm.shr(result, cl).unwrap();
            },
        ),
        Effect::Shl(first, second) => compile_shift(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, result| {
                rt.asm.shl(result, cl).unwrap();
            },
        ),
        Effect::Ror(first, second) => compile_shift(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, result| {
                rt.asm.ror(result, cl).unwrap();
            },
        ),
        Effect::Rol(first, second) => compile_shift(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, result| {
                rt.asm.rol(result, cl).unwrap();
            },
        ),
        Effect::Sar(first, second) => compile_shift(
            rt,
            allocator,
            context,
            first,
            second,
            width,
            |rt, result| {
                rt.asm.sar(result, cl).unwrap();
            },
        ),
        Effect::Assign(expression) => {
            let value = compile_expression(rt, allocator, context, expression, width);
            let register = allocator.acquire(rt, &[], &[]);
            allocator.copy_to_register(rt, value, register);

            allocator.replace(register, context.output_a, true);
            allocator.consume(value);
        }
        Effect::Bsr(expression) => compile_unary(
            rt,
            allocator,
            context,
            expression,
            width,
            |rt, result, source| {
                rt.asm.bsr(result, source).unwrap();
            },
        ),
        Effect::Tzcnt(expression) => compile_unary(
            rt,
            allocator,
            context,
            expression,
            width,
            |rt, result, source| {
                rt.asm.tzcnt(result, source).unwrap();
            },
        ),
    }
}

fn compile_unary<F>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    expression: &Expression,
    width: VMWidth,
    operation: F,
) where
    F: FnOnce(&mut Runtime, AsmRegister64, AsmRegister64),
{
    let value = compile_expression(rt, allocator, context, expression, width);
    let src = allocator.acquire(rt, &[], &[]);

    allocator.copy_to_register(rt, value, src);

    let mask = allocator.acquire(rt, &[], &[src]);

    rt.asm.mov(mask, width.mask() as i64).unwrap();
    rt.asm.and(src, mask).unwrap();

    allocator.spill_register(rt, mask);

    let dst = allocator.load_mutable(rt, context.output_a, &[src]);

    operation(rt, dst, src);

    allocator.mark_dirty(context.output_a);
    allocator.consume(value);
}

fn compile_expression(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    expression: &Expression,
    width: VMWidth,
) -> ValueRef {
    match expression {
        Expression::Operand(Operand::Input(0)) => ValueRef::Value(context.input_a),
        Expression::Operand(Operand::Input(1)) => ValueRef::Value(context.input_b),
        Expression::Operand(Operand::Output(0)) => ValueRef::Value(context.output_a),
        Expression::Operand(_) => unreachable!(),
        Expression::Constant(value) => ValueRef::Immediate(*value as i64),
        Expression::SignBit => ValueRef::Immediate(width.mask().ilog2() as i64),
        Expression::Sub(first, second)
        | Expression::BitAnd(first, second)
        | Expression::BitOr(first, second)
        | Expression::BitXor(first, second) => {
            let first = compile_expression(rt, allocator, context, first, width);
            let second = compile_expression(rt, allocator, context, second, width);

            let pinned = [first, second]
                .into_iter()
                .filter_map(|value| match value {
                    ValueRef::Value(value) => Some(value),
                    ValueRef::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            let result = allocator.acquire(rt, &pinned, &[]);
            allocator.copy_to_register(rt, first, result);

            let other = allocator.acquire(rt, &pinned, &[result]);
            allocator.copy_to_register(rt, second, other);

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
                allocator.spill_register(rt, other);
            }

            let value = allocator.temp();
            allocator.replace(result, value, true);

            ValueRef::Value(value)
        }
        Expression::BitShr(first, second) | Expression::BitShl(first, second) => {
            let first = compile_expression(rt, allocator, context, first, width);
            let second = compile_expression(rt, allocator, context, second, width);

            let pinned = [first, second]
                .into_iter()
                .filter_map(|value| match value {
                    ValueRef::Value(value) => Some(value),
                    ValueRef::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            allocator.copy_to_register(rt, second, rcx);

            let result = allocator.acquire(rt, &pinned, &[rcx]);
            allocator.copy_to_register(rt, first, result);

            match expression {
                Expression::BitShr(_, _) => rt.asm.shr(result, cl).unwrap(),
                Expression::BitShl(_, _) => rt.asm.shl(result, cl).unwrap(),
                _ => unreachable!(),
            }

            allocator.consume(first);
            allocator.consume(second);

            let value = allocator.temp();
            allocator.replace(result, value, true);

            ValueRef::Value(value)
        }
        Expression::BitNot(inner) | Expression::LowByte(inner) => {
            let inner = compile_expression(rt, allocator, context, inner, width);
            let result = allocator.acquire(rt, &[], &[]);

            allocator.copy_to_register(rt, inner, result);

            match expression {
                Expression::BitNot(_) => rt.asm.not(result).unwrap(),
                Expression::LowByte(_) => {
                    let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();
                    rt.asm.movzx(result, byte).unwrap();
                }
                _ => unreachable!(),
            }

            allocator.consume(inner);

            let value = allocator.temp();
            allocator.replace(result, value, true);

            ValueRef::Value(value)
        }
    }
}

fn compile_flags(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    rules: &[(Flag, Condition)],
    width: VMWidth,
) {
    rt.asm
        .mov(qword_ptr(rbp - Allocator::offset(Value::Flags)), 0i32)
        .unwrap();

    for (flag, definition) in rules {
        match definition {
            Condition::Compare(item) => {
                compile_comparison(rt, allocator, context, *flag, item, width)
            }
            Condition::Parity(node) => compile_parity(rt, allocator, context, *flag, node, width),
        }
    }

    let register = allocator.acquire(rt, &[], &[]);

    rt.asm
        .mov(register, qword_ptr(rbp - Allocator::offset(Value::Flags)))
        .unwrap();
    vreg::store_reg(rt, r12, register, VMReg::Flags);

    allocator.untrack(register);
}

fn compile_comparison(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
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

    let left = compile_expression(rt, allocator, context, first, width);
    let right = compile_expression(rt, allocator, context, second, width);

    let pinned = [left, right]
        .into_iter()
        .filter_map(|value| match value {
            ValueRef::Value(value) => Some(value),
            ValueRef::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let left_register = allocator.acquire(rt, &pinned, &[]);
    allocator.copy_to_register(rt, left, left_register);

    let right_register = allocator.acquire(rt, &pinned, &[left_register]);
    allocator.copy_to_register(rt, right, right_register);

    let result = allocator.acquire(rt, &pinned, &[left_register, right_register]);
    let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();

    match condition {
        0 | 1 | 2 => rt.asm.cmp(left_register, right_register).unwrap(),
        3 => rt.asm.bt(left_register, right_register).unwrap(),
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
        .or(qword_ptr(rbp - Allocator::offset(Value::Flags)), result)
        .unwrap();

    allocator.spill_register(rt, result);
    allocator.consume(left);
    allocator.consume(right);
    allocator.spill_register(rt, left_register);

    if right_register != left_register {
        allocator.spill_register(rt, right_register);
    }
}

fn compile_parity(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    flag: Flag,
    node: &Expression,
    width: VMWidth,
) {
    let value = compile_expression(rt, allocator, context, node, width);
    let register = allocator.acquire(rt, &[], &[]);

    allocator.copy_to_register(rt, value, register);

    let byte = get_gpr8(register::sized(register.into(), 1).unwrap()).unwrap();
    rt.asm.movzx(register, byte).unwrap();
    rt.asm.popcnt(register, register).unwrap();
    rt.asm.not(register).unwrap();
    rt.asm.and(register, 0x1).unwrap();
    rt.asm
        .shl(register, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm
        .or(qword_ptr(rbp - Allocator::offset(Value::Flags)), register)
        .unwrap();

    allocator.untrack(register);
    allocator.consume(value);
}

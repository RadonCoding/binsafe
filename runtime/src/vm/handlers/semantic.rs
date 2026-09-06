use iced_x86::code_asm::{
    cl, get_gpr32, get_gpr8, qword_ptr, r12, r13, r14, r8, r9, rax, rcx, rdx, rsp, AsmRegister64,
    CodeLabel,
};
use rand::Rng;

use crate::{
    register,
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMReg, VMWidth},
        utils::{bytecode, scratch, vreg},
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    A,
    B,
    Result,
}

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum Compare {
    Equal(Expression, Expression),
    LessThan(Expression, Expression),
    GreaterThan(Expression, Expression),
    BitSet(Expression, Expression),
}

#[derive(Clone)]
pub enum FlagDef {
    Compare(Compare),
    Parity(Expression),
}

pub struct Operation {
    pub effects: Vec<Effect>,
    pub flags: Vec<(Flag, FlagDef)>,
    pub store: Option<Expression>,
    pub widths: &'static [VMWidth],
    pub operands: u8,
}

#[derive(Clone)]
struct Allocator {
    available: Vec<AsmRegister64>,
    protected: Vec<AsmRegister64>,
}

impl Allocator {
    fn new() -> Self {
        Self {
            available: vec![rax, rcx, rdx, r8, r9],
            protected: vec![],
        }
    }

    fn alloc(&mut self) -> AsmRegister64 {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..self.available.len());
        self.available.swap_remove(index)
    }

    fn free(&mut self, register: AsmRegister64) {
        if !self.protected.contains(&register) && !self.available.contains(&register) {
            self.available.push(register);
        }
    }

    fn protect(&mut self, register: AsmRegister64) {
        self.protected.push(register);
    }

    fn protected(&self, register: AsmRegister64) -> bool {
        self.protected.contains(&register)
    }
}

#[derive(Clone)]
struct Context {
    first: AsmRegister64,
    second: AsmRegister64,
    result: AsmRegister64,
}

pub fn build(rt: &mut Runtime, operation: &Operation) {
    let mut epilogue = rt.asm.create_label();

    rt.asm.push(r13).unwrap();
    rt.asm.push(r14).unwrap();

    rt.asm.mov(r13, rcx).unwrap();

    let mut allocator = Allocator::new();
    let index = allocator.alloc();

    bytecode::read_byte_zx(
        rt,
        r13,
        get_gpr32(register::sized(index.into(), 4).unwrap()).unwrap(),
    );

    allocator.available.retain(|&r| r != rcx);

    let first = allocator.alloc();
    let second = allocator.alloc();
    let result = allocator.alloc();

    allocator.available.push(rcx);

    allocator.protect(first);
    allocator.protect(second);
    allocator.protect(result);

    let context = Context {
        first,
        second,
        result,
    };

    if operation.operands > 1 {
        scratch::load(rt, r12, second);
    }
    scratch::load(rt, r12, first);

    let handlers = operation
        .widths
        .iter()
        .map(|&width| {
            let actions = operation.effects.clone();
            let rules = operation.flags.clone();
            let context = context.clone();
            (
                width,
                Box::new(move |rt: &mut Runtime, allocator: &mut Allocator| {
                    effects(rt, allocator, &context, &actions, width);
                    let temporary = allocator.alloc();
                    rt.asm.mov(temporary, width.mask() as i64).unwrap();
                    rt.asm.and(context.result, temporary).unwrap();
                    allocator.free(temporary);
                    flags(rt, allocator, &context, &rules, width);
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
        index,
        cases
            .iter()
            .map(|(key, label): &(u8, CodeLabel)| (*key, *label))
            .collect::<Vec<(u8, CodeLabel)>>(),
    );

    allocator.free(index);

    for ((_key, mut label), (_width, handler)) in cases.into_iter().zip(handlers.into_iter()) {
        rt.asm.set_label(&mut label).unwrap();
        let mut local = allocator.clone();
        handler(rt, &mut local);
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();

    match &operation.store {
        Some(target) => {
            let register = expression(rt, &mut allocator, &context, target, VMWidth::Lower64);
            scratch::store(rt, r12, register);
            allocator.free(register);
        }
        None => {
            scratch::store(rt, r12, context.result);
        }
    }

    rt.asm.mov(rax, r13).unwrap();

    rt.asm.pop(r14).unwrap();
    rt.asm.pop(r13).unwrap();
    rt.asm.ret().unwrap();
}

fn effects(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    list: &[Effect],
    width: VMWidth,
) {
    for item in list {
        effect(rt, allocator, context, item, width);
    }
}

fn effect(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    item: &Effect,
    width: VMWidth,
) {
    macro_rules! binary {
        ($rt:expr, $allocator:expr, $context:expr, $first:expr, $second:expr, $operation:ident, $width:expr) => {{
            let first = expression($rt, $allocator, $context, $first, $width);
            let second = expression($rt, $allocator, $context, $second, $width);
            if first != $context.result {
                $rt.asm.mov($context.result, first).unwrap();
            }
            $rt.asm.$operation($context.result, second).unwrap();
            $allocator.free(first);
            $allocator.free(second);
        }};
    }

    macro_rules! shift {
        ($rt:expr, $allocator:expr, $context:expr, $first:expr, $second:expr, $operation:ident, $width:expr) => {{
            let second = expression($rt, $allocator, $context, $second, $width);
            let busy =
                !$allocator.available.contains(&rcx) && second != rcx && !$allocator.protected(rcx);
            if busy {
                $rt.asm.push(rcx).unwrap();
            }
            if second != rcx {
                $rt.asm.mov(rcx, second).unwrap();
                $allocator.free(second);
            }
            let available = $allocator.available.contains(&rcx);
            if available {
                $allocator.available.retain(|&register| register != rcx);
            }

            let first = expression($rt, $allocator, $context, $first, $width);
            if first != $context.result {
                $rt.asm.mov($context.result, first).unwrap();
            }
            $rt.asm.$operation($context.result, cl).unwrap();
            $allocator.free(first);

            if busy {
                $rt.asm.pop(rcx).unwrap();
            } else {
                $allocator.free(rcx);
            }
        }};
    }

    match item {
        Effect::Add(first, second) => binary!(rt, allocator, context, first, second, add, width),
        Effect::Sub(first, second) => binary!(rt, allocator, context, first, second, sub, width),
        Effect::And(first, second) => binary!(rt, allocator, context, first, second, and, width),
        Effect::Or(first, second) => binary!(rt, allocator, context, first, second, or, width),
        Effect::Xor(first, second) => binary!(rt, allocator, context, first, second, xor, width),
        Effect::Mul(first, second) => binary!(rt, allocator, context, first, second, imul_2, width),
        Effect::Shr(first, second) => shift!(rt, allocator, context, first, second, shr, width),
        Effect::Shl(first, second) => shift!(rt, allocator, context, first, second, shl, width),
        Effect::Ror(first, second) => shift!(rt, allocator, context, first, second, ror, width),
        Effect::Rol(first, second) => shift!(rt, allocator, context, first, second, rol, width),
        Effect::Sar(first, second) => shift!(rt, allocator, context, first, second, sar, width),
        Effect::Assign(expr) => {
            let value = expression(rt, allocator, context, expr, width);
            if value != context.result {
                rt.asm.mov(context.result, value).unwrap();
                allocator.free(value);
            }
        }
        Effect::Bsr(expr) => {
            let mut src = expression(rt, allocator, context, expr, width);
            if allocator.protected(src) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, src).unwrap();
                src = temporary;
            }
            let mask = allocator.alloc();
            rt.asm.mov(mask, width.mask() as i64).unwrap();
            rt.asm.and(src, mask).unwrap();
            allocator.free(mask);
            rt.asm.bsr(context.result, src).unwrap();
            allocator.free(src);
        }
        Effect::Tzcnt(expr) => {
            let mut src = expression(rt, allocator, context, expr, width);
            if allocator.protected(src) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, src).unwrap();
                src = temporary;
            }
            let mask = allocator.alloc();
            rt.asm.mov(mask, width.mask() as i64).unwrap();
            rt.asm.and(src, mask).unwrap();
            allocator.free(mask);
            rt.asm.tzcnt(context.result, src).unwrap();
            allocator.free(src);
        }
    }
}

fn expression(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    node: &Expression,
    width: VMWidth,
) -> AsmRegister64 {
    match node {
        Expression::Operand(Operand::A) => context.first,
        Expression::Operand(Operand::B) => context.second,
        Expression::Operand(Operand::Result) => context.result,
        Expression::Constant(value) => {
            let temporary = allocator.alloc();
            rt.asm.mov(temporary, *value as i64).unwrap();
            temporary
        }
        Expression::SignBit => {
            let temporary = allocator.alloc();
            rt.asm.mov(temporary, width.mask().ilog2() as i64).unwrap();
            temporary
        }
        Expression::Sub(first, second) => {
            let mut register = expression(rt, allocator, context, first, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }
            let other = expression(rt, allocator, context, second, width);
            rt.asm.sub(register, other).unwrap();
            allocator.free(other);
            register
        }
        Expression::LowByte(inner) => {
            let mut register = expression(rt, allocator, context, inner, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }
            let byte = get_gpr8(register::sized(register.into(), 1).unwrap()).unwrap();
            rt.asm.movzx(register, byte).unwrap();
            register
        }
        Expression::BitNot(inner) => {
            let mut register = expression(rt, allocator, context, inner, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }
            rt.asm.not(register).unwrap();
            register
        }
        Expression::BitAnd(first, second) => {
            let mut register = expression(rt, allocator, context, first, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }
            let other = expression(rt, allocator, context, second, width);
            rt.asm.and(register, other).unwrap();
            allocator.free(other);
            register
        }
        Expression::BitOr(first, second) => {
            let mut register = expression(rt, allocator, context, first, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }
            let other = expression(rt, allocator, context, second, width);
            rt.asm.or(register, other).unwrap();
            allocator.free(other);
            register
        }
        Expression::BitXor(first, second) => {
            let mut register = expression(rt, allocator, context, first, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }
            let other = expression(rt, allocator, context, second, width);
            rt.asm.xor(register, other).unwrap();
            allocator.free(other);
            register
        }
        Expression::BitShr(first, second) => {
            let other = expression(rt, allocator, context, second, width);
            let busy =
                !allocator.available.contains(&rcx) && other != rcx && !allocator.protected(rcx);

            if busy {
                rt.asm.push(rcx).unwrap();
            }
            if other != rcx {
                rt.asm.mov(rcx, other).unwrap();
                allocator.free(other);
            }

            let available = allocator.available.contains(&rcx);

            if available {
                allocator.available.retain(|&register| register != rcx);
            }

            let mut register = expression(rt, allocator, context, first, width);
            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }

            rt.asm.shr(register, cl).unwrap();

            if busy {
                rt.asm.pop(rcx).unwrap();
            } else {
                allocator.free(rcx);
            }
            register
        }
        Expression::BitShl(first, second) => {
            let other = expression(rt, allocator, context, second, width);

            let busy =
                !allocator.available.contains(&rcx) && other != rcx && !allocator.protected(rcx);

            if busy {
                rt.asm.push(rcx).unwrap();
            }

            if other != rcx {
                rt.asm.mov(rcx, other).unwrap();
                allocator.free(other);
            }

            let available = allocator.available.contains(&rcx);

            if available {
                allocator.available.retain(|&register| register != rcx);
            }

            let mut register = expression(rt, allocator, context, first, width);

            if allocator.protected(register) {
                let temporary = allocator.alloc();
                rt.asm.mov(temporary, register).unwrap();
                register = temporary;
            }

            rt.asm.shl(register, cl).unwrap();

            if busy {
                rt.asm.pop(rcx).unwrap();
            } else {
                allocator.free(rcx);
            }
            register
        }
    }
}

fn flags(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    list: &[(Flag, FlagDef)],
    width: VMWidth,
) {
    let temporary = allocator.alloc();
    rt.asm.xor(temporary, temporary).unwrap();
    rt.asm.push(temporary).unwrap();
    allocator.free(temporary);

    for (flag, definition) in list {
        match definition {
            FlagDef::Compare(item) => compare(rt, allocator, context, *flag, item, width),
            FlagDef::Parity(node) => parity(rt, allocator, context, *flag, node, width),
        }
    }

    let register = allocator.alloc();
    rt.asm.pop(register).unwrap();
    vreg::store_reg(rt, r12, register, VMReg::Flags);
    allocator.free(register);
}

fn compare(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    flag: Flag,
    compare: &Compare,
    width: VMWidth,
) {
    let temporary = match compare {
        Compare::Equal(first, second) => {
            let lhs = expression(rt, allocator, context, first, width);
            let rhs = expression(rt, allocator, context, second, width);
            rt.asm.cmp(lhs, rhs).unwrap();
            allocator.free(lhs);
            allocator.free(rhs);
            let result = allocator.alloc();
            let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();
            rt.asm.sete(byte).unwrap();
            rt.asm.movzx(result, byte).unwrap();
            result
        }
        Compare::LessThan(first, second) => {
            let lhs = expression(rt, allocator, context, first, width);
            let rhs = expression(rt, allocator, context, second, width);
            rt.asm.cmp(lhs, rhs).unwrap();
            allocator.free(lhs);
            allocator.free(rhs);
            let result = allocator.alloc();
            let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();
            rt.asm.setb(byte).unwrap();
            rt.asm.movzx(result, byte).unwrap();
            result
        }
        Compare::GreaterThan(first, second) => {
            let lhs = expression(rt, allocator, context, first, width);
            let rhs = expression(rt, allocator, context, second, width);
            rt.asm.cmp(lhs, rhs).unwrap();
            allocator.free(lhs);
            allocator.free(rhs);
            let result = allocator.alloc();
            let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();
            rt.asm.seta(byte).unwrap();
            rt.asm.movzx(result, byte).unwrap();
            result
        }
        Compare::BitSet(first, second) => {
            let lhs = expression(rt, allocator, context, first, width);
            let rhs = expression(rt, allocator, context, second, width);
            rt.asm.bt(lhs, rhs).unwrap();
            allocator.free(lhs);
            allocator.free(rhs);
            let result = allocator.alloc();
            let byte = get_gpr8(register::sized(result.into(), 1).unwrap()).unwrap();
            rt.asm.setc(byte).unwrap();
            rt.asm.movzx(result, byte).unwrap();
            result
        }
    };

    rt.asm
        .shl(temporary, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm.or(qword_ptr(rsp), temporary).unwrap();
    allocator.free(temporary);
}

fn parity(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    context: &Context,
    flag: Flag,
    node: &Expression,
    width: VMWidth,
) {
    let mut temporary = expression(rt, allocator, context, node, width);

    if allocator.protected(temporary) {
        let copy = allocator.alloc();
        rt.asm.mov(copy, temporary).unwrap();
        temporary = copy;
    }

    let byte = get_gpr8(register::sized(temporary.into(), 1).unwrap()).unwrap();
    rt.asm.movzx(temporary, byte).unwrap();
    rt.asm.popcnt(temporary, temporary).unwrap();
    rt.asm.not(temporary).unwrap();
    rt.asm.and(temporary, 1i32).unwrap();
    rt.asm
        .shl(temporary, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm.or(qword_ptr(rsp), temporary).unwrap();
    allocator.free(temporary);
}

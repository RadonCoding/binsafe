use iced_x86::code_asm::{
    cl, get_gpr16, get_gpr32, get_gpr8, qword_ptr, r12, r13, r14, r14d, rax, rbp, rcx, rdx, rsp,
    AsmRegister16, AsmRegister32, AsmRegister64, AsmRegister8, CodeAssembler, CodeLabel,
};

use crate::{
    register,
    runtime::Runtime,
    vm::{
        bytecode::{Flag, VMReg, VMWidth},
        handlers::semantic::{
            allocator::Allocator, Compare, Condition, Effect, Expression, Operand, Operation,
            Reference, Value,
        },
        utils::{bytecode, scratch, vreg},
    },
};

#[cfg(debug_assertions)]
#[track_caller]
pub fn compile(rt: &mut Runtime, operation: &Operation) {
    #[cfg(debug_assertions)]
    let index = rt.asm.instructions().len();

    let mut epilogue = rt.asm.create_label();
    let operands = operation.operands();
    let outputs = operation.outputs();
    let flags = !operation.flags.is_empty();
    let temporaries = operation.temporaries();
    let slots = operands + outputs + flags as usize + temporaries;
    let size = ((slots as i32 * 8) + 15) & !15;
    let allocator = Allocator::new(operands, outputs, flags);

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
            .mov(qword_ptr(rbp - allocator.offset(Value::Input(index))), rax)
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
                        allocator.dirty(output);
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
                let src = compile_expression(rt, &mut allocator, expression, VMWidth::Lower64);

                let dst = allocator.acquire(rt, &[], &[]);

                allocator.copy(rt, src, dst);

                scratch::store(rt, r12, dst);

                allocator.spill(rt, dst);
                allocator.consume(src);
            }
        }
        None => {
            let mut allocator = Allocator::new(operands, outputs, flags);

            for index in (0..outputs).rev() {
                let dst = allocator.acquire(rt, &[], &[]);
                allocator.copy(rt, Reference::Value(Value::Output(index)), dst);
                scratch::store(rt, r12, dst);
                allocator.spill(rt, dst);
            }
        }
    }

    rt.asm.mov(rax, r13).unwrap();

    rt.asm.add(rsp, size).unwrap();
    rt.asm.pop(rbp).unwrap();
    rt.asm.pop(r14).unwrap();
    rt.asm.pop(r13).unwrap();
    rt.asm.ret().unwrap();

    #[cfg(debug_assertions)]
    {
        use std::panic::Location;

        use logger::debug;

        let location = Location::caller();

        debug!("{}", location.file());

        for instruction in &rt.asm.instructions()[index..] {
            debug!("{}{instruction}", " ".repeat(4));
        }
    }
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
            Reference::Value(value) => Some(value),
            Reference::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let dst = allocator.acquire(rt, &pinned, &[]);
    allocator.copy(rt, first, dst);

    let src = allocator.acquire(rt, &pinned, &[dst]);
    allocator.copy(rt, second, src);

    operation(rt, dst, src);

    allocator.replace(dst, Value::Output(0), true);
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
            Reference::Value(value) => Some(value),
            Reference::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let src = allocator.acquire(rt, &pinned, &[rax]);
    allocator.copy(rt, second, src);
    allocator.copy(rt, first, rax);

    compile_implicit(
        rt,
        width,
        src,
        |asm, byte| asm.mul(byte).unwrap(),
        |asm, word| asm.mul(word).unwrap(),
        |asm, dword| asm.mul(dword).unwrap(),
        |asm, qword| asm.mul(qword).unwrap(),
        |asm, byte| asm.imul(byte).unwrap(),
        |asm, word| asm.imul(word).unwrap(),
        |asm, dword| asm.imul(dword).unwrap(),
        |asm, qword| asm.imul(qword).unwrap(),
    );

    allocator.replace(rax, Value::Output(0), true);
    allocator.replace(rdx, Value::Output(1), true);

    allocator.consume(first);
    allocator.consume(second);
}

fn compile_div(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    third: &Expression,
    width: VMWidth,
) {
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, width);
    let third = compile_expression(rt, allocator, third, width);

    let pinned = [first, second, third]
        .into_iter()
        .filter_map(|value| match value {
            Reference::Value(value) => Some(value),
            Reference::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let src = allocator.acquire(rt, &pinned, &[rax, rdx]);

    allocator.copy(rt, first, src);
    allocator.copy(rt, second, rax);
    allocator.copy(rt, third, rdx);

    compile_implicit(
        rt,
        width,
        src,
        |asm, byte| asm.div(byte).unwrap(),
        |asm, word| asm.div(word).unwrap(),
        |asm, dword| asm.div(dword).unwrap(),
        |asm, qword| asm.div(qword).unwrap(),
        |asm, byte| asm.idiv(byte).unwrap(),
        |asm, word| asm.idiv(word).unwrap(),
        |asm, dword| asm.idiv(dword).unwrap(),
        |asm, qword| asm.idiv(qword).unwrap(),
    );

    allocator.replace(rax, Value::Output(0), true);
    allocator.replace(rdx, Value::Output(1), true);

    allocator.consume(first);
    allocator.consume(second);
    allocator.consume(third);
}

fn compile_implicit<U8, U16, U32, U64, S8, S16, S32, S64>(
    rt: &mut Runtime,
    width: VMWidth,
    src: AsmRegister64,
    unsigned8: U8,
    unsigned16: U16,
    unsigned32: U32,
    unsigned64: U64,
    signed8: S8,
    signed16: S16,
    signed32: S32,
    signed64: S64,
) where
    U8: FnOnce(&mut CodeAssembler, AsmRegister8),
    U16: FnOnce(&mut CodeAssembler, AsmRegister16),
    U32: FnOnce(&mut CodeAssembler, AsmRegister32),
    U64: FnOnce(&mut CodeAssembler, AsmRegister64),
    S8: FnOnce(&mut CodeAssembler, AsmRegister8),
    S16: FnOnce(&mut CodeAssembler, AsmRegister16),
    S32: FnOnce(&mut CodeAssembler, AsmRegister32),
    S64: FnOnce(&mut CodeAssembler, AsmRegister64),
{
    let signed = width == width.signed();

    match (width.size(), signed) {
        (1, false) => {
            let byte = get_gpr8(register::sized(src.into(), 1).unwrap()).unwrap();
            unsigned8(&mut rt.asm, byte);
        }
        (2, false) => {
            let word = get_gpr16(register::sized(src.into(), 2).unwrap()).unwrap();
            unsigned16(&mut rt.asm, word);
        }
        (4, false) => {
            let dword = get_gpr32(register::sized(src.into(), 4).unwrap()).unwrap();
            unsigned32(&mut rt.asm, dword);
        }
        (8, false) => {
            unsigned64(&mut rt.asm, src);
        }
        (1, true) => {
            let byte = get_gpr8(register::sized(src.into(), 1).unwrap()).unwrap();
            signed8(&mut rt.asm, byte);
        }
        (2, true) => {
            let word = get_gpr16(register::sized(src.into(), 2).unwrap()).unwrap();
            signed16(&mut rt.asm, word);
        }
        (4, true) => {
            let dword = get_gpr32(register::sized(src.into(), 4).unwrap()).unwrap();
            signed32(&mut rt.asm, dword);
        }
        (8, true) => {
            signed64(&mut rt.asm, src);
        }
        _ => unreachable!(),
    }
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
            Reference::Value(value) => Some(value),
            Reference::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    allocator.copy(rt, second, rcx);

    let dst = allocator.acquire(rt, &pinned, &[rcx]);
    allocator.copy(rt, first, dst);

    operation(rt, dst);

    allocator.replace(dst, Value::Output(0), true);
    allocator.consume(first);
    allocator.consume(second);
}

fn compile_effect(rt: &mut Runtime, allocator: &mut Allocator, effect: &Effect, width: VMWidth) {
    match effect {
        Effect::Add(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, first, second| {
                rt.asm.add(first, second).unwrap();
            })
        }
        Effect::Sub(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, first, second| {
                rt.asm.sub(first, second).unwrap();
            })
        }
        Effect::And(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, first, second| {
                rt.asm.and(first, second).unwrap();
            })
        }
        Effect::Or(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, first, second| {
                rt.asm.or(first, second).unwrap();
            })
        }
        Effect::Xor(first, second) => {
            compile_binary(rt, allocator, first, second, width, |rt, first, second| {
                rt.asm.xor(first, second).unwrap();
            })
        }
        Effect::Mul(first, second) => compile_mul(rt, allocator, first, second, width),
        Effect::Div(first, second, third) => {
            compile_div(rt, allocator, first, second, third, width)
        }
        Effect::Shr(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, dst| {
                rt.asm.shr(dst, cl).unwrap();
            })
        }
        Effect::Shl(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, dst| {
                rt.asm.shl(dst, cl).unwrap();
            })
        }
        Effect::Ror(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, dst| {
                rt.asm.ror(dst, cl).unwrap();
            })
        }
        Effect::Rol(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, dst| {
                rt.asm.rol(dst, cl).unwrap();
            })
        }
        Effect::Sar(first, second) => {
            compile_shift(rt, allocator, first, second, width, |rt, dst| {
                rt.asm.sar(dst, cl).unwrap();
            })
        }
        Effect::Assign(expression) => {
            let src = compile_expression(rt, allocator, expression, width);
            let dst = allocator.acquire(rt, &[], &[]);
            allocator.copy(rt, src, dst);

            allocator.replace(dst, Value::Output(0), true);
            allocator.consume(src);
        }
        Effect::Bsr(expression) => {
            compile_unary(rt, allocator, expression, width, |rt, dst, src| {
                rt.asm.bsr(dst, src).unwrap();
            })
        }
        Effect::Tzcnt(expression) => {
            compile_unary(rt, allocator, expression, width, |rt, dst, src| {
                rt.asm.tzcnt(dst, src).unwrap();
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

    allocator.dirty(Value::Output(0));
    allocator.consume(value);
}

fn compile_expression(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    expression: &Expression,
    width: VMWidth,
) -> Reference {
    match expression {
        Expression::Operand(Operand::Input(index)) => Reference::Value(Value::Input(*index)),
        Expression::Operand(Operand::Output(index)) => Reference::Value(Value::Output(*index)),
        Expression::Constant(value) => Reference::Immediate(*value as i64),
        Expression::SignBit => Reference::Immediate(width.mask().ilog2() as i64),
        Expression::Sub(first, second)
        | Expression::BitAnd(first, second)
        | Expression::BitOr(first, second)
        | Expression::BitXor(first, second) => {
            let first = compile_expression(rt, allocator, first, width);
            let second = compile_expression(rt, allocator, second, width);

            let pinned = [first, second]
                .into_iter()
                .filter_map(|value| match value {
                    Reference::Value(value) => Some(value),
                    Reference::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            let dst = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, first, dst);

            let src = allocator.acquire(rt, &pinned, &[dst]);
            allocator.copy(rt, second, src);

            match expression {
                Expression::Sub(_, _) => rt.asm.sub(dst, src).unwrap(),
                Expression::BitAnd(_, _) => rt.asm.and(dst, src).unwrap(),
                Expression::BitOr(_, _) => rt.asm.or(dst, src).unwrap(),
                Expression::BitXor(_, _) => rt.asm.xor(dst, src).unwrap(),
                _ => unreachable!(),
            }

            allocator.consume(first);
            allocator.consume(second);

            if src != dst {
                allocator.spill(rt, src);
            }

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::BitShr(first, second) | Expression::BitShl(first, second) => {
            let first = compile_expression(rt, allocator, first, width);
            let second = compile_expression(rt, allocator, second, width);

            let pinned = [first, second]
                .into_iter()
                .filter_map(|value| match value {
                    Reference::Value(value) => Some(value),
                    Reference::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            allocator.copy(rt, second, rcx);

            let dst = allocator.acquire(rt, &pinned, &[rcx]);
            allocator.copy(rt, first, dst);

            match expression {
                Expression::BitShr(_, _) => rt.asm.shr(dst, cl).unwrap(),
                Expression::BitShl(_, _) => rt.asm.shl(dst, cl).unwrap(),
                _ => unreachable!(),
            }

            allocator.consume(first);
            allocator.consume(second);

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::BitNot(inner) | Expression::LowByte(inner) => {
            let src = compile_expression(rt, allocator, inner, width);

            let dst = allocator.acquire(rt, &[], &[]);

            allocator.copy(rt, src, dst);

            match expression {
                Expression::BitNot(_) => rt.asm.not(dst).unwrap(),
                Expression::LowByte(_) => {
                    let byte = get_gpr8(register::sized(dst.into(), 1).unwrap()).unwrap();
                    rt.asm.movzx(dst, byte).unwrap();
                }
                _ => unreachable!(),
            }

            allocator.consume(src);

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
    }
}

fn compile_flags(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    flags: &[(Flag, Condition)],
    width: VMWidth,
) {
    rt.asm
        .mov(qword_ptr(rbp - allocator.offset(Value::Flags)), 0x0)
        .unwrap();

    for (flag, condition) in flags {
        match condition {
            Condition::Compare(item) => compile_comparison(rt, allocator, *flag, item, width),
            Condition::Parity(node) => compile_parity(rt, allocator, *flag, node, width),
        }
    }

    let register = allocator.acquire(rt, &[], &[]);

    rt.asm
        .mov(register, qword_ptr(rbp - allocator.offset(Value::Flags)))
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

    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, width);

    let pinned = [first, second]
        .into_iter()
        .filter_map(|value| match value {
            Reference::Value(value) => Some(value),
            Reference::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let dst = allocator.acquire(rt, &pinned, &[]);
    allocator.copy(rt, first, dst);

    let src = allocator.acquire(rt, &pinned, &[dst]);
    allocator.copy(rt, second, src);

    let tmp = allocator.acquire(rt, &pinned, &[dst, src]);
    let byte = get_gpr8(register::sized(tmp.into(), 1).unwrap()).unwrap();

    match condition {
        0 | 1 | 2 => rt.asm.cmp(dst, src).unwrap(),
        3 => rt.asm.bt(dst, src).unwrap(),
        _ => unreachable!(),
    }

    match condition {
        0 => rt.asm.sete(byte).unwrap(),
        1 => rt.asm.setb(byte).unwrap(),
        2 => rt.asm.seta(byte).unwrap(),
        3 => rt.asm.setc(byte).unwrap(),
        _ => unreachable!(),
    }

    rt.asm.movzx(tmp, byte).unwrap();
    rt.asm
        .shl(tmp, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm
        .or(qword_ptr(rbp - allocator.offset(Value::Flags)), tmp)
        .unwrap();

    allocator.spill(rt, tmp);
    allocator.consume(first);
    allocator.consume(second);
    allocator.spill(rt, dst);

    if src != dst {
        allocator.spill(rt, src);
    }
}

fn compile_parity(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    flag: Flag,
    node: &Expression,
    width: VMWidth,
) {
    let src = compile_expression(rt, allocator, node, width);
    let dst = allocator.acquire(rt, &[], &[]);

    allocator.copy(rt, src, dst);

    let byte = get_gpr8(register::sized(dst.into(), 1).unwrap()).unwrap();
    rt.asm.movzx(dst, byte).unwrap();
    rt.asm.popcnt(dst, dst).unwrap();
    rt.asm.not(dst).unwrap();
    rt.asm.and(dst, 0x1).unwrap();
    rt.asm
        .shl(dst, flag.bit32().trailing_zeros() as i32)
        .unwrap();
    rt.asm
        .or(qword_ptr(rbp - allocator.offset(Value::Flags)), dst)
        .unwrap();

    allocator.untrack(dst);
    allocator.consume(src);
}

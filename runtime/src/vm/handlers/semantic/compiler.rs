use iced_x86::code_asm::{
    ah, ax, byte_ptr, cl, dl, dword_ptr, dx, get_gpr16, get_gpr32, get_gpr8, ptr, qword_ptr, r12,
    r13, r14, r14d, rax, rbp, rbx, rcx, rdx, rsp, word_ptr, xmm0, xmm1, ymm0, ymm1, AsmRegister16,
    AsmRegister32, AsmRegister64, AsmRegister8, CodeAssembler, CodeLabel,
};
use rand::Rng;

use crate::{
    runtime::Runtime,
    utils::register_of_size,
    vm::{
        bytecode::{VMCode, VMReg, VMWidth},
        handlers::{
            self,
            semantic::{
                allocator::Allocator, Compare, Effect, Expression, Flags, Immediate, Operand,
                Operation, Reference, Register, Value, Vector,
            },
            vector,
        },
        utils::{bytecode, register, scratch},
    },
};

pub fn compile(rt: &mut Runtime, operation: &Operation) {
    let operation = obfuscate(operation);
    compile_scalar(rt, &operation);
    rt.asm.ret().unwrap();
}

pub fn compile_fragment(rt: &mut Runtime, operation: &Operation) {
    compile_scalar(rt, &obfuscate(operation));
}

pub fn compile_compound(rt: &mut Runtime, members: &[VMCode]) {
    for (index, member) in members.iter().enumerate() {
        if index > 0 {
            rt.asm.mov(rcx, rax).unwrap();
        }

        let operation = handlers::operation(rt, *member).unwrap();
        compile_fragment(rt, &operation);
    }
    rt.asm.ret().unwrap();
}

fn obfuscate(operation: &Operation) -> Operation {
    let mut rng = rand::thread_rng();

    let mut budget = rng.gen_range(1..4);

    Operation {
        effects: operation
            .effects
            .iter()
            .cloned()
            .map(|effect| effect.obfuscate(&mut rng, &mut budget))
            .collect(),
        flags: operation.flags.clone(),
        stores: operation.stores.clone(),
        widths: operation.widths,
    }
}

fn compile_scalar(rt: &mut Runtime, operation: &Operation) {
    let mut epilogue = rt.asm.create_label();
    let operands = operation.operands();
    let outputs = operation.outputs();
    let flags = !operation.flags.is_empty();
    let locals = operation.locals();
    let temporaries = operation.temporaries();
    let slots = operands + outputs + flags as usize + locals + temporaries;
    let size = ((slots as i32 * 8) + 15) & !15;
    let allocator = Allocator::new(operands, outputs, locals, flags);

    rt.asm.push(r13).unwrap();
    rt.asm.push(r14).unwrap();
    rt.asm.push(rbp).unwrap();
    rt.asm.mov(rbp, rsp).unwrap();
    rt.asm.sub(rsp, size).unwrap();

    rt.asm.mov(r13, rcx).unwrap();

    if !operation.widths.is_empty() {
        bytecode::read_byte_zx(rt, r13, r14d);
    }

    for index in (0..operands).rev() {
        scratch::load(rt, r12, rax);

        rt.asm
            .mov(qword_ptr(rbp - allocator.offset(Value::Input(index))), rax)
            .unwrap();
    }

    if operation.widths.is_empty() {
        let mut local = Allocator::new(operands, outputs, locals, flags);

        compile_effects(rt, &mut local, &operation.effects, VMWidth::Lower64);

        if flags {
            compile_flags(rt, &mut local, &operation.flags, VMWidth::Lower64);
        }

        local.dump(rt);
    } else {
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

                        if !rules.is_empty() {
                            compile_flags(rt, allocator, &rules, width);
                        }
                    }) as Box<dyn FnOnce(&mut Runtime, &mut Allocator)>,
                )
            })
            .collect::<Vec<(VMWidth, Box<dyn FnOnce(&mut Runtime, &mut Allocator)>)>>();

        let cases = handlers
            .iter()
            .map(|(width, _function)| (rt.mapper.index(*width) as u8, rt.asm.create_label()))
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

            let mut local = Allocator::new(operands, outputs, locals, flags);

            handler(rt, &mut local);

            local.dump(rt);

            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();

    match &operation.stores {
        Some(stores) => {
            let mut allocator = Allocator::new(operands, outputs, locals, flags);

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
            let mut allocator = Allocator::new(operands, outputs, locals, flags);

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
}

fn compile_vector(rt: &mut Runtime, operation: Vector) {
    match operation {
        Vector::And => vector::with_width(
            rt,
            |rt| rt.asm.pand(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpand(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::Or => vector::with_width(
            rt,
            |rt| rt.asm.por(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpor(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::Xor => vector::with_width(
            rt,
            |rt| rt.asm.pxor(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpxor(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::AndNot => vector::with_width(
            rt,
            |rt| rt.asm.pandn(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpandn(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::Div => vector::with_stride(
            rt,
            |rt| rt.asm.divps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.divpd(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vdivps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vdivpd(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::Mul => vector::with_extension(
            rt,
            |rt| rt.asm.mulpd(xmm0, xmm1).unwrap(),
            |rt| rt.asm.pmulld(xmm0, xmm1).unwrap(),
            |rt| rt.asm.mulps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.pmulhw(xmm0, xmm1).unwrap(),
            |rt| rt.asm.pmullw(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vmulpd(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpmulld(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vmulps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpmulhw(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpmullw(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::Add => vector::with_precision(
            rt,
            |rt| rt.asm.paddb(xmm0, xmm1).unwrap(),
            |rt| rt.asm.paddw(xmm0, xmm1).unwrap(),
            |rt| rt.asm.paddd(xmm0, xmm1).unwrap(),
            |rt| rt.asm.paddq(xmm0, xmm1).unwrap(),
            |rt| rt.asm.addps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.addps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.addps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.addpd(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpaddb(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpaddw(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpaddd(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpaddq(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vaddps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vaddps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vaddps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vaddpd(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::Sub => vector::with_precision(
            rt,
            |rt| rt.asm.psubb(xmm0, xmm1).unwrap(),
            |rt| rt.asm.psubw(xmm0, xmm1).unwrap(),
            |rt| rt.asm.psubd(xmm0, xmm1).unwrap(),
            |rt| rt.asm.psubq(xmm0, xmm1).unwrap(),
            |rt| rt.asm.subps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.subps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.subps(xmm0, xmm1).unwrap(),
            |rt| rt.asm.subpd(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpsubb(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpsubw(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpsubd(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vpsubq(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vsubps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vsubps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vsubps(ymm0, ymm0, ymm1).unwrap(),
            |rt| rt.asm.vsubpd(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::ByteEqual => vector::with_width(
            rt,
            |rt| rt.asm.pcmpeqb(xmm0, xmm1).unwrap(),
            |rt| rt.asm.vpcmpeqb(ymm0, ymm0, ymm1).unwrap(),
        ),
        Vector::ByteMask => vector::byte_mask(rt),
        Vector::LoadVector => vector::load_vector(rt),
        Vector::StoreMerge => vector::store_merge(rt),
        Vector::StoreExtend => vector::store_extend(rt),
        Vector::LoadMemory => vector::load_memory(rt),
        Vector::StoreMemory => vector::store_memory(rt),
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

fn mask(rt: &mut Runtime, register: AsmRegister64, width: VMWidth) {
    match width.size() {
        1 => {
            let byte = get_gpr8(register_of_size(register.into(), 1).unwrap()).unwrap();
            rt.asm.movzx(register, byte).unwrap();
        }
        2 => {
            let word = get_gpr16(register_of_size(register.into(), 2).unwrap()).unwrap();
            rt.asm.movzx(register, word).unwrap();
        }
        4 => {
            let dword = get_gpr32(register_of_size(register.into(), 4).unwrap()).unwrap();
            rt.asm.mov(dword, dword).unwrap();
        }
        8 => {}
        _ => unreachable!(),
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
    mask(rt, dst, width);

    let src = allocator.acquire(rt, &pinned, &[dst]);
    allocator.copy(rt, second, src);
    mask(rt, src, width);

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

    compile_operation(
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

    if width.size() == 1 {
        rt.asm.movzx(rdx, ax).unwrap();
        rt.asm.shr(rdx, 0x8).unwrap();
    }

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

    if width.size() == 1 {
        rt.asm.mov(ah, dl).unwrap();
    }

    compile_operation(
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

    if width.size() == 1 {
        rt.asm.movzx(dx, ah).unwrap();
    }

    allocator.replace(rax, Value::Output(0), true);
    allocator.replace(rdx, Value::Output(1), true);

    allocator.consume(first);
    allocator.consume(second);
    allocator.consume(third);
}

fn compile_exchange(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
) {
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, VMWidth::Lower64);

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

    match width.size() {
        1 => {
            let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();
            rt.asm.xchg(ptr(src), byte).unwrap();
        }
        2 => {
            let word = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
            rt.asm.xchg(ptr(src), word).unwrap();
        }
        4 => {
            let dword = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
            rt.asm.xchg(ptr(src), dword).unwrap();
        }
        8 => {
            rt.asm.xchg(ptr(src), dst).unwrap();
        }
        _ => unreachable!(),
    }

    allocator.replace(dst, Value::Output(0), true);

    allocator.consume(first);
    allocator.consume(second);
}

fn compile_exchange_add(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
) {
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, VMWidth::Lower64);

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

    match width.size() {
        1 => {
            let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();
            rt.asm.lock().xadd(ptr(src), byte).unwrap();
        }
        2 => {
            let word = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
            rt.asm.lock().xadd(ptr(src), word).unwrap();
        }
        4 => {
            let dword = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
            rt.asm.lock().xadd(ptr(src), dword).unwrap();
        }
        8 => {
            rt.asm.lock().xadd(ptr(src), dst).unwrap();
        }
        _ => unreachable!(),
    }

    allocator.copy(rt, first, src);

    rt.asm.add(src, dst).unwrap();

    allocator.replace(dst, Value::Output(1), true);
    allocator.replace(src, Value::Output(0), true);

    allocator.consume(first);
    allocator.consume(second);
}

fn compile_compare_exchange(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    third: &Expression,
    width: VMWidth,
) {
    let first = compile_expression(rt, allocator, first, width);
    let second = compile_expression(rt, allocator, second, width);
    let third = compile_expression(rt, allocator, third, VMWidth::Lower64);

    let pinned = [first, second, third]
        .into_iter()
        .filter_map(|value| match value {
            Reference::Value(value) => Some(value),
            Reference::Immediate(_) => None,
        })
        .collect::<Vec<Value>>();

    let src = allocator.acquire(rt, &pinned, &[rax]);
    allocator.copy(rt, second, src);

    let dst = allocator.acquire(rt, &pinned, &[rax, src]);
    allocator.copy(rt, third, dst);

    allocator.copy(rt, first, rax);

    match width.size() {
        1 => {
            let byte = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
            rt.asm.lock().cmpxchg(ptr(dst), byte).unwrap();
        }
        2 => {
            let word = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
            rt.asm.lock().cmpxchg(ptr(dst), word).unwrap();
        }
        4 => {
            let dword = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
            rt.asm.lock().cmpxchg(ptr(dst), dword).unwrap();
        }
        8 => {
            rt.asm.lock().cmpxchg(ptr(dst), src).unwrap();
        }
        _ => unreachable!(),
    }

    allocator.replace(rax, Value::Output(0), true);

    allocator.consume(first);
    allocator.consume(second);
    allocator.consume(third);
}

fn compile_operation<U8, U16, U32, U64, S8, S16, S32, S64>(
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
            let byte = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
            unsigned8(&mut rt.asm, byte);
        }
        (2, false) => {
            let word = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
            unsigned16(&mut rt.asm, word);
        }
        (4, false) => {
            let dword = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
            unsigned32(&mut rt.asm, dword);
        }
        (8, false) => {
            unsigned64(&mut rt.asm, src);
        }
        (1, true) => {
            let byte = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
            signed8(&mut rt.asm, byte);
        }
        (2, true) => {
            let word = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
            signed16(&mut rt.asm, word);
        }
        (4, true) => {
            let dword = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
            signed32(&mut rt.asm, dword);
        }
        (8, true) => {
            signed64(&mut rt.asm, src);
        }
        _ => unreachable!(),
    }
}

fn compile_shift<U8, U16, U32, U64, S8, S16, S32, S64>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    first: &Expression,
    second: &Expression,
    width: VMWidth,
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

    compile_operation(
        rt, width, dst, unsigned8, unsigned16, unsigned32, unsigned64, signed8, signed16, signed32,
        signed64,
    );

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
        Effect::Shr(first, second) => compile_shift(
            rt,
            allocator,
            first,
            second,
            width,
            |asm, byte| {
                asm.shr(byte, cl).unwrap();
            },
            |asm, word| {
                asm.shr(word, cl).unwrap();
            },
            |asm, dword| {
                asm.shr(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.shr(qword, cl).unwrap();
            },
            |asm, byte| {
                asm.shr(byte, cl).unwrap();
            },
            |asm, word| {
                asm.shr(word, cl).unwrap();
            },
            |asm, dword| {
                asm.shr(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.shr(qword, cl).unwrap();
            },
        ),
        Effect::Shl(first, second) => compile_shift(
            rt,
            allocator,
            first,
            second,
            width,
            |asm, byte| {
                asm.shl(byte, cl).unwrap();
            },
            |asm, word| {
                asm.shl(word, cl).unwrap();
            },
            |asm, dword| {
                asm.shl(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.shl(qword, cl).unwrap();
            },
            |asm, byte| {
                asm.shl(byte, cl).unwrap();
            },
            |asm, word| {
                asm.shl(word, cl).unwrap();
            },
            |asm, dword| {
                asm.shl(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.shl(qword, cl).unwrap();
            },
        ),
        Effect::Ror(first, second) => compile_shift(
            rt,
            allocator,
            first,
            second,
            width,
            |asm, byte| {
                asm.ror(byte, cl).unwrap();
            },
            |asm, word| {
                asm.ror(word, cl).unwrap();
            },
            |asm, dword| {
                asm.ror(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.ror(qword, cl).unwrap();
            },
            |asm, byte| {
                asm.ror(byte, cl).unwrap();
            },
            |asm, word| {
                asm.ror(word, cl).unwrap();
            },
            |asm, dword| {
                asm.ror(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.ror(qword, cl).unwrap();
            },
        ),
        Effect::Rol(first, second) => compile_shift(
            rt,
            allocator,
            first,
            second,
            width,
            |asm, byte| {
                asm.rol(byte, cl).unwrap();
            },
            |asm, word| {
                asm.rol(word, cl).unwrap();
            },
            |asm, dword| {
                asm.rol(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.rol(qword, cl).unwrap();
            },
            |asm, byte| {
                asm.rol(byte, cl).unwrap();
            },
            |asm, word| {
                asm.rol(word, cl).unwrap();
            },
            |asm, dword| {
                asm.rol(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.rol(qword, cl).unwrap();
            },
        ),
        Effect::Sar(first, second) => compile_shift(
            rt,
            allocator,
            first,
            second,
            width,
            |asm, byte| {
                asm.sar(byte, cl).unwrap();
            },
            |asm, word| {
                asm.sar(word, cl).unwrap();
            },
            |asm, dword| {
                asm.sar(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.sar(qword, cl).unwrap();
            },
            |asm, byte| {
                asm.sar(byte, cl).unwrap();
            },
            |asm, word| {
                asm.sar(word, cl).unwrap();
            },
            |asm, dword| {
                asm.sar(dword, cl).unwrap();
            },
            |asm, qword| {
                asm.sar(qword, cl).unwrap();
            },
        ),
        Effect::Push(expression) => {
            let src = compile_expression(rt, allocator, expression, width);
            let dst = allocator.acquire(rt, &[], &[]);
            allocator.copy(rt, src, dst);

            allocator.replace(dst, Value::Output(0), true);
            allocator.consume(src);
        }
        Effect::Bsr(expression) => compile_unary(
            rt,
            allocator,
            expression,
            width,
            |rt, dst, src| rt.asm.bsr(dst, src).unwrap(),
            |rt, dst, src| rt.asm.bsr(dst, src).unwrap(),
            |rt, dst, src| rt.asm.bsr(dst, src).unwrap(),
        ),
        Effect::Tzcnt(expression) => compile_unary(
            rt,
            allocator,
            expression,
            width,
            |rt, dst, src| rt.asm.tzcnt(dst, src).unwrap(),
            |rt, dst, src| rt.asm.tzcnt(dst, src).unwrap(),
            |rt, dst, src| rt.asm.tzcnt(dst, src).unwrap(),
        ),
        Effect::Exchange(first, second) => compile_exchange(rt, allocator, first, second, width),
        Effect::ExchangeAdd(first, second) => {
            compile_exchange_add(rt, allocator, first, second, width)
        }
        Effect::CompareExchange(first, second, third) => {
            compile_compare_exchange(rt, allocator, first, second, third, width)
        }
        Effect::Register(register, expression) => {
            let value = compile_expression(rt, allocator, expression, width);

            let pinned = match value {
                Reference::Value(value) => vec![value],
                Reference::Immediate(_) => vec![],
            };

            let index = allocator.acquire(rt, &pinned, &[]);
            let slot = get_gpr32(register_of_size(index.into(), 4).unwrap()).unwrap();

            match register {
                Register::Operand => bytecode::read_byte_zx(rt, r13, slot),
                Register::Fixed(register) => {
                    rt.asm.mov(slot, rt.mapper.index(*register) as i32).unwrap()
                }
            }

            let src = allocator.acquire(rt, &pinned, &[index]);
            allocator.copy(rt, value, src);

            match width {
                VMWidth::Lower64 | VMWidth::SLower64 => {
                    rt.asm.mov(ptr(r12 + index * 8), src).unwrap();
                }
                VMWidth::Lower32 => {
                    let source = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
                    rt.asm.mov(source, source).unwrap();
                    rt.asm.mov(ptr(r12 + index * 8), src).unwrap();
                }
                VMWidth::Lower16 => {
                    let source = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
                    rt.asm.mov(ptr(r12 + index * 8), source).unwrap();
                }
                VMWidth::Higher8 => {
                    let source = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
                    rt.asm.mov(ptr(r12 + index * 8 + 0x1), source).unwrap();
                }
                VMWidth::Lower8 => {
                    let source = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
                    rt.asm.mov(ptr(r12 + index * 8), source).unwrap();
                }
                _ => unreachable!(),
            }

            allocator.consume(value);
        }
        Effect::Memory(address, expression) => {
            let pointer = compile_expression(rt, allocator, address, VMWidth::Lower64);
            let value = compile_expression(rt, allocator, expression, width);

            let pinned = [pointer, value]
                .into_iter()
                .filter_map(|reference| match reference {
                    Reference::Value(value) => Some(value),
                    Reference::Immediate(_) => None,
                })
                .collect::<Vec<Value>>();

            let base = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, pointer, base);

            let src = allocator.acquire(rt, &pinned, &[base]);
            allocator.copy(rt, value, src);

            match width {
                VMWidth::Lower64 | VMWidth::SLower64 => {
                    rt.asm.mov(ptr(base), src).unwrap();
                }
                VMWidth::Lower32 => {
                    let source = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
                    rt.asm.mov(ptr(base), source).unwrap();
                }
                VMWidth::Lower16 => {
                    let source = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
                    rt.asm.mov(ptr(base), source).unwrap();
                }
                VMWidth::Higher8 | VMWidth::Lower8 => {
                    let source = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
                    rt.asm.mov(ptr(base), source).unwrap();
                }
                _ => unreachable!(),
            }

            allocator.consume(pointer);
            allocator.consume(value);
        }
        Effect::Assign(index, expression) => {
            let value = compile_expression(rt, allocator, expression, width);

            let pinned = match value {
                Reference::Value(value) => vec![value],
                Reference::Immediate(_) => vec![],
            };

            let dst = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, value, dst);
            allocator.consume(value);

            rt.asm
                .mov(qword_ptr(rbp - allocator.offset(Value::Local(*index))), dst)
                .unwrap();
        }
        Effect::Read(index, width) => {
            let dst = allocator.acquire(rt, &[], &[]);
            let register = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();

            match width.size() {
                1 => bytecode::read_byte_zx(rt, r13, register),
                2 => bytecode::read_word_zx(rt, r13, register),
                4 => bytecode::read_dword(rt, r13, register),
                8 => bytecode::read_qword(rt, r13, dst),
                _ => unreachable!(),
            }

            rt.asm
                .mov(qword_ptr(rbp - allocator.offset(Value::Local(*index))), dst)
                .unwrap();
        }
        Effect::Advance(expression) => {
            let value = compile_expression(rt, allocator, expression, width);

            let pinned = match value {
                Reference::Value(value) => vec![value],
                Reference::Immediate(_) => vec![],
            };

            let register = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, value, register);
            allocator.consume(value);

            rt.asm.add(r13, register).unwrap();
        }
        Effect::Drop(expression) => {
            let value = compile_expression(rt, allocator, expression, width);
            allocator.consume(value);
        }
        Effect::Loop(counter, body) => {
            let counter = Value::Local(*counter);
            let mut repeat = rt.asm.create_label();
            let mut done = rt.asm.create_label();

            rt.asm.set_label(&mut repeat).unwrap();
            rt.asm.zero_bytes().unwrap();

            let register = allocator.acquire(rt, &[], &[]);
            rt.asm
                .mov(register, qword_ptr(rbp - allocator.offset(counter)))
                .unwrap();
            rt.asm.test(register, register).unwrap();
            rt.asm.jz(done).unwrap();

            compile_effects(rt, allocator, body, width);

            let register = allocator.acquire(rt, &[], &[]);
            rt.asm
                .mov(register, qword_ptr(rbp - allocator.offset(counter)))
                .unwrap();
            rt.asm.sub(register, 1).unwrap();
            rt.asm
                .mov(qword_ptr(rbp - allocator.offset(counter)), register)
                .unwrap();
            rt.asm.jmp(repeat).unwrap();

            rt.asm.set_label(&mut done).unwrap();
            rt.asm.zero_bytes().unwrap();
        }
        Effect::Select(selector, arms) => {
            let value = compile_expression(rt, allocator, selector, width);
            let register = allocator.acquire(rt, &[], &[]);
            allocator.copy(rt, value, register);
            allocator.consume(value);

            let mut merge = rt.asm.create_label();
            let labels = arms
                .iter()
                .map(|_| rt.asm.create_label())
                .collect::<Vec<CodeLabel>>();

            let cases = arms
                .iter()
                .zip(&labels)
                .flat_map(|((keys, _), label)| keys.iter().map(move |key| (*key as u8, *label)))
                .collect::<Vec<(u8, CodeLabel)>>();

            rt.jumps(register, cases);

            for ((_, body), mut label) in arms.iter().zip(labels) {
                rt.asm.set_label(&mut label).unwrap();
                rt.asm.zero_bytes().unwrap();
                compile_effects(rt, allocator, body, width);
                rt.asm.jmp(merge).unwrap();
            }

            rt.asm.set_label(&mut merge).unwrap();
            rt.asm.zero_bytes().unwrap();
        }
        Effect::When(condition, body) => {
            let value = compile_expression(rt, allocator, condition, width);
            let register = allocator.acquire(rt, &[], &[]);
            allocator.copy(rt, value, register);
            allocator.consume(value);
            rt.asm.test(register, register).unwrap();

            let mut skip = rt.asm.create_label();
            rt.asm.jz(skip).unwrap();

            compile_effects(rt, allocator, body, width);

            rt.asm.set_label(&mut skip).unwrap();
            rt.asm.zero_bytes().unwrap();
        }
        Effect::Cpuid => {
            rt.asm.push(rbx).unwrap();

            scratch::load(rt, r12, rcx);
            scratch::load(rt, r12, rax);
            rt.asm.cpuid().unwrap();
            scratch::store(rt, r12, rax);
            scratch::store(rt, r12, rbx);
            scratch::store(rt, r12, rcx);
            scratch::store(rt, r12, rdx);

            rt.asm.pop(rbx).unwrap();
        }
        Effect::Timestamp => {
            rt.asm.rdtsc().unwrap();
            scratch::store(rt, r12, rax);
            scratch::store(rt, r12, rdx);
        }
        Effect::Vector(vector) => {
            compile_vector(rt, *vector);
            rt.asm.zero_bytes().unwrap();
        }
    }
}

fn compile_unary<U16, U32, U64>(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    expression: &Expression,
    width: VMWidth,
    unsigned16: U16,
    unsigned32: U32,
    unsigned64: U64,
) where
    U16: FnOnce(&mut Runtime, AsmRegister16, AsmRegister16),
    U32: FnOnce(&mut Runtime, AsmRegister32, AsmRegister32),
    U64: FnOnce(&mut Runtime, AsmRegister64, AsmRegister64),
{
    let value = compile_expression(rt, allocator, expression, width);
    let src = allocator.acquire(rt, &[], &[]);

    allocator.copy(rt, value, src);

    let mask = allocator.acquire(rt, &[], &[src]);

    rt.asm.mov(mask, width.mask() as i64).unwrap();
    rt.asm.and(src, mask).unwrap();

    allocator.spill(rt, mask);

    let dst = allocator.mutable(rt, Value::Output(0), &[src]);

    match width.size() {
        2 => {
            let dst = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
            let src = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
            unsigned16(rt, dst, src);
        }
        4 => {
            let dst = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
            let src = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
            unsigned32(rt, dst, src);
        }
        8 => {
            unsigned64(rt, dst, src);
        }
        _ => unreachable!(),
    }

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
        Expression::Register(register) => {
            let index = allocator.acquire(rt, &[], &[]);
            let slot = get_gpr32(register_of_size(index.into(), 4).unwrap()).unwrap();

            match register {
                Register::Operand => bytecode::read_byte_zx(rt, r13, slot),
                Register::Fixed(register) => {
                    rt.asm.mov(slot, rt.mapper.index(*register) as i32).unwrap()
                }
            }

            let dst = allocator.acquire(rt, &[], &[index]);

            match width {
                VMWidth::Lower64 | VMWidth::SLower64 => {
                    rt.asm.mov(dst, ptr(r12 + index * 8)).unwrap();
                }
                VMWidth::Lower32 => {
                    let destination = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                    rt.asm.mov(destination, ptr(r12 + index * 8)).unwrap();
                }
                VMWidth::Lower16 => {
                    rt.asm.movzx(dst, word_ptr(r12 + index * 8)).unwrap();
                }
                VMWidth::Higher8 => {
                    rt.asm.movzx(dst, byte_ptr(r12 + index * 8 + 0x1)).unwrap();
                }
                VMWidth::Lower8 => {
                    rt.asm.movzx(dst, byte_ptr(r12 + index * 8)).unwrap();
                }
                VMWidth::SLower32 => {
                    rt.asm.movsxd(dst, dword_ptr(r12 + index * 8)).unwrap();
                }
                VMWidth::SLower16 => {
                    rt.asm.movsx(dst, word_ptr(r12 + index * 8)).unwrap();
                }
                VMWidth::SLower8 => {
                    rt.asm.movsx(dst, byte_ptr(r12 + index * 8)).unwrap();
                }
                _ => unreachable!(),
            }

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::Extend(inner, extend) => {
            let src = compile_expression(rt, allocator, inner, *extend);
            let dst = allocator.acquire(rt, &[], &[]);
            allocator.copy(rt, src, dst);
            allocator.consume(src);

            let dword = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
            let word = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
            let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();

            match (extend.size(), *extend == extend.signed()) {
                (8, _) => {}
                (4, false) => rt.asm.mov(dword, dword).unwrap(),
                (4, true) => rt.asm.movsxd(dst, dword).unwrap(),
                (2, false) => rt.asm.movzx(dst, word).unwrap(),
                (2, true) => rt.asm.movsx(dst, word).unwrap(),
                (1, false) => rt.asm.movzx(dst, byte).unwrap(),
                (1, true) => rt.asm.movsx(dst, byte).unwrap(),
                _ => unreachable!(),
            }

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::Memory(address) => {
            let pointer = compile_expression(rt, allocator, address, VMWidth::Lower64);

            let pinned = match pointer {
                Reference::Value(value) => vec![value],
                Reference::Immediate(_) => vec![],
            };

            let base = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, pointer, base);

            let dst = allocator.acquire(rt, &[], &[base]);

            match width {
                VMWidth::Lower64 | VMWidth::SLower64 => {
                    rt.asm.mov(dst, ptr(base)).unwrap();
                }
                VMWidth::Lower32 => {
                    let destination = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                    rt.asm.mov(destination, ptr(base)).unwrap();
                }
                VMWidth::Lower16 => {
                    rt.asm.movzx(dst, word_ptr(base)).unwrap();
                }
                VMWidth::Higher8 | VMWidth::Lower8 => {
                    rt.asm.movzx(dst, byte_ptr(base)).unwrap();
                }
                VMWidth::SLower32 => {
                    rt.asm.movsxd(dst, dword_ptr(base)).unwrap();
                }
                VMWidth::SLower16 => {
                    rt.asm.movsx(dst, word_ptr(base)).unwrap();
                }
                VMWidth::SLower8 => {
                    rt.asm.movsx(dst, byte_ptr(base)).unwrap();
                }
                _ => unreachable!(),
            }

            allocator.consume(pointer);

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::Immediate(Immediate::Fixed(value)) => Reference::Immediate(*value as i64),
        Expression::Local(index) => {
            let dst = allocator.acquire(rt, &[], &[]);

            rt.asm
                .mov(dst, qword_ptr(rbp - allocator.offset(Value::Local(*index))))
                .unwrap();

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::Flag(flag) => {
            let dst = allocator.acquire(rt, &[], &[]);

            register::load(rt, r12, dst, VMReg::Flags);

            let bit = flag.bit32().trailing_zeros() as i32;

            if bit > 0 {
                rt.asm.shr(dst, bit).unwrap();
            }

            rt.asm.and(dst, 0x1).unwrap();

            let tmp = allocator.temporary();

            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::Compare(compare) => compile_compare(rt, allocator, compare, width),
        Expression::Parity(node) => compile_parity(rt, allocator, node, width),
        Expression::Segment => {
            let dst = allocator.acquire(rt, &[], &[]);

            rt.asm.mov(dst, qword_ptr(0x30).gs()).unwrap();

            let tmp = allocator.temporary();
            allocator.replace(dst, tmp, true);

            Reference::Value(tmp)
        }
        Expression::SignBit => Reference::Immediate(width.mask().ilog2() as i64),
        Expression::BitSize => Reference::Immediate((width.size() * 8) as i64),
        Expression::ByteMask(n) => {
            Reference::Immediate(((0xFF as u64) << ((width.size() - 1 - n) * 8)) as i64)
        }
        Expression::Add(first, second)
        | Expression::Sub(first, second)
        | Expression::Mul(first, second)
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
            mask(rt, dst, width);

            let src = allocator.acquire(rt, &pinned, &[dst]);
            allocator.copy(rt, second, src);
            mask(rt, src, width);

            match expression {
                Expression::Add(_, _) => rt.asm.add(dst, src).unwrap(),
                Expression::Sub(_, _) => rt.asm.sub(dst, src).unwrap(),
                Expression::Mul(_, _) => rt.asm.imul_2(dst, src).unwrap(),
                Expression::BitAnd(_, _) => rt.asm.and(dst, src).unwrap(),
                Expression::BitOr(_, _) => rt.asm.or(dst, src).unwrap(),
                Expression::BitXor(_, _) => rt.asm.xor(dst, src).unwrap(),
                _ => unreachable!(),
            }

            mask(rt, dst, width);

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
            mask(rt, dst, width);

            match expression {
                Expression::BitShr(_, _) => rt.asm.shr(dst, cl).unwrap(),
                Expression::BitShl(_, _) => rt.asm.shl(dst, cl).unwrap(),
                _ => unreachable!(),
            }

            mask(rt, dst, width);

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
                    let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();
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

fn compile_flags(rt: &mut Runtime, allocator: &mut Allocator, flags: &Flags, width: VMWidth) {
    let register = allocator.acquire(rt, &[], &[]);

    register::load(rt, r12, register, VMReg::Flags);

    rt.asm
        .mov(qword_ptr(rbp - allocator.offset(Value::Flags)), register)
        .unwrap();

    allocator.untrack(register);

    for (flag, expression) in flags.values() {
        let value = compile_expression(rt, allocator, expression, width);

        let pinned = match value {
            Reference::Value(value) => vec![value],
            Reference::Immediate(_) => vec![],
        };

        let dst = allocator.acquire(rt, &pinned, &[]);
        allocator.copy(rt, value, dst);
        allocator.consume(value);

        let bit = flag.bit32().trailing_zeros() as i32;
        let mask = flag.bit32();

        rt.asm
            .and(dword_ptr(rbp - allocator.offset(Value::Flags)), !mask)
            .unwrap();
        rt.asm.shl(dst, bit).unwrap();
        rt.asm
            .or(dword_ptr(rbp - allocator.offset(Value::Flags)), dst)
            .unwrap();

        allocator.spill(rt, dst);
    }

    match flags.condition() {
        None => {
            let register = allocator.acquire(rt, &[], &[]);

            rt.asm
                .mov(register, qword_ptr(rbp - allocator.offset(Value::Flags)))
                .unwrap();

            register::store(rt, r12, VMReg::Flags, register);

            allocator.untrack(register);
        }
        Some(condition) => {
            let condition = compile_expression(rt, allocator, condition, width);

            let pinned = match condition {
                Reference::Value(value) => vec![value],
                Reference::Immediate(_) => vec![],
            };

            let selector = allocator.acquire(rt, &pinned, &[]);
            allocator.copy(rt, condition, selector);
            allocator.consume(condition);

            let register = allocator.acquire(rt, &[], &[selector]);

            rt.asm
                .mov(register, qword_ptr(rbp - allocator.offset(Value::Flags)))
                .unwrap();

            let target = allocator.acquire(rt, &[], &[selector, register]);
            rt.asm
                .lea(target, ptr(r12 + rt.mapper.index(VMReg::Flags) as i32 * 8))
                .unwrap();

            let skip = allocator.acquire(rt, &[], &[selector, register, target]);
            rt.asm
                .lea(skip, ptr(rbp - allocator.offset(Value::Flags)))
                .unwrap();

            rt.asm.test(selector, selector).unwrap();
            rt.asm.cmovz(target, skip).unwrap();
            rt.asm.mov(ptr(target), register).unwrap();
        }
    }
}

fn compile_compare(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    compare: &Compare,
    width: VMWidth,
) -> Reference {
    let (first, second) = match compare {
        Compare::Equal(first, second)
        | Compare::LessThan(first, second)
        | Compare::GreaterThan(first, second)
        | Compare::BitSet(first, second) => (first, second),
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
    mask(rt, dst, width);

    let src = allocator.acquire(rt, &pinned, &[dst]);
    allocator.copy(rt, second, src);
    mask(rt, src, width);

    let tmp = allocator.acquire(rt, &pinned, &[dst, src]);

    let byte = get_gpr8(register_of_size(tmp.into(), 1).unwrap()).unwrap();

    match compare {
        Compare::Equal(_, _) => {
            rt.asm.cmp(dst, src).unwrap();
            rt.asm.sete(byte).unwrap();
        }
        Compare::LessThan(_, _) => {
            rt.asm.cmp(dst, src).unwrap();
            rt.asm.setb(byte).unwrap();
        }
        Compare::GreaterThan(_, _) => {
            rt.asm.cmp(dst, src).unwrap();
            rt.asm.seta(byte).unwrap();
        }
        Compare::BitSet(_, _) => {
            rt.asm.bt(dst, src).unwrap();
            rt.asm.setc(byte).unwrap();
        }
    }

    rt.asm.movzx(tmp, byte).unwrap();

    allocator.consume(first);
    allocator.consume(second);
    allocator.spill(rt, dst);

    if src != dst {
        allocator.spill(rt, src);
    }

    let value = allocator.temporary();
    allocator.replace(tmp, value, true);

    Reference::Value(value)
}

fn compile_parity(
    rt: &mut Runtime,
    allocator: &mut Allocator,
    node: &Expression,
    width: VMWidth,
) -> Reference {
    let src = compile_expression(rt, allocator, node, width);
    let dst = allocator.acquire(rt, &[], &[]);

    allocator.copy(rt, src, dst);

    let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();
    rt.asm.movzx(dst, byte).unwrap();
    rt.asm.popcnt(dst, dst).unwrap();
    rt.asm.not(dst).unwrap();
    rt.asm.and(dst, 0x1).unwrap();

    allocator.consume(src);

    let value = allocator.temporary();
    allocator.replace(dst, value, true);

    Reference::Value(value)
}

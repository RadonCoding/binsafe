use iced_x86::code_asm::{
    ah, ax, byte_ptr, cl, dl, dword_ptr, dx, eax, get_gpr16, get_gpr32, get_gpr8, ptr, qword_ptr,
    r12, r13, r14, r14d, r8, r8d, r9, r9b, r9d, r9w, rax, rbp, rbx, rcx, rdx, rsp, word_ptr, xmm0,
    ymm0, AsmRegister64, CodeLabel,
};
use std::collections::HashSet;

use crate::{
    runtime::Runtime,
    utils::register_of_size,
    vm::{
        bytecode::{VMCode, VMPrecision, VMReg, VMWidth},
        handlers::{
            self,
            semantic::{
                allocator::{xmm, Allocator},
                obfuscation, Binary, Compare, Flags, Node, Operation, Reference, Register, Shift,
                Slot, Statement, Unary, Value, Vector,
            },
        },
        utils::{bytecode, register, scratch},
    },
};

macro_rules! sized {
    ($rt:expr, $width:expr, $src:expr, $unsigned:ident, $signed:ident) => {{
        let src = $src;
        match ($width.size(), $width == $width.signed()) {
            (1, false) => {
                let r = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
                $rt.asm.$unsigned(r).unwrap();
            }
            (2, false) => {
                let r = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
                $rt.asm.$unsigned(r).unwrap();
            }
            (4, false) => {
                let r = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
                $rt.asm.$unsigned(r).unwrap();
            }
            (8, false) => $rt.asm.$unsigned(src).unwrap(),
            (1, true) => {
                let r = get_gpr8(register_of_size(src.into(), 1).unwrap()).unwrap();
                $rt.asm.$signed(r).unwrap();
            }
            (2, true) => {
                let r = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
                $rt.asm.$signed(r).unwrap();
            }
            (4, true) => {
                let r = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
                $rt.asm.$signed(r).unwrap();
            }
            (8, true) => $rt.asm.$signed(src).unwrap(),
            _ => unreachable!(),
        }
    }};
}

macro_rules! shift {
    ($rt:expr, $width:expr, $dst:expr, $op:ident) => {
        match $width.size() {
            1 => {
                let r = get_gpr8(register_of_size($dst.into(), 1).unwrap()).unwrap();
                $rt.asm.$op(r, cl).unwrap();
            }
            2 => {
                let r = get_gpr16(register_of_size($dst.into(), 2).unwrap()).unwrap();
                $rt.asm.$op(r, cl).unwrap();
            }
            4 => {
                let r = get_gpr32(register_of_size($dst.into(), 4).unwrap()).unwrap();
                $rt.asm.$op(r, cl).unwrap();
            }
            8 => $rt.asm.$op($dst, cl).unwrap(),
            _ => unreachable!(),
        }
    };
}

fn pinned(references: &[Reference]) -> Vec<Slot> {
    references
        .iter()
        .filter_map(|reference| match reference {
            Reference::Value(value) => Some(*value),
            Reference::Immediate(_) => None,
        })
        .collect()
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

fn node_slot(nodes: &[Node], value: Value) -> usize {
    let mut slot = 0;
    for node in &nodes[..value.node] {
        if node.results() > 1 {
            slot += node.results();
        }
    }
    slot + value.output
}

fn compile_precision(
    rt: &mut Runtime,
    integer_64: impl FnOnce(&mut Runtime) + 'static,
    float_64: impl FnOnce(&mut Runtime) + 'static,
    integer_32: impl FnOnce(&mut Runtime) + 'static,
    float_32: impl FnOnce(&mut Runtime) + 'static,
    integer_16: impl FnOnce(&mut Runtime) + 'static,
    float_16: impl FnOnce(&mut Runtime) + 'static,
    integer_8: impl FnOnce(&mut Runtime) + 'static,
    float_8: impl FnOnce(&mut Runtime) + 'static,
) {
    bytecode::read_byte_zx(rt, r13, r8d);
    bytecode::read_byte_zx(rt, r13, r9d);

    let mut epilogue = rt.asm.create_label();

    let lower64 = rt.mapper.index(VMWidth::Lower64) as u8;
    let lower32 = rt.mapper.index(VMWidth::Lower32) as u8;
    let lower16 = rt.mapper.index(VMWidth::Lower16) as u8;
    let lower8 = rt.mapper.index(VMWidth::Lower8) as u8;
    let integer = rt.mapper.index(VMPrecision::Integer) as u8;
    let float = rt.mapper.index(VMPrecision::Float) as u8;

    rt.switch(
        r8,
        epilogue,
        vec![
            (
                vec![lower64],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![
                            (vec![integer], Box::new(integer_64)),
                            (vec![float], Box::new(float_64)),
                        ],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
            (
                vec![lower32],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![
                            (vec![integer], Box::new(integer_32)),
                            (vec![float], Box::new(float_32)),
                        ],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
            (
                vec![lower16],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![
                            (vec![integer], Box::new(integer_16)),
                            (vec![float], Box::new(float_16)),
                        ],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
            (
                vec![lower8],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![
                            (vec![integer], Box::new(integer_8)),
                            (vec![float], Box::new(float_8)),
                        ],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
        ],
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

fn compile_extension(
    rt: &mut Runtime,
    float_64: impl FnOnce(&mut Runtime) + 'static,
    integer_32: impl FnOnce(&mut Runtime) + 'static,
    float_32: impl FnOnce(&mut Runtime) + 'static,
    integer_high_16: impl FnOnce(&mut Runtime) + 'static,
    integer_low_16: impl FnOnce(&mut Runtime) + 'static,
) {
    bytecode::read_byte_zx(rt, r13, r8d);
    bytecode::read_byte_zx(rt, r13, r9d);

    let mut epilogue = rt.asm.create_label();

    let lower64 = rt.mapper.index(VMWidth::Lower64) as u8;
    let lower32 = rt.mapper.index(VMWidth::Lower32) as u8;
    let higher16 = rt.mapper.index(VMWidth::Higher16) as u8;
    let lower16 = rt.mapper.index(VMWidth::Lower16) as u8;
    let integer = rt.mapper.index(VMPrecision::Integer) as u8;
    let float = rt.mapper.index(VMPrecision::Float) as u8;

    rt.switch(
        r8,
        epilogue,
        vec![
            (
                vec![lower64],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(r9, epilogue, vec![(vec![float], Box::new(float_64))]);
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
            (
                vec![lower32],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![
                            (vec![integer], Box::new(integer_32)),
                            (vec![float], Box::new(float_32)),
                        ],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
            (
                vec![higher16],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![(vec![integer], Box::new(integer_high_16))],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
            (
                vec![lower16],
                Box::new(move |rt| {
                    let mut epilogue = rt.asm.create_label();
                    rt.switch(
                        r9,
                        epilogue,
                        vec![(vec![integer], Box::new(integer_low_16))],
                    );
                    rt.asm.set_label(&mut epilogue).unwrap();
                }),
            ),
        ],
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

fn compile_stride(
    rt: &mut Runtime,
    stride_64: impl FnOnce(&mut Runtime) + 'static,
    stride_32: impl FnOnce(&mut Runtime) + 'static,
) {
    bytecode::read_byte_zx(rt, r13, r8d);

    let mut epilogue = rt.asm.create_label();

    let lower64 = rt.mapper.index(VMWidth::Lower64) as u8;
    let lower32 = rt.mapper.index(VMWidth::Lower32) as u8;

    rt.switch(
        r8,
        epilogue,
        vec![
            (vec![lower64], Box::new(stride_64)),
            (vec![lower32], Box::new(stride_32)),
        ],
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

struct Lowering<'a> {
    nodes: &'a [Node],
    allocator: Allocator,
    compiled: HashSet<usize>,
}

impl Lowering<'_> {
    fn store_node(&self, rt: &mut Runtime, slot: usize, register: AsmRegister64) {
        rt.asm
            .mov(
                qword_ptr(rbp - self.allocator.offset(Slot::Node(slot))),
                register,
            )
            .unwrap();
    }

    fn store_local(&self, rt: &mut Runtime, local: usize, register: AsmRegister64) {
        rt.asm
            .mov(
                qword_ptr(rbp - self.allocator.offset(Slot::Local(local))),
                register,
            )
            .unwrap();
    }

    fn operand(&self, value: Value) -> Slot {
        match self.nodes[value.node] {
            Node::Input(index) => Slot::Input(index),
            Node::Local(index) => Slot::Local(index),
            _ => unreachable!(),
        }
    }

    fn compile_node(&mut self, rt: &mut Runtime, value: Value, width: VMWidth) -> Reference {
        let nodes = self.nodes;

        match &nodes[value.node] {
            &Node::Input(index) => Reference::Value(Slot::Input(index)),
            &Node::Immediate(value) => Reference::Immediate(value as i64),
            &Node::Register(register) => {
                let index = self.allocator.acquire(rt, &[], &[]);
                let slot = get_gpr32(register_of_size(index.into(), 4).unwrap()).unwrap();

                match register {
                    Register::Operand => bytecode::read_byte_zx(rt, r13, slot),
                    Register::Fixed(register) => {
                        rt.asm.mov(slot, rt.mapper.index(register) as i32).unwrap()
                    }
                }

                let dst = self.allocator.acquire(rt, &[], &[index]);

                match width {
                    VMWidth::Lower64 | VMWidth::SLower64 => {
                        rt.asm.mov(dst, ptr(r12 + index * 8)).unwrap();
                    }
                    VMWidth::Lower32 => {
                        let destination =
                            get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
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

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Local(index) => {
                let slot = self.allocator.offset(Slot::Local(index));
                let dst = self.allocator.acquire(rt, &[], &[]);

                rt.asm.mov(dst, qword_ptr(rbp - slot)).unwrap();

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Flag(flag) => {
                let dst = self.allocator.acquire(rt, &[], &[]);

                register::load(rt, r12, dst, VMReg::Flags);

                let bit = flag.bit32().trailing_zeros() as i32;

                if bit > 0 {
                    rt.asm.shr(dst, bit).unwrap();
                }

                rt.asm.and(dst, 0x1).unwrap();

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Segment => {
                let dst = self.allocator.acquire(rt, &[], &[]);

                rt.asm.mov(dst, qword_ptr(0x30).gs()).unwrap();

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::SignBit => Reference::Immediate(width.mask().ilog2() as i64),
            &Node::BitSize => Reference::Immediate((width.size() * 8) as i64),
            &Node::ByteMask(n) => {
                Reference::Immediate(((0xFF as u64) << ((width.size() - 1 - n) * 8)) as i64)
            }
            &Node::Memory(address) => {
                let pointer = self.compile_node(rt, address, VMWidth::Lower64);

                let pinned = pinned(&[pointer]);

                let base = self.allocator.acquire(rt, &pinned, &[]);
                self.allocator.copy_register(rt, pointer, base);

                let dst = self.allocator.acquire(rt, &[], &[base]);

                match width {
                    VMWidth::Lower64 | VMWidth::SLower64 => {
                        rt.asm.mov(dst, ptr(base)).unwrap();
                    }
                    VMWidth::Lower32 => {
                        let destination =
                            get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
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

                self.allocator.consume(pointer);

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Unary(operator, inner) => match operator {
                Unary::Not => {
                    let src = self.compile_node(rt, inner, width);
                    let dst = self.allocator.acquire(rt, &[], &[]);
                    self.allocator.copy_register(rt, src, dst);
                    rt.asm.not(dst).unwrap();
                    self.allocator.consume(src);

                    let tmp = self.allocator.temporary();
                    self.allocator.replace_register(dst, tmp, true);
                    Reference::Value(tmp)
                }
                Unary::LowByte => {
                    let src = self.compile_node(rt, inner, width);
                    let dst = self.allocator.acquire(rt, &[], &[]);
                    self.allocator.copy_register(rt, src, dst);
                    let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();
                    rt.asm.movzx(dst, byte).unwrap();
                    self.allocator.consume(src);

                    let tmp = self.allocator.temporary();
                    self.allocator.replace_register(dst, tmp, true);
                    Reference::Value(tmp)
                }
                Unary::Parity => {
                    let src = self.compile_node(rt, inner, width);
                    let dst = self.allocator.acquire(rt, &[], &[]);
                    self.allocator.copy_register(rt, src, dst);

                    let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();
                    rt.asm.movzx(dst, byte).unwrap();
                    rt.asm.popcnt(dst, dst).unwrap();
                    rt.asm.not(dst).unwrap();
                    rt.asm.and(dst, 0x1).unwrap();
                    self.allocator.consume(src);

                    let tmp = self.allocator.temporary();
                    self.allocator.replace_register(dst, tmp, true);
                    Reference::Value(tmp)
                }
                Unary::Tzcnt => {
                    let value = self.compile_node(rt, inner, width);
                    let src = self.allocator.acquire(rt, &[], &[]);
                    self.allocator.copy_register(rt, value, src);
                    self.allocator.consume(value);

                    let mask = self.allocator.acquire(rt, &[], &[src]);
                    rt.asm.mov(mask, width.mask() as i64).unwrap();
                    rt.asm.and(src, mask).unwrap();
                    self.allocator.spill(rt, mask);

                    let dst = self.allocator.acquire(rt, &[], &[src]);

                    match width.size() {
                        2 => {
                            let d = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
                            let s = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
                            rt.asm.tzcnt(d, s).unwrap();
                        }
                        4 => {
                            let d = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                            let s = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
                            rt.asm.tzcnt(d, s).unwrap();
                        }
                        8 => rt.asm.tzcnt(dst, src).unwrap(),
                        _ => unreachable!(),
                    }

                    let tmp = self.allocator.temporary();
                    self.allocator.replace_register(dst, tmp, true);
                    Reference::Value(tmp)
                }
            },
            &Node::Binary(operator, first, second) => {
                let first = self.compile_node(rt, first, width);
                let second = self.compile_node(rt, second, width);

                let pinned = pinned(&[first, second]);

                let dst = self.allocator.acquire(rt, &pinned, &[]);
                self.allocator.copy_register(rt, first, dst);
                mask(rt, dst, width);

                let src = self.allocator.acquire(rt, &pinned, &[dst]);
                self.allocator.copy_register(rt, second, src);
                mask(rt, src, width);

                match operator {
                    Binary::Add => rt.asm.add(dst, src).unwrap(),
                    Binary::Sub => rt.asm.sub(dst, src).unwrap(),
                    Binary::Mul => rt.asm.imul_2(dst, src).unwrap(),
                    Binary::And => rt.asm.and(dst, src).unwrap(),
                    Binary::Or => rt.asm.or(dst, src).unwrap(),
                    Binary::Xor => rt.asm.xor(dst, src).unwrap(),
                }

                mask(rt, dst, width);

                self.allocator.consume(first);
                self.allocator.consume(second);

                if src != dst {
                    self.allocator.spill(rt, src);
                }

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Shift(operator, first, second) => {
                let first = self.compile_node(rt, first, width);
                let second = self.compile_node(rt, second, width);

                let pinned = pinned(&[first, second]);

                self.allocator.copy_register(rt, second, rcx);

                let dst = self.allocator.acquire(rt, &pinned, &[rcx]);
                self.allocator.copy_register(rt, first, dst);
                mask(rt, dst, width);

                match operator {
                    Shift::Shl => shift!(rt, width, dst, shl),
                    Shift::Shr => shift!(rt, width, dst, shr),
                    Shift::Sar => shift!(rt, width, dst, sar),
                    Shift::Rol => shift!(rt, width, dst, rol),
                    Shift::Ror => shift!(rt, width, dst, ror),
                }

                mask(rt, dst, width);

                self.allocator.consume(first);
                self.allocator.consume(second);

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Compare(operator, first, second) => {
                let first = self.compile_node(rt, first, width);
                let second = self.compile_node(rt, second, width);

                let pinned = pinned(&[first, second]);

                let dst = self.allocator.acquire(rt, &pinned, &[]);
                self.allocator.copy_register(rt, first, dst);
                mask(rt, dst, width);

                let src = self.allocator.acquire(rt, &pinned, &[dst]);
                self.allocator.copy_register(rt, second, src);
                mask(rt, src, width);

                let tmp = self.allocator.acquire(rt, &pinned, &[dst, src]);

                let byte = get_gpr8(register_of_size(tmp.into(), 1).unwrap()).unwrap();

                match operator {
                    Compare::Equal => {
                        rt.asm.cmp(dst, src).unwrap();
                        rt.asm.sete(byte).unwrap();
                    }
                    Compare::LessThan => {
                        rt.asm.cmp(dst, src).unwrap();
                        rt.asm.setb(byte).unwrap();
                    }
                    Compare::GreaterThan => {
                        rt.asm.cmp(dst, src).unwrap();
                        rt.asm.seta(byte).unwrap();
                    }
                    Compare::BitSet => {
                        rt.asm.bt(dst, src).unwrap();
                        rt.asm.setc(byte).unwrap();
                    }
                }

                rt.asm.movzx(tmp, byte).unwrap();

                self.allocator.consume(first);
                self.allocator.consume(second);
                self.allocator.spill(rt, dst);

                if src != dst {
                    self.allocator.spill(rt, src);
                }

                let value = self.allocator.temporary();
                self.allocator.replace_register(tmp, value, true);

                Reference::Value(value)
            }
            &Node::Bsr(destination, source) => {
                let destination = self.compile_node(rt, destination, width);
                let source = self.compile_node(rt, source, width);

                let pinned = pinned(&[destination, source]);

                let dst = self.allocator.acquire(rt, &pinned, &[]);
                self.allocator.copy_register(rt, destination, dst);

                let src = self.allocator.acquire(rt, &pinned, &[dst]);
                self.allocator.copy_register(rt, source, src);

                let mask = self.allocator.acquire(rt, &pinned, &[dst, src]);
                rt.asm.mov(mask, width.mask() as i64).unwrap();
                rt.asm.and(src, mask).unwrap();
                self.allocator.spill(rt, mask);

                match width.size() {
                    2 => {
                        let d = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
                        let s = get_gpr16(register_of_size(src.into(), 2).unwrap()).unwrap();
                        rt.asm.bsr(d, s).unwrap();
                    }
                    4 => {
                        let d = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                        let s = get_gpr32(register_of_size(src.into(), 4).unwrap()).unwrap();
                        rt.asm.bsr(d, s).unwrap();
                    }
                    8 => rt.asm.bsr(dst, src).unwrap(),
                    _ => unreachable!(),
                }

                self.allocator.consume(destination);
                self.allocator.consume(source);

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Extend(inner, extend) => {
                let src = self.compile_node(rt, inner, extend);
                let dst = self.allocator.acquire(rt, &[], &[]);
                self.allocator.copy_register(rt, src, dst);
                self.allocator.consume(src);

                let dword = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                let word = get_gpr16(register_of_size(dst.into(), 2).unwrap()).unwrap();
                let byte = get_gpr8(register_of_size(dst.into(), 1).unwrap()).unwrap();

                match (extend.size(), extend == extend.signed()) {
                    (8, _) => {}
                    (4, false) => rt.asm.mov(dword, dword).unwrap(),
                    (4, true) => rt.asm.movsxd(dst, dword).unwrap(),
                    (2, false) => rt.asm.movzx(dst, word).unwrap(),
                    (2, true) => rt.asm.movsx(dst, word).unwrap(),
                    (1, false) => rt.asm.movzx(dst, byte).unwrap(),
                    (1, true) => rt.asm.movsx(dst, byte).unwrap(),
                    _ => unreachable!(),
                }

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::Exchange(first, second) => {
                let first = self.compile_node(rt, first, width);
                let second = self.compile_node(rt, second, VMWidth::Lower64);

                let pinned = pinned(&[first, second]);

                let dst = self.allocator.acquire(rt, &pinned, &[]);
                self.allocator.copy_register(rt, first, dst);

                let src = self.allocator.acquire(rt, &pinned, &[dst]);
                self.allocator.copy_register(rt, second, src);

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

                self.allocator.consume(first);
                self.allocator.consume(second);

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(dst, tmp, true);

                Reference::Value(tmp)
            }
            &Node::CompareExchange(first, second, third) => {
                let first = self.compile_node(rt, first, width);
                let second = self.compile_node(rt, second, width);
                let third = self.compile_node(rt, third, VMWidth::Lower64);

                let pinned = pinned(&[first, second, third]);

                let src = self.allocator.acquire(rt, &pinned, &[rax]);
                self.allocator.copy_register(rt, second, src);

                let dst = self.allocator.acquire(rt, &pinned, &[rax, src]);
                self.allocator.copy_register(rt, third, dst);

                self.allocator.copy_register(rt, first, rax);

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

                self.allocator.consume(first);
                self.allocator.consume(second);
                self.allocator.consume(third);

                let tmp = self.allocator.temporary();
                self.allocator.replace_register(rax, tmp, true);

                Reference::Value(tmp)
            }
            &Node::LoadMemory(address) => self.compile_load_memory(rt, address, width),
            &Node::LoadVector => self.compile_load_vector(rt, width),
            &Node::Vector(operator, first, second) => {
                self.compile_vector(rt, operator, first, second, width)
            }
            &Node::PackedByteMask(value) => self.compile_packed_byte_mask(rt, value, width),
            &Node::WideMul(first, second) => {
                if self.compiled.insert(value.node) {
                    let base = node_slot(
                        nodes,
                        Value {
                            node: value.node,
                            output: 0,
                        },
                    );

                    let first = self.compile_node(rt, first, width);
                    let second = self.compile_node(rt, second, width);

                    let pinned = pinned(&[first, second]);

                    let src = self.allocator.acquire(rt, &pinned, &[rax]);
                    self.allocator.copy_register(rt, second, src);
                    self.allocator.copy_register(rt, first, rax);

                    sized!(rt, width, src, mul, imul);

                    if width.size() == 1 {
                        rt.asm.movzx(rdx, ax).unwrap();
                        rt.asm.shr(rdx, 0x8).unwrap();
                    }

                    self.allocator.consume(first);
                    self.allocator.consume(second);

                    self.store_node(rt, base, rax);
                    self.store_node(rt, base + 1, rdx);
                }

                Reference::Value(Slot::Node(node_slot(nodes, value)))
            }
            &Node::Div(first, second, third) => {
                if self.compiled.insert(value.node) {
                    let base = node_slot(
                        nodes,
                        Value {
                            node: value.node,
                            output: 0,
                        },
                    );

                    let first = self.compile_node(rt, first, width);
                    let second = self.compile_node(rt, second, width);
                    let third = self.compile_node(rt, third, width);

                    let pinned = pinned(&[first, second, third]);

                    let src = self.allocator.acquire(rt, &pinned, &[rax, rdx]);

                    self.allocator.copy_register(rt, first, src);
                    self.allocator.copy_register(rt, second, rax);
                    self.allocator.copy_register(rt, third, rdx);

                    if width.size() == 1 {
                        rt.asm.mov(ah, dl).unwrap();
                    }

                    sized!(rt, width, src, div, idiv);

                    if width.size() == 1 {
                        rt.asm.movzx(dx, ah).unwrap();
                    }

                    self.allocator.consume(first);
                    self.allocator.consume(second);
                    self.allocator.consume(third);

                    self.store_node(rt, base, rax);
                    self.store_node(rt, base + 1, rdx);
                }

                Reference::Value(Slot::Node(node_slot(nodes, value)))
            }
            &Node::Cpuid(leaf, subleaf) => {
                if self.compiled.insert(value.node) {
                    let base = node_slot(
                        nodes,
                        Value {
                            node: value.node,
                            output: 0,
                        },
                    );

                    let leaf = self.compile_node(rt, leaf, width);
                    let subleaf = self.compile_node(rt, subleaf, width);

                    self.allocator.copy_register(rt, leaf, rax);
                    self.allocator.copy_register(rt, subleaf, rcx);
                    self.allocator.consume(leaf);
                    self.allocator.consume(subleaf);

                    self.allocator.spill(rt, rdx);

                    rt.asm.push(rbx).unwrap();
                    rt.asm.cpuid().unwrap();

                    self.store_node(rt, base + 1, rbx);

                    rt.asm.pop(rbx).unwrap();

                    self.store_node(rt, base, rax);
                    self.store_node(rt, base + 2, rcx);
                    self.store_node(rt, base + 3, rdx);
                }

                Reference::Value(Slot::Node(node_slot(nodes, value)))
            }
            &Node::Timestamp => {
                if self.compiled.insert(value.node) {
                    let base = node_slot(
                        nodes,
                        Value {
                            node: value.node,
                            output: 0,
                        },
                    );

                    self.allocator.spill(rt, rax);
                    self.allocator.spill(rt, rdx);

                    rt.asm.rdtsc().unwrap();

                    self.store_node(rt, base, rax);
                    self.store_node(rt, base + 1, rdx);
                }

                Reference::Value(Slot::Node(node_slot(nodes, value)))
            }
            &Node::ExchangeAdd(first, second) => {
                if self.compiled.insert(value.node) {
                    let base = node_slot(
                        nodes,
                        Value {
                            node: value.node,
                            output: 0,
                        },
                    );

                    let first = self.compile_node(rt, first, width);
                    let second = self.compile_node(rt, second, VMWidth::Lower64);

                    let pinned = pinned(&[first, second]);

                    let dst = self.allocator.acquire(rt, &pinned, &[]);
                    self.allocator.copy_register(rt, first, dst);

                    let src = self.allocator.acquire(rt, &pinned, &[dst]);
                    self.allocator.copy_register(rt, second, src);

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
                            let dword =
                                get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                            rt.asm.lock().xadd(ptr(src), dword).unwrap();
                        }
                        8 => {
                            rt.asm.lock().xadd(ptr(src), dst).unwrap();
                        }
                        _ => unreachable!(),
                    }

                    self.allocator.copy_register(rt, first, src);

                    rt.asm.add(src, dst).unwrap();

                    self.store_node(rt, base, src);
                    self.store_node(rt, base + 1, dst);

                    self.allocator.consume(first);
                    self.allocator.consume(second);
                }

                Reference::Value(Slot::Node(node_slot(nodes, value)))
            }
        }
    }

    fn compile_vector(
        &mut self,
        rt: &mut Runtime,
        operator: Vector,
        first: Value,
        second: Value,
        width: VMWidth,
    ) -> Reference {
        let first = self.compile_node(rt, first, width);
        let second = self.compile_node(rt, second, width);

        let pinned = pinned(&[first, second]);

        let dst = self.allocator.acquire_vector(rt, &pinned, &[]);
        self.allocator.copy_vector(rt, first, dst);

        let src = self.allocator.acquire_vector(rt, &pinned, &[dst]);
        self.allocator.copy_vector(rt, second, src);

        match operator {
            Vector::Add => match width {
                VMWidth::Lower256 => compile_precision(
                    rt,
                    move |rt| rt.asm.vpaddq(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vaddpd(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpaddd(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vaddps(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpaddw(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vaddps(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpaddb(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vaddps(dst, dst, src).unwrap(),
                ),
                VMWidth::Lower128 => compile_precision(
                    rt,
                    move |rt| rt.asm.paddq(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.addpd(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.paddd(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.addps(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.paddw(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.addps(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.paddb(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.addps(xmm(dst), xmm(src)).unwrap(),
                ),
                _ => unreachable!(),
            },
            Vector::Sub => match width {
                VMWidth::Lower256 => compile_precision(
                    rt,
                    move |rt| rt.asm.vpsubq(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vsubpd(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpsubd(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vsubps(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpsubw(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vsubps(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpsubb(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vsubps(dst, dst, src).unwrap(),
                ),
                VMWidth::Lower128 => compile_precision(
                    rt,
                    move |rt| rt.asm.psubq(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.subpd(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.psubd(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.subps(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.psubw(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.subps(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.psubb(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.subps(xmm(dst), xmm(src)).unwrap(),
                ),
                _ => unreachable!(),
            },
            Vector::Mul => match width {
                VMWidth::Lower256 => compile_extension(
                    rt,
                    move |rt| rt.asm.vmulpd(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpmulld(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vmulps(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpmulhw(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vpmullw(dst, dst, src).unwrap(),
                ),
                VMWidth::Lower128 => compile_extension(
                    rt,
                    move |rt| rt.asm.mulpd(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.pmulld(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.mulps(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.pmulhw(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.pmullw(xmm(dst), xmm(src)).unwrap(),
                ),
                _ => unreachable!(),
            },
            Vector::Div => match width {
                VMWidth::Lower256 => compile_stride(
                    rt,
                    move |rt| rt.asm.vdivpd(dst, dst, src).unwrap(),
                    move |rt| rt.asm.vdivps(dst, dst, src).unwrap(),
                ),
                VMWidth::Lower128 => compile_stride(
                    rt,
                    move |rt| rt.asm.divpd(xmm(dst), xmm(src)).unwrap(),
                    move |rt| rt.asm.divps(xmm(dst), xmm(src)).unwrap(),
                ),
                _ => unreachable!(),
            },
            Vector::And => match width {
                VMWidth::Lower256 => rt.asm.vpand(dst, dst, src).unwrap(),
                VMWidth::Lower128 => rt.asm.pand(xmm(dst), xmm(src)).unwrap(),
                _ => unreachable!(),
            },
            Vector::Or => match width {
                VMWidth::Lower256 => rt.asm.vpor(dst, dst, src).unwrap(),
                VMWidth::Lower128 => rt.asm.por(xmm(dst), xmm(src)).unwrap(),
                _ => unreachable!(),
            },
            Vector::Xor => match width {
                VMWidth::Lower256 => rt.asm.vpxor(dst, dst, src).unwrap(),
                VMWidth::Lower128 => rt.asm.pxor(xmm(dst), xmm(src)).unwrap(),
                _ => unreachable!(),
            },
            Vector::AndNot => match width {
                VMWidth::Lower256 => rt.asm.vpandn(dst, dst, src).unwrap(),
                VMWidth::Lower128 => rt.asm.pandn(xmm(dst), xmm(src)).unwrap(),
                _ => unreachable!(),
            },
            Vector::PackedByteEqual => match width {
                VMWidth::Lower256 => rt.asm.vpcmpeqb(dst, dst, src).unwrap(),
                VMWidth::Lower128 => rt.asm.pcmpeqb(xmm(dst), xmm(src)).unwrap(),
                _ => unreachable!(),
            },
        }

        self.allocator.consume(first);
        self.allocator.consume(second);

        if src != dst {
            self.allocator.spill_vector(rt, src);
        }

        let tmp = self.allocator.temporary();
        self.allocator.replace_vector(dst, tmp, true);
        Reference::Value(tmp)
    }

    fn compile_packed_byte_mask(
        &mut self,
        rt: &mut Runtime,
        value: Value,
        width: VMWidth,
    ) -> Reference {
        let value = self.compile_node(rt, value, width);

        let pinned = pinned(&[value]);
        let source = self.allocator.acquire_vector(rt, &pinned, &[]);
        self.allocator.copy_vector(rt, value, source);
        self.allocator.consume(value);

        let dst = self.allocator.acquire(rt, &[], &[]);
        let mask = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();

        match width {
            VMWidth::Lower256 => rt.asm.vpmovmskb(mask, source).unwrap(),
            VMWidth::Lower128 => rt.asm.pmovmskb(mask, xmm(source)).unwrap(),
            _ => unreachable!(),
        }

        let tmp = self.allocator.temporary();
        self.allocator.replace_register(dst, tmp, true);
        Reference::Value(tmp)
    }

    fn compile_load_vector(&mut self, rt: &mut Runtime, width: VMWidth) -> Reference {
        self.allocator.spill(rt, rax);
        self.allocator.spill(rt, r9);

        bytecode::read_byte_zx(rt, r13, r9d);
        rt.asm.shl(r9, 0x5).unwrap();
        register::load(rt, r12, rax, VMReg::VVector);

        match width {
            VMWidth::Lower64 => {
                rt.asm.mov(rax, ptr(rax + r9)).unwrap();
                let tmp = self.allocator.temporary();
                self.allocator.replace_register(rax, tmp, true);
                Reference::Value(tmp)
            }
            VMWidth::Lower32 => {
                rt.asm.mov(eax, ptr(rax + r9)).unwrap();
                let tmp = self.allocator.temporary();
                self.allocator.replace_register(rax, tmp, true);
                Reference::Value(tmp)
            }
            VMWidth::Lower256 => {
                let dst = self.allocator.acquire_vector(rt, &[], &[]);
                rt.asm.vmovups(dst, ptr(rax + r9)).unwrap();
                let tmp = self.allocator.temporary();
                self.allocator.replace_vector(dst, tmp, true);
                Reference::Value(tmp)
            }
            VMWidth::Lower128 => {
                let dst = self.allocator.acquire_vector(rt, &[], &[]);
                rt.asm.movups(xmm(dst), ptr(rax + r9)).unwrap();
                let tmp = self.allocator.temporary();
                self.allocator.replace_vector(dst, tmp, true);
                Reference::Value(tmp)
            }
            _ => unreachable!(),
        }
    }

    fn compile_load_memory(
        &mut self,
        rt: &mut Runtime,
        address: Value,
        width: VMWidth,
    ) -> Reference {
        let address = self.compile_node(rt, address, VMWidth::Lower64);

        let pinned = pinned(&[address]);

        let base = self.allocator.acquire(rt, &pinned, &[]);
        self.allocator.copy_register(rt, address, base);
        self.allocator.consume(address);

        match width {
            VMWidth::Lower256 => {
                let dst = self.allocator.acquire_vector(rt, &[], &[]);
                rt.asm.vmovups(dst, ptr(base)).unwrap();
                let tmp = self.allocator.temporary();
                self.allocator.replace_vector(dst, tmp, true);
                return Reference::Value(tmp);
            }
            VMWidth::Lower128 => {
                let dst = self.allocator.acquire_vector(rt, &[], &[]);
                rt.asm.movups(xmm(dst), ptr(base)).unwrap();
                let tmp = self.allocator.temporary();
                self.allocator.replace_vector(dst, tmp, true);
                return Reference::Value(tmp);
            }
            _ => {}
        }

        let dst = self.allocator.acquire(rt, &[], &[base]);

        match width {
            VMWidth::Lower64 | VMWidth::SLower64 => rt.asm.mov(dst, ptr(base)).unwrap(),
            VMWidth::Lower32 => {
                let destination = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();
                rt.asm.mov(destination, ptr(base)).unwrap();
            }
            VMWidth::Lower16 => rt.asm.movzx(dst, word_ptr(base)).unwrap(),
            VMWidth::Higher8 | VMWidth::Lower8 => rt.asm.movzx(dst, byte_ptr(base)).unwrap(),
            VMWidth::SLower32 => rt.asm.movsxd(dst, dword_ptr(base)).unwrap(),
            VMWidth::SLower16 => rt.asm.movsx(dst, word_ptr(base)).unwrap(),
            VMWidth::SLower8 => rt.asm.movsx(dst, byte_ptr(base)).unwrap(),
            _ => unreachable!(),
        }

        let tmp = self.allocator.temporary();
        self.allocator.replace_register(dst, tmp, true);
        Reference::Value(tmp)
    }

    fn compile_statements(&mut self, rt: &mut Runtime, statements: &[Statement], width: VMWidth) {
        for statement in statements {
            self.compile_statement(rt, statement, width);
        }
    }

    fn compile_statement(&mut self, rt: &mut Runtime, statement: &Statement, width: VMWidth) {
        match statement {
            &Statement::WriteRegister(register, value) => {
                self.compile_write_register(rt, register, value, width)
            }
            &Statement::WriteMemory(address, value) => {
                self.compile_write_memory(rt, address, value, width)
            }
            &Statement::StoreMemory(address, value) => {
                self.compile_store_memory(rt, address, value, width)
            }
            &Statement::StoreMerge(value) => self.compile_store_merge(rt, value, width),
            &Statement::StoreExtend(value) => self.compile_store_extend(rt, value, width),
            &Statement::Assign(index, value) => self.compile_assign(rt, index, value, width),
            &Statement::Read(index, width) => self.compile_read(rt, index, width),
            &Statement::Advance(value) => self.compile_advance(rt, value, width),
            &Statement::Drop(value) => self.compile_drop(rt, value, width),
            Statement::Loop(counter, body) => self.compile_loop(rt, *counter, body, width),
            Statement::Select(selector, arms) => self.compile_select(rt, *selector, arms, width),
            Statement::When(condition, body) => self.compile_when(rt, *condition, body, width),
        }
    }

    fn compile_write_register(
        &mut self,
        rt: &mut Runtime,
        register: Register,
        value: Value,
        width: VMWidth,
    ) {
        let value = self.compile_node(rt, value, width);

        let pinned = pinned(&[value]);

        let index = self.allocator.acquire(rt, &pinned, &[]);
        let slot = get_gpr32(register_of_size(index.into(), 4).unwrap()).unwrap();

        match register {
            Register::Operand => bytecode::read_byte_zx(rt, r13, slot),
            Register::Fixed(register) => {
                rt.asm.mov(slot, rt.mapper.index(register) as i32).unwrap()
            }
        }

        let src = self.allocator.acquire(rt, &pinned, &[index]);
        self.allocator.copy_register(rt, value, src);

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

        self.allocator.consume(value);
    }

    fn compile_write_memory(
        &mut self,
        rt: &mut Runtime,
        address: Value,
        value: Value,
        width: VMWidth,
    ) {
        let pointer = self.compile_node(rt, address, VMWidth::Lower64);
        let value = self.compile_node(rt, value, width);

        let pinned = pinned(&[pointer, value]);

        let base = self.allocator.acquire(rt, &pinned, &[]);
        self.allocator.copy_register(rt, pointer, base);

        let src = self.allocator.acquire(rt, &pinned, &[base]);
        self.allocator.copy_register(rt, value, src);

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

        self.allocator.consume(pointer);
        self.allocator.consume(value);
    }

    fn compile_store_memory(
        &mut self,
        rt: &mut Runtime,
        address: Value,
        value: Value,
        width: VMWidth,
    ) {
        let address = self.allocator.offset(self.operand(address));
        let value = self.allocator.offset(self.operand(value));

        rt.asm.mov(r8, qword_ptr(rbp - address)).unwrap();

        match width {
            VMWidth::Lower64 => {
                rt.asm.mov(r9, qword_ptr(rbp - value)).unwrap();
                rt.asm.mov(ptr(r8), r9).unwrap();
            }
            VMWidth::Lower32 => {
                rt.asm.mov(r9, qword_ptr(rbp - value)).unwrap();
                rt.asm.mov(ptr(r8), r9d).unwrap();
            }
            VMWidth::Lower16 => {
                rt.asm.mov(r9, qword_ptr(rbp - value)).unwrap();
                rt.asm.mov(ptr(r8), r9w).unwrap();
            }
            VMWidth::Lower8 | VMWidth::Higher8 => {
                rt.asm.mov(r9, qword_ptr(rbp - value)).unwrap();
                rt.asm.mov(ptr(r8), r9b).unwrap();
            }
            VMWidth::Lower256 => {
                rt.asm.vmovups(ymm0, ptr(rbp - value)).unwrap();
                rt.asm.vmovups(ptr(r8), ymm0).unwrap();
            }
            VMWidth::Lower128 => {
                rt.asm.movups(xmm0, ptr(rbp - value)).unwrap();
                rt.asm.movups(ptr(r8), xmm0).unwrap();
            }
            _ => unreachable!(),
        }
    }

    fn compile_store_merge(&mut self, rt: &mut Runtime, value: Value, width: VMWidth) {
        bytecode::read_byte_zx(rt, r13, r9d);
        rt.asm.shl(r9, 0x5).unwrap();
        register::load(rt, r12, rax, VMReg::VVector);

        let value = self.allocator.offset(self.operand(value));

        match width {
            VMWidth::Lower64 => {
                rt.asm.mov(r8, qword_ptr(rbp - value)).unwrap();
                rt.asm.mov(ptr(rax + r9), r8).unwrap();
            }
            VMWidth::Lower32 => {
                rt.asm.mov(r8, qword_ptr(rbp - value)).unwrap();
                rt.asm.mov(ptr(rax + r9), r8d).unwrap();
            }
            VMWidth::Lower256 => {
                rt.asm.vmovups(ymm0, ptr(rbp - value)).unwrap();
                rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
            }
            VMWidth::Lower128 => {
                rt.asm.movups(xmm0, ptr(rbp - value)).unwrap();
                rt.asm.movups(ptr(rax + r9), xmm0).unwrap();
            }
            _ => unreachable!(),
        }
    }

    fn compile_store_extend(&mut self, rt: &mut Runtime, value: Value, width: VMWidth) {
        bytecode::read_byte_zx(rt, r13, r9d);
        rt.asm.shl(r9, 0x5).unwrap();
        register::load(rt, r12, rax, VMReg::VVector);

        let value = self.allocator.offset(self.operand(value));

        match width {
            VMWidth::Lower64 => {
                rt.asm.vmovups(ymm0, ptr(rax + r9)).unwrap();
                rt.asm.mov(r8, qword_ptr(rbp - value)).unwrap();
                rt.asm.movq(xmm0, r8).unwrap();
                rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
            }
            VMWidth::Lower32 => {
                rt.asm.vmovups(ymm0, ptr(rax + r9)).unwrap();
                rt.asm.mov(r8, qword_ptr(rbp - value)).unwrap();
                rt.asm.movd(xmm0, r8d).unwrap();
                rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
            }
            VMWidth::Lower256 => {
                rt.asm.vmovups(ymm0, ptr(rbp - value)).unwrap();
                rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
            }
            VMWidth::Lower128 => {
                rt.asm.movups(xmm0, ptr(rbp - value)).unwrap();
                rt.asm.vmovaps(xmm0, xmm0).unwrap();
                rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
            }
            _ => unreachable!(),
        }
    }

    fn compile_assign(&mut self, rt: &mut Runtime, index: usize, value: Value, width: VMWidth) {
        let value = self.compile_node(rt, value, width);

        let pinned = pinned(&[value]);

        let dst = self.allocator.acquire(rt, &pinned, &[]);
        self.allocator.copy_register(rt, value, dst);
        self.allocator.consume(value);

        self.store_local(rt, index, dst);
    }

    fn compile_read(&mut self, rt: &mut Runtime, index: usize, width: VMWidth) {
        let dst = self.allocator.acquire(rt, &[], &[]);
        let register = get_gpr32(register_of_size(dst.into(), 4).unwrap()).unwrap();

        match width.size() {
            1 => bytecode::read_byte_zx(rt, r13, register),
            2 => bytecode::read_word_zx(rt, r13, register),
            4 => bytecode::read_dword(rt, r13, register),
            8 => bytecode::read_qword(rt, r13, dst),
            _ => unreachable!(),
        }

        self.store_local(rt, index, dst);
    }

    fn compile_advance(&mut self, rt: &mut Runtime, value: Value, width: VMWidth) {
        let value = self.compile_node(rt, value, width);

        let pinned = pinned(&[value]);

        let register = self.allocator.acquire(rt, &pinned, &[]);
        self.allocator.copy_register(rt, value, register);
        self.allocator.consume(value);

        rt.asm.add(r13, register).unwrap();
    }

    fn compile_drop(&mut self, rt: &mut Runtime, value: Value, width: VMWidth) {
        let value = self.compile_node(rt, value, width);
        self.allocator.consume(value);
    }

    fn compile_loop(
        &mut self,
        rt: &mut Runtime,
        counter: usize,
        body: &[Statement],
        width: VMWidth,
    ) {
        let counter = Slot::Local(counter);

        let mut repeat = rt.asm.create_label();
        let mut done = rt.asm.create_label();

        rt.asm.set_label(&mut repeat).unwrap();
        rt.asm.zero_bytes().unwrap();

        let register = self.allocator.acquire(rt, &[], &[]);
        rt.asm
            .mov(register, qword_ptr(rbp - self.allocator.offset(counter)))
            .unwrap();
        rt.asm.test(register, register).unwrap();
        rt.asm.jz(done).unwrap();

        self.compile_statements(rt, body, width);

        let register = self.allocator.acquire(rt, &[], &[]);
        rt.asm
            .mov(register, qword_ptr(rbp - self.allocator.offset(counter)))
            .unwrap();
        rt.asm.sub(register, 1).unwrap();
        rt.asm
            .mov(qword_ptr(rbp - self.allocator.offset(counter)), register)
            .unwrap();
        rt.asm.jmp(repeat).unwrap();

        rt.asm.set_label(&mut done).unwrap();
        rt.asm.zero_bytes().unwrap();
    }

    fn compile_select(
        &mut self,
        rt: &mut Runtime,
        selector: Value,
        arms: &[(Vec<u64>, Vec<Statement>)],
        width: VMWidth,
    ) {
        let value = self.compile_node(rt, selector, width);
        let register = self.allocator.acquire(rt, &[], &[]);
        self.allocator.copy_register(rt, value, register);
        self.allocator.consume(value);

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
            self.compile_statements(rt, body, width);
            rt.asm.jmp(merge).unwrap();
        }

        rt.asm.set_label(&mut merge).unwrap();
        rt.asm.zero_bytes().unwrap();
    }

    fn compile_when(
        &mut self,
        rt: &mut Runtime,
        condition: Value,
        body: &[Statement],
        width: VMWidth,
    ) {
        let value = self.compile_node(rt, condition, width);
        let register = self.allocator.acquire(rt, &[], &[]);
        self.allocator.copy_register(rt, value, register);
        self.allocator.consume(value);
        rt.asm.test(register, register).unwrap();

        let mut skip = rt.asm.create_label();
        rt.asm.jz(skip).unwrap();

        self.compile_statements(rt, body, width);

        rt.asm.set_label(&mut skip).unwrap();
        rt.asm.zero_bytes().unwrap();
    }

    fn compile_flags(&mut self, rt: &mut Runtime, flags: &Flags, width: VMWidth) {
        let register = self.allocator.acquire(rt, &[], &[]);

        register::load(rt, r12, register, VMReg::Flags);

        rt.asm
            .mov(
                qword_ptr(rbp - self.allocator.offset(Slot::Flags)),
                register,
            )
            .unwrap();

        self.allocator.untrack_register(register);

        for &(flag, value) in flags.values() {
            let value = self.compile_node(rt, value, width);

            let pinned = pinned(&[value]);

            let dst = self.allocator.acquire(rt, &pinned, &[]);
            self.allocator.copy_register(rt, value, dst);
            self.allocator.consume(value);

            let bit = flag.bit32().trailing_zeros() as i32;
            let mask = flag.bit32();

            rt.asm
                .and(dword_ptr(rbp - self.allocator.offset(Slot::Flags)), !mask)
                .unwrap();
            rt.asm.shl(dst, bit).unwrap();
            rt.asm
                .or(dword_ptr(rbp - self.allocator.offset(Slot::Flags)), dst)
                .unwrap();

            self.allocator.spill(rt, dst);
        }

        match flags.condition() {
            None => {
                let register = self.allocator.acquire(rt, &[], &[]);

                rt.asm
                    .mov(
                        register,
                        qword_ptr(rbp - self.allocator.offset(Slot::Flags)),
                    )
                    .unwrap();

                register::store(rt, r12, VMReg::Flags, register);

                self.allocator.untrack_register(register);
            }
            Some(&condition) => {
                let condition = self.compile_node(rt, condition, width);

                let pinned = pinned(&[condition]);

                let selector = self.allocator.acquire(rt, &pinned, &[]);
                self.allocator.copy_register(rt, condition, selector);
                self.allocator.consume(condition);

                let register = self.allocator.acquire(rt, &[], &[selector]);

                rt.asm
                    .mov(
                        register,
                        qword_ptr(rbp - self.allocator.offset(Slot::Flags)),
                    )
                    .unwrap();

                let target = self.allocator.acquire(rt, &[], &[selector, register]);
                rt.asm
                    .lea(target, ptr(r12 + rt.mapper.index(VMReg::Flags) as i32 * 8))
                    .unwrap();

                let skip = self
                    .allocator
                    .acquire(rt, &[], &[selector, register, target]);
                rt.asm
                    .lea(skip, ptr(rbp - self.allocator.offset(Slot::Flags)))
                    .unwrap();

                rt.asm.test(selector, selector).unwrap();
                rt.asm.cmovz(target, skip).unwrap();
                rt.asm.mov(ptr(target), register).unwrap();
            }
        }
    }
}

pub fn compile(rt: &mut Runtime, operation: &Operation) {
    let operation = obfuscation::operation(operation);
    compile_scalar(rt, &operation);
    rt.asm.ret().unwrap();
}

pub fn compile_fragment(rt: &mut Runtime, operation: &Operation) {
    compile_scalar(rt, &obfuscation::operation(operation));
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

fn compile_scalar(rt: &mut Runtime, operation: &Operation) {
    let mut epilogue = rt.asm.create_label();
    let operands = operation.operands_count();
    let flags = !operation.flags.is_empty();
    let locals = operation.locals();
    let node_slots = operation.node_slots();
    let temporaries = operation.temporaries();
    let pointers = operation.pointers();
    let slots = operands + flags as usize + locals + node_slots + temporaries;
    let size = ((slots as i32 * 32) + 15) & !15;

    rt.asm.push(r13).unwrap();
    rt.asm.push(r14).unwrap();
    rt.asm.push(rbp).unwrap();
    rt.asm.mov(rbp, rsp).unwrap();
    rt.asm.sub(rsp, size).unwrap();

    rt.asm.mov(r13, rcx).unwrap();

    if operation.widths.is_empty() {
        compile_body(rt, operation, &pointers, VMWidth::Lower64);
    } else {
        bytecode::read_byte_zx(rt, r13, r14d);

        let labels = operation
            .widths
            .iter()
            .map(|_| rt.asm.create_label())
            .collect::<Vec<CodeLabel>>();

        let cases = operation
            .widths
            .iter()
            .zip(&labels)
            .map(|(width, label)| (rt.mapper.index(*width) as u8, *label))
            .collect::<Vec<(u8, CodeLabel)>>();

        rt.jumps(r14, cases);

        for (&width, mut label) in operation.widths.iter().zip(labels) {
            rt.asm.set_label(&mut label).unwrap();
            compile_body(rt, operation, &pointers, width);
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();

    rt.asm.mov(rax, r13).unwrap();

    rt.asm.add(rsp, size).unwrap();
    rt.asm.pop(rbp).unwrap();
    rt.asm.pop(r14).unwrap();
    rt.asm.pop(r13).unwrap();
}

fn compile_body(
    rt: &mut Runtime,
    operation: &Operation,
    pointers: &HashSet<usize>,
    width: VMWidth,
) {
    let operands = operation.operands_count();
    let flags = !operation.flags.is_empty();
    let locals = operation.locals();
    let node_slots = operation.node_slots();

    let mut lowering = Lowering {
        nodes: &operation.nodes,
        allocator: Allocator::new(operands, locals, node_slots, width, flags),
        compiled: HashSet::new(),
    };

    for index in (0..operands).rev() {
        let slot = lowering.allocator.offset(Slot::Input(index));
        let width = if pointers.contains(&index) {
            VMWidth::Lower64
        } else {
            width
        };

        match width {
            VMWidth::Lower256 => {
                scratch::load_256(rt, r12, ymm0);
                rt.asm.vmovups(ptr(rbp - slot), ymm0).unwrap();
            }
            VMWidth::Lower128 => {
                scratch::load_128(rt, r12, xmm0);
                rt.asm.movups(ptr(rbp - slot), xmm0).unwrap();
            }
            _ => {
                scratch::load(rt, r12, rax);
                rt.asm.mov(qword_ptr(rbp - slot), rax).unwrap();
            }
        }
    }

    lowering.compile_statements(rt, &operation.statements, width);

    if flags {
        lowering.compile_flags(rt, &operation.flags, width);
    }

    lowering.allocator.dump(rt);

    lowering.allocator = Allocator::new(operands, locals, node_slots, width, flags);

    let Some(outputs) = &operation.outputs else {
        return;
    };

    for &value in outputs {
        let src = lowering.compile_node(rt, value, width);

        match width {
            VMWidth::Lower256 if lowering.allocator.is_vector(src) => {
                lowering.allocator.copy_vector(rt, src, ymm0);
                scratch::store_256(rt, r12, ymm0);
            }
            VMWidth::Lower128 if lowering.allocator.is_vector(src) => {
                lowering.allocator.copy_vector(rt, src, ymm0);
                scratch::store_128(rt, r12, xmm0);
            }
            _ => {
                let dst = lowering.allocator.acquire(rt, &[], &[]);
                lowering.allocator.copy_register(rt, src, dst);
                scratch::store(rt, r12, dst);
                lowering.allocator.spill(rt, dst);
            }
        }

        lowering.allocator.consume(src);
    }
}

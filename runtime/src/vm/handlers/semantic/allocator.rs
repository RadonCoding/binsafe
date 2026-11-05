use iced_x86::{
    code_asm::{
        get_xmm, ptr, qword_ptr, r8, r9, rax, rbp, rcx, rdx, ymm2, ymm3, ymm4, ymm5, AsmRegister64,
        AsmRegisterXmm, AsmRegisterYmm,
    },
    Register,
};

use std::collections::HashSet;

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        handlers::semantic::{Reference, Slot},
    },
};

pub fn xmm(register: AsmRegisterYmm) -> AsmRegisterXmm {
    let register: Register = register.into();
    get_xmm(Register::XMM0 + register.number() as u32).unwrap()
}

#[derive(Clone)]
pub struct Allocator {
    tracked: Vec<(AsmRegister64, Slot)>,
    vectors: Vec<(AsmRegisterYmm, Slot)>,
    dirty: HashSet<Slot>,
    temporary: usize,
    inputs: usize,
    locals: usize,
    nodes: usize,
    width: VMWidth,
    flags: bool,
}

impl Allocator {
    const REGISTERS: [AsmRegister64; 5] = [rax, rcx, rdx, r8, r9];
    const VECTORS: [AsmRegisterYmm; 4] = [ymm2, ymm3, ymm4, ymm5];

    pub fn new(inputs: usize, locals: usize, nodes: usize, width: VMWidth, flags: bool) -> Self {
        Self {
            tracked: Vec::new(),
            vectors: Vec::new(),
            dirty: HashSet::new(),
            temporary: 0,
            inputs,
            locals,
            nodes,
            width,
            flags,
        }
    }

    fn track(&mut self, register: AsmRegister64, value: Slot, dirty: bool) {
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

    fn track_vector(&mut self, register: AsmRegisterYmm, value: Slot, dirty: bool) {
        assert!(
            self.vectors.iter().all(|(r, _)| *r != register),
            "vector register {:?} is already tracked",
            register
        );
        assert!(
            self.vectors.iter().all(|(_, v)| *v != value),
            "value {:?} is already tracked",
            value
        );
        self.vectors.push((register, value));

        if dirty {
            self.dirty.insert(value);
        } else {
            self.dirty.remove(&value);
        }
    }

    pub fn untrack_register(&mut self, register: AsmRegister64) -> Option<Slot> {
        let index = self.tracked.iter().position(|(r, _)| *r == register)?;
        Some(self.tracked.swap_remove(index).1)
    }

    fn untrack_vector(&mut self, register: AsmRegisterYmm) -> Option<Slot> {
        let index = self.vectors.iter().position(|(r, _)| *r == register)?;
        Some(self.vectors.swap_remove(index).1)
    }

    fn tracked_register(&self, value: Slot) -> Option<AsmRegister64> {
        self.tracked
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(r, _)| *r)
    }

    fn tracked_value(&self, register: AsmRegister64) -> Option<Slot> {
        self.tracked
            .iter()
            .find(|(r, _)| *r == register)
            .map(|(_, v)| *v)
    }

    fn tracked_vector(&self, value: Slot) -> Option<AsmRegisterYmm> {
        self.vectors
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(r, _)| *r)
    }

    fn tracked_vector_value(&self, register: AsmRegisterYmm) -> Option<Slot> {
        self.vectors
            .iter()
            .find(|(r, _)| *r == register)
            .map(|(_, v)| *v)
    }

    pub fn temporary(&mut self) -> Slot {
        let value = Slot::Temporary(self.temporary);
        self.temporary += 1;
        value
    }

    pub fn offset(&self, value: Slot) -> i32 {
        let flags = self.flags as usize;
        let slot = match value {
            Slot::Input(index) => index,
            Slot::Flags => self.inputs,
            Slot::Local(index) => self.inputs + flags + index,
            Slot::Node(index) => self.inputs + flags + self.locals + index,
            Slot::Temporary(index) => self.inputs + flags + self.locals + self.nodes + index,
        };
        (slot as i32 + 1) * 32
    }

    pub fn is_vector(&self, reference: Reference) -> bool {
        matches!(reference, Reference::Value(value) if self.tracked_vector(value).is_some())
    }

    pub fn spill(&mut self, rt: &mut Runtime, register: AsmRegister64) {
        let Some(value) = self.tracked_value(register) else {
            return;
        };

        if self.dirty.remove(&value) {
            rt.asm
                .mov(qword_ptr(rbp - self.offset(value)), register)
                .unwrap();
        }

        self.untrack_register(register);
    }

    pub fn spill_vector(&mut self, rt: &mut Runtime, register: AsmRegisterYmm) {
        let Some(value) = self.tracked_vector_value(register) else {
            return;
        };

        if self.dirty.remove(&value) {
            let slot = ptr(rbp - self.offset(value));
            if self.width == VMWidth::Lower256 {
                rt.asm.vmovups(slot, register).unwrap();
            } else {
                rt.asm.movups(slot, xmm(register)).unwrap();
            }
        }

        self.untrack_vector(register);
    }

    pub fn dump(&mut self, rt: &mut Runtime) {
        let registers = self
            .tracked
            .iter()
            .map(|(register, _)| *register)
            .collect::<Vec<AsmRegister64>>();

        for register in registers {
            self.spill(rt, register);
        }

        let vectors = self
            .vectors
            .iter()
            .map(|(register, _)| *register)
            .collect::<Vec<AsmRegisterYmm>>();

        for register in vectors {
            self.spill_vector(rt, register);
        }
    }

    pub fn acquire(
        &mut self,
        rt: &mut Runtime,
        pinned: &[Slot],
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
            .unwrap();

        self.spill(rt, register);
        register
    }

    pub fn acquire_vector(
        &mut self,
        rt: &mut Runtime,
        pinned: &[Slot],
        avoid: &[AsmRegisterYmm],
    ) -> AsmRegisterYmm {
        if let Some(register) = Self::VECTORS.iter().copied().find(|register| {
            !avoid.contains(register) && self.tracked_vector_value(*register).is_none()
        }) {
            return register;
        }

        if let Some(register) = Self::VECTORS.iter().copied().find(|register| {
            if avoid.contains(register) {
                return false;
            }

            match self.tracked_vector_value(*register) {
                Some(value) => !pinned.contains(&value),
                None => true,
            }
        }) {
            self.spill_vector(rt, register);
            return register;
        }

        let register = Self::VECTORS
            .iter()
            .copied()
            .find(|register| !avoid.contains(register))
            .unwrap();

        self.spill_vector(rt, register);
        register
    }

    pub fn copy_register(&mut self, rt: &mut Runtime, src: Reference, dst: AsmRegister64) {
        self.spill(rt, dst);

        match src {
            Reference::Immediate(value) => {
                rt.asm.mov(dst, value).unwrap();
            }
            Reference::Value(value) => {
                if let Some(src) = self.tracked_register(value) {
                    rt.asm.mov(dst, src).unwrap();
                } else {
                    rt.asm
                        .mov(dst, qword_ptr(rbp - self.offset(value)))
                        .unwrap();
                }
            }
        }
    }

    pub fn copy_vector(&mut self, rt: &mut Runtime, src: Reference, dst: AsmRegisterYmm) {
        self.spill_vector(rt, dst);

        let Reference::Value(value) = src else {
            unreachable!();
        };

        let source = self.tracked_vector(value);

        if self.width == VMWidth::Lower256 {
            match source {
                Some(src) => rt.asm.vmovups(dst, src).unwrap(),
                None => rt.asm.vmovups(dst, ptr(rbp - self.offset(value))).unwrap(),
            }
        } else {
            let dst = xmm(dst);
            match source {
                Some(src) => rt.asm.movups(dst, xmm(src)).unwrap(),
                None => rt.asm.movups(dst, ptr(rbp - self.offset(value))).unwrap(),
            }
        }
    }

    pub fn replace_register(&mut self, register: AsmRegister64, value: Slot, dirty: bool) {
        self.untrack_register(register);

        if let Some(previous) = self.tracked_register(value) {
            self.untrack_register(previous);
        }

        if let Some(previous) = self.tracked_vector(value) {
            self.untrack_vector(previous);
        }

        self.track(register, value, dirty);
    }

    pub fn replace_vector(&mut self, register: AsmRegisterYmm, value: Slot, dirty: bool) {
        self.untrack_vector(register);

        if let Some(previous) = self.tracked_vector(value) {
            self.untrack_vector(previous);
        }

        if let Some(previous) = self.tracked_register(value) {
            self.untrack_register(previous);
        }

        self.track_vector(register, value, dirty);
    }

    pub fn consume(&mut self, value: Reference) {
        let Reference::Value(value) = value else {
            return;
        };

        if matches!(value, Slot::Temporary(_)) {
            if let Some(register) = self.tracked_register(value) {
                self.untrack_register(register);
            }
            if let Some(register) = self.tracked_vector(value) {
                self.untrack_vector(register);
            }
            self.dirty.remove(&value);
        }
    }
}

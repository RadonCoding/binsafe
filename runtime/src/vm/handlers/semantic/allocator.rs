use iced_x86::code_asm::{qword_ptr, r8, r9, rax, rbp, rcx, rdx, AsmRegister64};

use std::collections::HashSet;

use crate::{
    runtime::Runtime,
    vm::handlers::semantic::{Reference, Value},
};

#[derive(Clone)]
pub struct Allocator {
    tracked: Vec<(AsmRegister64, Value)>,
    dirty: HashSet<Value>,
    temporary: usize,
    inputs: usize,
    outputs: usize,
    flags: bool,
}

impl Allocator {
    const REGISTERS: [AsmRegister64; 5] = [rax, rcx, rdx, r8, r9];

    pub fn new(inputs: usize, outputs: usize, flags: bool) -> Self {
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

    pub fn untrack(&mut self, register: AsmRegister64) -> Option<Value> {
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

    pub fn temporary(&mut self) -> Value {
        let value = Value::Temporary(self.temporary);
        self.temporary += 1;
        value
    }

    pub fn offset(&self, value: Value) -> i32 {
        let flags = self.flags as usize;
        let slot = match value {
            Value::Input(index) => index,
            Value::Output(index) => self.inputs + index,
            Value::Flags => self.inputs + self.outputs,
            Value::Temporary(index) => self.inputs + self.outputs + flags + index,
        };
        (slot as i32 + 1) * 8
    }

    pub fn dirty(&mut self, value: Value) {
        self.dirty.insert(value);
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

        self.untrack(register);
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
    }

    pub fn acquire(
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

    pub fn copy(&mut self, rt: &mut Runtime, src: Reference, dst: AsmRegister64) {
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

    pub fn mutable(
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
            .mov(register, qword_ptr(rbp - self.offset(value)))
            .unwrap();
        self.track(register, value, false);
        register
    }

    pub fn replace(&mut self, register: AsmRegister64, value: Value, dirty: bool) {
        self.untrack(register);

        if let Some(previous) = self
            .tracked
            .iter()
            .find(|(_, v)| *v == value)
            .map(|(r, _)| *r)
        {
            self.untrack(previous);
        }

        self.track(register, value, dirty);
    }

    pub fn consume(&mut self, value: Reference) {
        let Reference::Value(value) = value else {
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

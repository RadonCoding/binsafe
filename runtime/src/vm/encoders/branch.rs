use std::any::Any;
use std::fmt::Debug;
use std::slice;

use crate::mapper::Mapper;
use crate::vm::bytecode::{Flag, VMCondition, VMLogic, VMCode, VMReg};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Branch {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
}

impl Branch {
    pub fn jump() -> Self {
        Self::always(VMLogic::JAND)
    }

    pub fn call() -> Self {
        Self::always(VMLogic::CAND)
    }

    pub fn skip() -> Self {
        Self::always(VMLogic::SAND)
    }

    pub fn fallthrough() -> Self {
        Self::never(VMLogic::SAND)
    }

    fn always(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![VMCondition::eq(Flag::Zero, Flag::Zero)],
        }
    }

    fn never(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![VMCondition::neq(Flag::Zero, Flag::Zero)],
        }
    }
}

impl Encode for Branch {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::Branch)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(self.logic), self.conditions.len() as u8];

        for condition in &self.conditions {
            bytes.extend_from_slice(&condition.encode(mapper));
        }
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![
            Effect::Register(VMReg::Flags),
            Effect::Register(VMReg::VImmAdd),
            Effect::Register(VMReg::VImmMul),
        ]
    }

    fn writes(&self) -> Vec<super::Effect> {
        match self.logic {
            VMLogic::SAND | VMLogic::SOR => vec![],
            _ => vec![Effect::Register(VMReg::NBranch)],
        }
    }

    fn consumes(&self) -> i32 {
        1
    }

    fn produces(&self) -> i32 {
        0
    }

    fn is_branch(&self) -> bool {
        true
    }

    fn seal(&mut self, _mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8], usize)) {
        for condition in &mut self.conditions {
            transform(slice::from_mut(&mut condition.lhs), 0);
            transform(slice::from_mut(&mut condition.rhs), 0);
        }
    }
}

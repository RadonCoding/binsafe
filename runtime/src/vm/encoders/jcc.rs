use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMOp, VMReg, VMTest};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Jcc {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
}

impl Encode for Jcc {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::Jcc),
            mapper.index(self.logic),
            self.conditions.len() as u8,
        ];

        for condition in &self.conditions {
            bytes.extend_from_slice(&condition.encode(mapper));
        }
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::Flags)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        match self.logic {
            VMLogic::SAND | VMLogic::SOR => vec![],
            _ => vec![Effect::Register(VMReg::NBranch)],
        }
    }

    fn depth(&self) -> i32 {
        -1
    }

    fn branches(&self) -> bool {
        true
    }
}

impl Jcc {
    pub fn jump() -> Self {
        Self::always(VMLogic::JAND)
    }

    pub fn call() -> Self {
        Self::always(VMLogic::CAND)
    }

    pub fn skip() -> Self {
        Self::always(VMLogic::SAND)
    }

    pub fn pass() -> Self {
        Self::never(VMLogic::SAND)
    }

    fn always(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![tautology()],
        }
    }

    fn never(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![contradiction()],
        }
    }
}

/// Canonical always-true sub-condition: a flag bit compared for equality against itself.
pub fn tautology() -> VMCondition {
    VMCondition {
        test: VMTest::EQ,
        lhs: VMFlag::Zero as u8,
        rhs: VMFlag::Zero as u8,
    }
}

/// Canonical always-false sub-condition: a flag bit compared for inequality against itself.
pub fn contradiction() -> VMCondition {
    VMCondition {
        test: VMTest::NEQ,
        lhs: VMFlag::Zero as u8,
        rhs: VMFlag::Zero as u8,
    }
}

/// Whether `condition` is the canonical [`tautology`] or [`contradiction`] sub-condition.
pub fn is_canonical(condition: &VMCondition) -> bool {
    matches!(condition.test, VMTest::EQ | VMTest::NEQ) && condition.lhs == condition.rhs
}

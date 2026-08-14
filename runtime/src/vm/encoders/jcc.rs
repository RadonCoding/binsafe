use std::any::Any;
use std::fmt::{self, Debug};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMOp, VMReg, VMTest};
use crate::vm::encoders::{Effect, Encode};

pub struct Jcc {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
}

impl Debug for Jcc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operator = match self.logic {
            VMLogic::JAND | VMLogic::CAND | VMLogic::SAND => " & ",
            VMLogic::JOR | VMLogic::COR | VMLogic::SOR => " | ",
            VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => " ^ ",
        };

        let flag = |value| match value {
            x if x == VMFlag::Carry as u8 => "CF",
            x if x == VMFlag::Reserved1 as u8 => "Reserved1",
            x if x == VMFlag::Parity as u8 => "PF",
            x if x == VMFlag::Auxiliary as u8 => "AF",
            x if x == VMFlag::Zero as u8 => "ZF",
            x if x == VMFlag::Sign as u8 => "SF",
            x if x == VMFlag::Trap as u8 => "TF",
            x if x == VMFlag::Interrupt as u8 => "IF",
            x if x == VMFlag::Direction as u8 => "DF",
            x if x == VMFlag::Overflow as u8 => "OF",
            _ => unreachable!(),
        };

        write!(f, "{}({:?}, [", stringify!(Jcc), self.logic)?;

        for (i, condition) in self.conditions.iter().enumerate() {
            if i > 0 {
                write!(f, "{operator}")?;
            }

            match condition.test {
                VMTest::CMP => match condition.rhs {
                    0 => write!(f, "!{}", flag(condition.lhs))?,
                    1 => write!(f, "{}", flag(condition.lhs))?,
                    _ => write!(f, "{}=={:#04x}", flag(condition.lhs), condition.rhs)?,
                },
                VMTest::EQ => {
                    write!(f, "{}=={}", flag(condition.lhs), flag(condition.rhs))?;
                }
                VMTest::NEQ => {
                    write!(f, "{}!={}", flag(condition.lhs), flag(condition.rhs))?;
                }
            }
        }

        write!(f, "])")
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

    pub fn fallthrough() -> Self {
        Self::never(VMLogic::SAND)
    }

    fn always(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![VMCondition::eq(VMFlag::Zero, VMFlag::Zero)],
        }
    }

    fn never(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![VMCondition::neq(VMFlag::Zero, VMFlag::Zero)],
        }
    }
}

impl Encode for Jcc {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

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

    fn is_branch(&self) -> bool {
        true
    }
}

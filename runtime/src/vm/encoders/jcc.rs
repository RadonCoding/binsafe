use rand::seq::SliceRandom;
use rand::Rng;

use crate::mapper::{mapped, Mapper};
use crate::vm::bytecode::{VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};

mapped! {
    VMTest {
        CMP,
        EQ,
        NEQ,
    }
}

mapped! {
    VMLogic {
        AND,
        OR,
    }
}

#[derive(Debug, Clone)]
pub struct VMCondition {
    pub test: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl Encode for VMCondition {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.test), self.lhs, self.rhs]
    }
}

#[derive(Debug)]
pub struct Jcc {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
    pub destination: u32,
}

impl VMCondition {
    fn swap(&self) -> Self {
        Self {
            test: self.test,
            lhs: self.rhs,
            rhs: self.lhs,
        }
    }
}

impl Jcc {
    fn mutate(&mut self) {
        let mut rng = rand::thread_rng();

        #[cfg(debug_assertions)]
        {
            eprintln!("before:");
            eprintln!("  logic={:?}", self.logic);
            eprintln!("  conditions={:#?}", self.conditions);
        }

        self.conditions.shuffle(&mut rng);

        for condition in &mut self.conditions {
            if rng.gen() {
                *condition = condition.swap();
            }
        }

        let original = self.conditions.clone();

        match rng.gen_range(0..6) {
            0 => {}
            1 => self.conditions.extend(original),
            2 => self
                .conditions
                .extend(original.iter().map(VMCondition::swap)),
            3 => self.logic = VMLogic::AND,
            4 => self.logic = VMLogic::OR,
            _ => {
                self.conditions = self
                    .conditions
                    .iter()
                    .flat_map(|condition| match condition.test {
                        VMTest::NEQ => {
                            self.logic = VMLogic::OR;

                            vec![
                                VMCondition {
                                    test: VMTest::CMP,
                                    lhs: condition.lhs,
                                    rhs: condition.rhs,
                                },
                                VMCondition {
                                    test: VMTest::CMP,
                                    lhs: condition.rhs,
                                    rhs: condition.lhs,
                                },
                            ]
                        }

                        _ => vec![condition.clone()],
                    })
                    .collect();
            }
        }

        self.conditions.shuffle(&mut rng);

        #[cfg(debug_assertions)]
        {
            eprintln!("after:");
            eprintln!("  logic={:?}", self.logic);
            eprintln!("  conditions={:#?}", self.conditions);
        }
    }
}
impl Encode for Jcc {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        self.mutate();

        let mut bytes = vec![
            mapper.index(VMOp::Jcc),
            mapper.index(self.logic),
            self.conditions.len() as u8,
        ];

        for condition in &mut self.conditions {
            bytes.extend_from_slice(&condition.encode(mapper));
        }
        bytes.extend_from_slice(&self.destination.to_le_bytes());
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Flags]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Reg(VMReg::NBranch)]
    }
}

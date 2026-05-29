use crate::mapper::Mapper;
use crate::vm::bytecode::VMWidth;
use crate::vm::encoders::jcc::{Jcc, VMCondition, VMLogic};
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Skip {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
    pub payload: Vec<Box<dyn Encode>>,
}

impl Encode for Skip {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        let mut payload_bytes = Vec::new();
        for op in &mut self.payload {
            payload_bytes.extend(op.encode(mapper));
        }

        let offset = u8::try_from(payload_bytes.len()).unwrap();

        let mut load_imm = LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![offset],
        };
        let mut jcc = Jcc {
            logic: self.logic,
            conditions: self.conditions.clone(),
        };

        let mut bytes = load_imm.encode(mapper);
        bytes.extend(jcc.encode(mapper));
        bytes.extend(payload_bytes);
        bytes
    }

    fn reads(&self) -> Vec<Effect> {
        let mut effects = vec![Effect::Flags];
        for op in &self.payload {
            effects.extend(op.reads());
        }
        effects
    }

    fn writes(&self) -> Vec<Effect> {
        let mut effects = Vec::new();
        for op in &self.payload {
            effects.extend(op.writes());
        }
        effects
    }
}

use crate::mapper::Mapper;
use crate::vm::bytecode::{self, VMCondition, VMLogic, VMWidth};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Skip {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
    pub payload: Vec<Box<dyn Encode>>,
}

impl Encode for Skip {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut payload = Vec::new();

        for op in &self.payload {
            payload.extend(op.encode(mapper));
        }

        let mut operations = Vec::<Box<dyn Encode>>::new();
        operations.push(Box::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![u8::try_from(payload.len()).unwrap()],
        }));
        operations.push(Box::new(Jcc {
            logic: self.logic,
            conditions: self.conditions.clone(),
        }));

        let mut bytes = bytecode::assemble(mapper, &operations);
        bytes.extend(payload);
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

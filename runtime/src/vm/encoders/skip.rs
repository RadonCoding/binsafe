use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{self, VMCondition, VMLogic, VMWidth};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Skip {
    expansion: Vec<Rc<dyn Encode>>,
}

impl Skip {
    pub fn new(
        mapper: &mut Mapper,
        logic: VMLogic,
        conditions: Vec<VMCondition>,
        body: Vec<Rc<dyn Encode>>,
    ) -> Self {
        let length = u8::try_from(body.iter().map(|op| op.size(mapper)).sum::<usize>()).unwrap();

        let mut expansion = Vec::new();

        expansion.push(Rc::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![length],
        }) as Rc<dyn Encode>);

        expansion.push(Rc::new(Jcc { logic, conditions }));

        expansion.extend(body);

        Self { expansion }
    }
}

impl Encode for Skip {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        bytecode::assemble(mapper, &self.expansion)
    }

    fn size(&self, mapper: &mut Mapper) -> usize {
        self.expansion.iter().map(|op| op.size(mapper)).sum()
    }

    fn reads(&self) -> Vec<Effect> {
        self.expansion.iter().flat_map(|op| op.reads()).collect()
    }

    fn writes(&self) -> Vec<Effect> {
        self.expansion.iter().flat_map(|op| op.writes()).collect()
    }

    fn depth(&self) -> i32 {
        self.expansion.iter().map(|op| op.depth()).sum()
    }

    fn branches(&self) -> bool {
        true
    }

    fn children(&mut self) -> Option<&mut Vec<Rc<dyn Encode>>> {
        Some(&mut self.expansion)
    }
}

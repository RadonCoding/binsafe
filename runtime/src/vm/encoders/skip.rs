use crate::mapper::Mapper;
use crate::vm::bytecode::{self, VMCondition, VMLogic, VMWidth};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct Skip {
    expansion: Vec<Box<dyn Encode>>,
}

impl Skip {
    pub fn new(
        _mapper: &mut Mapper,
        logic: VMLogic,
        conditions: Vec<VMCondition>,
        body: Vec<Box<dyn Encode>>,
    ) -> Self {
        let mut expansion = Vec::with_capacity(2 + body.len());
        expansion.push(Box::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![0],
        }) as Box<dyn Encode>);
        expansion.push(Box::new(Jcc { logic, conditions }) as Box<dyn Encode>);
        expansion.extend(body);

        Self { expansion }
    }
}

impl Encode for Skip {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

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

    fn children_ref(&self) -> Option<&[Box<dyn Encode>]> {
        Some(&self.expansion)
    }

    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Encode>>> {
        Some(&mut self.expansion)
    }

    fn seal(&mut self, mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8], usize)) {
        let index = self
            .expansion
            .iter()
            .position(|op| op.as_any().downcast_ref::<Jcc>().is_some())
            .unwrap();

        let length = self.expansion[index + 1..]
            .iter()
            .map(|op| op.size(mapper))
            .sum::<usize>();

        let (width, mut source) = if let Ok(value) = u8::try_from(length) {
            (VMWidth::Lower8, value.to_le_bytes().to_vec())
        } else if let Ok(value) = u16::try_from(length) {
            (VMWidth::Lower16, value.to_le_bytes().to_vec())
        } else {
            (
                VMWidth::Lower32,
                u32::try_from(length).unwrap().to_le_bytes().to_vec(),
            )
        };

        transform(&mut source, 0);

        let load = self.expansion[0]
            .as_any_mut()
            .downcast_mut::<LoadImmediate>()
            .unwrap();
        load.width = width;
        load.source = source;
    }
}

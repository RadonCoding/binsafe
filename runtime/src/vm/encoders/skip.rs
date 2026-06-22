use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{self, VMCondition, VMLogic, VMWidth};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Skip {
    pub expansion: Vec<Rc<dyn Encode>>,
    width: VMWidth,
    source: Vec<u8>,
}

impl Skip {
    pub fn new(
        _mapper: &mut Mapper,
        logic: VMLogic,
        conditions: Vec<VMCondition>,
        body: Vec<Rc<dyn Encode>>,
    ) -> Self {
        let mut expansion = Vec::with_capacity(1 + body.len());
        expansion.push(Rc::new(Jcc { logic, conditions }) as Rc<dyn Encode>);
        expansion.extend(body);

        Self {
            expansion,
            width: VMWidth::Lower8,
            source: vec![0],
        }
    }
}

impl Encode for Skip {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let header = LoadImmediate {
            width: self.width,
            source: self.source.clone(),
        };

        let mut bytes = header.encode(mapper);
        bytes.extend(bytecode::assemble(mapper, &self.expansion));
        bytes
    }

    fn size(&self, mapper: &mut Mapper) -> usize {
        let body = self.expansion[1..]
            .iter()
            .map(|op| op.size(mapper))
            .sum::<usize>();

        let header = if body <= u8::MAX as usize {
            3 // +2 for opcode +1 for immediate
        } else if body <= u16::MAX as usize {
            4 // +2 for opcode +2 for immediate
        } else {
            6 // +2 for opcode +4 for immediate
        };

        let jcc = self.expansion[0].size(mapper);

        header + jcc + body
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

    fn seal(&mut self, mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8])) {
        let length = self.expansion[1..]
            .iter()
            .map(|op| op.size(mapper))
            .sum::<usize>();

        let (width, mut source) = if length <= u8::MAX as usize {
            (VMWidth::Lower8, vec![length as u8])
        } else {
            (
                VMWidth::Lower16,
                u16::try_from(length).unwrap().to_le_bytes().to_vec(),
            )
        };

        transform(&mut source);

        self.width = width;
        self.source = source;
    }
}

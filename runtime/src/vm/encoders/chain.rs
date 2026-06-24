use std::any::Any;

use crate::mapper::Mapper;
use crate::vm::bytecode::{self};
use crate::vm::encoders::label::Label;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Chain {
    operations: Vec<Box<dyn Encode>>,
    jumps: Vec<Jump>,
}

#[derive(Debug)]
pub struct Jump {
    pub source: Label,
    pub destination: Target,
}

#[derive(Debug)]
pub enum Target {
    Label(Label),
    End,
}

impl Chain {
    pub fn new(operations: Vec<Box<dyn Encode>>, jumps: Vec<Jump>) -> Self {
        Self { operations, jumps }
    }

    fn position(
        &self,
        mapper: &mut Mapper,
        operations: Option<&[Box<dyn Encode>]>,
        label: usize,
    ) -> Option<usize> {
        let mut offset = 0;

        for operation in operations.unwrap_or(&self.operations) {
            if let Some(target) = operation.as_any().downcast_ref::<Label>() {
                if target.id() == label {
                    return Some(offset);
                }
            }

            if let Some(children) = operation.children_ref() {
                if let Some(position) = self.position(mapper, Some(children), label) {
                    return Some(offset + position);
                }
            }

            offset += operation.size(mapper);
        }

        None
    }
}

impl Encode for Chain {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        bytecode::assemble(mapper, &self.operations)
    }

    fn size(&self, mapper: &mut Mapper) -> usize {
        self.operations.iter().map(|op| op.size(mapper)).sum()
    }

    fn reads(&self) -> Vec<Effect> {
        self.operations.iter().flat_map(|op| op.reads()).collect()
    }

    fn writes(&self) -> Vec<Effect> {
        self.operations.iter().flat_map(|op| op.writes()).collect()
    }

    fn depth(&self) -> i32 {
        self.operations.iter().map(|op| op.depth()).sum()
    }

    fn children_ref(&self) -> Option<&[Box<dyn Encode>]> {
        Some(&self.operations)
    }

    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Encode>>> {
        Some(&mut self.operations)
    }

    fn seal(&mut self, mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8])) {
        for jump in &self.jumps {
            let index = self
                .operations
                .iter()
                .position(|op| {
                    op.as_any()
                        .downcast_ref::<Label>()
                        .map_or(false, |l| l.id() == jump.source.id())
                })
                .unwrap();

            let source = self.operations[..index]
                .iter()
                .map(|op| op.size(mapper))
                .sum::<usize>();

            let after = source
                + self.operations[index + 1].size(mapper)
                + self.operations[index + 2].size(mapper);

            let target = match jump.destination {
                Target::Label(label) => self.position(mapper, None, label.id()).unwrap(),
                Target::End => self.size(mapper),
            };

            let offset = i16::try_from(target as isize - after as isize).unwrap();

            let mut bytes = offset.to_le_bytes().to_vec();

            transform(&mut bytes);

            let load = self.operations[index + 1]
                .as_any_mut()
                .downcast_mut::<LoadImmediate>()
                .unwrap();
            load.source = bytes;
        }
    }
}

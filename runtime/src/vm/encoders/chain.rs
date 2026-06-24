use std::any::Any;

use crate::mapper::Mapper;
use crate::vm::bytecode;
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
    pub source: usize,
    pub destination: Target,
}

#[derive(Debug)]
pub enum Target {
    Label(usize),
    End,
}

impl Chain {
    pub fn new(operations: Vec<Box<dyn Encode>>, jumps: Vec<Jump>) -> Self {
        Self { operations, jumps }
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

    fn branches(&self) -> bool {
        true
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
                .position(|op| op.id() == jump.source)
                .unwrap();

            let mut source = 0;

            for operation in &self.operations {
                if operation.id() == jump.source {
                    break;
                }

                source += operation.size(mapper);
            }

            let after = source
                + self.operations[index].size(mapper)
                + self.operations[index + 1].size(mapper);

            let target = match jump.destination {
                Target::Label(id) => position(&self.operations, id, mapper).unwrap(),
                Target::End => self.size(mapper),
            };

            let offset = i16::try_from(target as isize - after as isize).unwrap();

            let mut bytes = offset.to_le_bytes().to_vec();

            transform(&mut bytes);

            let any = self.operations[index].as_mut() as &mut dyn Any;
            let load = any.downcast_mut::<LoadImmediate>().unwrap();
            load.source = bytes;
        }
    }
}

fn position(operations: &[Box<dyn Encode>], label: usize, mapper: &mut Mapper) -> Option<usize> {
    let mut offset = 0;

    for operation in operations {
        if let Some(target) = operation.as_any().downcast_ref::<Label>() {
            if target.id() == label {
                return Some(offset);
            }
        }

        if let Some(children) = operation.children_ref() {
            if let Some(position) = position(children, label, mapper) {
                return Some(offset + position);
            }
        }

        offset += operation.size(mapper);
    }

    None
}

use std::any::Any;

use crate::mapper::Mapper;
use crate::vm::bytecode;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

/// [`Jump`]-paired operations referenced by index, with offsets recomputed at [`Chain::seal`].
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
    Operation(usize),
    End,
}

impl Chain {
    pub fn new(operations: Vec<Box<dyn Encode>>, jumps: Vec<Jump>) -> Self {
        Self { operations, jumps }
    }
}

impl Encode for Chain {
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
        let n = self.operations.len();

        let mut positions = vec![0usize; n + 1];

        let mut cursor = 0;

        for i in 0..n {
            positions[i] = cursor;
            cursor += self.operations[i].size(mapper);
        }

        positions[n] = cursor;

        for jump in &self.jumps {
            let after = positions[jump.source]
                + self.operations[jump.source].size(mapper)
                + self.operations[jump.source + 1].size(mapper);

            let target = match jump.destination {
                Target::Operation(index) => positions[index],
                Target::End => positions[n],
            };

            let offset = i16::try_from(target as isize - after as isize).unwrap();

            let mut source = offset.to_le_bytes().to_vec();
            transform(&mut source);

            let any: &mut dyn Any = self.operations[jump.source].as_mut();
            let load = any.downcast_mut::<LoadImmediate>().unwrap();
            load.source = source;
        }
    }
}

use std::any::Any;

use crate::mapper::Mapper;
use crate::vm::bytecode::{self, VMCondition, VMLogic, VMWidth};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::label::Label;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Block {
    body: Vec<Box<dyn Encode>>,
    pub jumps: Vec<Jump>,
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

impl Block {
    pub fn new(body: Vec<Box<dyn Encode>>, jumps: Vec<Jump>) -> Self {
        Self { body, jumps }
    }

    pub fn skip(
        logic: VMLogic,
        conditions: Vec<VMCondition>,
        mut body: Vec<Box<dyn Encode>>,
    ) -> Block {
        let source = Label::source();

        body.insert(0, Box::new(source));
        body.insert(
            1,
            Box::new(LoadImmediate {
                width: VMWidth::SLower8,
                source: vec![0],
            }),
        );
        body.insert(2, Box::new(Jcc { logic, conditions }));

        let jumps = vec![Jump {
            source,
            destination: Target::End,
        }];

        Self::new(body, jumps)
    }

    fn position(
        &self,
        mapper: &mut Mapper,
        operations: Option<&[Box<dyn Encode>]>,
        label: usize,
    ) -> Option<usize> {
        let mut offset = 0;

        for operation in operations.unwrap_or(&self.body) {
            if let Some(target) = operation.as_any().downcast_ref::<Label>() {
                if target.id() == label {
                    return Some(offset);
                }
            }

            offset += operation.size(mapper);
        }

        None
    }

    fn indices(&self, label: usize) -> Option<(usize, usize)> {
        let index = self.body.iter().position(|operation| {
            operation
                .as_any()
                .downcast_ref::<Label>()
                .map_or(false, |l| l.id() == label)
        })?;

        let mut stack = Vec::new();

        for i in index + 1..self.body.len() {
            let operation = &self.body[i];

            if operation.as_any().downcast_ref::<Jcc>().is_some() {
                if stack.len() == 1 {
                    return Some((stack[0], i));
                }
            }

            let delta = operation.depth();

            if delta > 0 {
                for _ in 0..delta {
                    stack.push(i);
                }
            } else {
                for _ in 0..(-delta) {
                    stack.pop();
                }
            }
        }

        unreachable!()
    }
}

impl Encode for Block {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        bytecode::assemble(mapper, &self.body)
    }

    fn size(&self, mapper: &mut Mapper) -> usize {
        self.body.iter().map(|op| op.size(mapper)).sum()
    }

    fn reads(&self) -> Vec<Effect> {
        self.body.iter().flat_map(|op| op.reads()).collect()
    }

    fn writes(&self) -> Vec<Effect> {
        self.body.iter().flat_map(|op| op.writes()).collect()
    }

    fn depth(&self) -> i32 {
        self.body.iter().map(|op| op.depth()).sum()
    }

    fn children_ref(&self) -> Option<&[Box<dyn Encode>]> {
        Some(&self.body)
    }

    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Encode>>> {
        Some(&mut self.body)
    }

    fn seal(&mut self, mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8], usize)) {
        let mut changed = true;

        while changed {
            changed = false;

            for i in 0..self.jumps.len() {
                let source_label = self.jumps[i].source.id();
                let destination_label = match &self.jumps[i].destination {
                    Target::Label(label) => Some(label.id()),
                    Target::End => None,
                };

                let Some((load_index, branch_index)) = self.indices(source_label) else {
                    continue;
                };

                let destination = if let Some(destination) = destination_label {
                    self.position(mapper, None, destination).unwrap()
                } else {
                    self.size(mapper)
                };

                let after = self.body[..=branch_index]
                    .iter()
                    .map(|op| op.size(mapper))
                    .sum::<usize>();

                let offset = destination as isize - after as isize;

                let load = self.body[load_index]
                    .as_any_mut()
                    .downcast_mut::<LoadImmediate>()
                    .unwrap();

                let width = match load.width {
                    VMWidth::SLower8 if i8::try_from(offset).is_err() => Some(VMWidth::SLower16),
                    VMWidth::SLower16 if i16::try_from(offset).is_err() => Some(VMWidth::SLower32),
                    _ => None,
                };

                if let Some(width) = width {
                    load.width = width.clone();
                    load.source = match width {
                        VMWidth::SLower8 => vec![0],
                        VMWidth::SLower16 => vec![0, 0],
                        VMWidth::SLower32 => vec![0, 0, 0, 0],
                        _ => unreachable!(),
                    };
                    changed = true;
                }
            }
        }

        for i in 0..self.jumps.len() {
            let source_label = self.jumps[i].source.id();
            let destination_label = match &self.jumps[i].destination {
                Target::Label(label) => Some(label.id()),
                Target::End => None,
            };

            let Some((load_index, branch_index)) = self.indices(source_label) else {
                continue;
            };

            let destination = if let Some(label) = destination_label {
                self.position(mapper, None, label).unwrap()
            } else {
                self.size(mapper)
            };

            let after = self.body[..=branch_index]
                .iter()
                .map(|op| op.size(mapper))
                .sum::<usize>();

            let offset = destination as isize - after as isize;

            let load = self.body[load_index]
                .as_any_mut()
                .downcast_mut::<LoadImmediate>()
                .unwrap();

            let mut source = match load.width {
                VMWidth::SLower8 => (offset as i8).to_le_bytes().to_vec(),
                VMWidth::SLower16 => (offset as i16).to_le_bytes().to_vec(),
                VMWidth::SLower32 => (offset as i32).to_le_bytes().to_vec(),
                _ => unreachable!(),
            };

            transform(&mut source, load_index);

            load.source = source;
        }
    }
}

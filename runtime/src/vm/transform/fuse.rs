use std::mem;

use crate::runtime::Runtime;
use crate::vm::bytecode::VMCode;
use crate::vm::encoders::compound::Compound;
use crate::vm::encoders::Encode;
use crate::vm::transform::{descend, Phase, Transform};

pub struct Fuse {
    pub register: bool,
}

impl Transform for Fuse {
    fn phase(&self) -> Phase {
        Phase::Fuse
    }

    fn run(&self, rt: &mut Runtime, mut operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
        descend(&mut operations, |operations| {
            let fusible = operations
                .iter()
                .map(|operation| {
                    !operation.is_branch()
                        && operation
                            .code()
                            .is_some_and(|code| !matches!(code, VMCode::Compound))
                })
                .collect::<Vec<bool>>();

            let codes = operations
                .iter()
                .map(|operation| operation.code())
                .collect::<Vec<Option<VMCode>>>();

            let mut planned = Vec::new();
            let mut cursor = 0;

            while cursor < codes.len() {
                let mut chosen = None;

                let limit = codes.len() - cursor;

                for length in (2..=limit).rev() {
                    if !fusible[cursor..cursor + length]
                        .iter()
                        .all(|&fusible| fusible)
                    {
                        continue;
                    }

                    let members = codes[cursor..cursor + length]
                        .iter()
                        .map(|code| code.unwrap())
                        .collect::<Vec<VMCode>>();

                    if let Some(index) = rt.compounds.iter().position(|entry| *entry == members) {
                        chosen = Some((length, index));
                        break;
                    }

                    if self.register {
                        chosen = Some((length, rt.compound(members)));
                        break;
                    }
                }

                match chosen {
                    Some((length, index)) => {
                        planned.push((length, Some(index)));
                        cursor += length;
                    }
                    None => {
                        planned.push((1, None));
                        cursor += 1;
                    }
                }
            }

            let mut source = mem::take(operations).into_iter();

            for (length, index) in planned {
                match index {
                    Some(index) => {
                        let members = (0..length).map(|_| source.next().unwrap()).collect();
                        operations.push(Box::new(Compound { index, members }));
                    }
                    None => operations.push(source.next().unwrap()),
                }
            }
        });

        operations
    }
}

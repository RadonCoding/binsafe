use std::mem;

use rand::seq::SliceRandom;
use rand::Rng;

use crate::vm::bytecode::VMWidth;
use crate::vm::encoders::block::{Block, Jump, Target};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::label::Label;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::Encode;
use crate::vm::transform::atomize;

/// Shuffles the physical order of atoms by chaining them in execution order through signed-offset [`Jcc`]s.
pub fn scramble(mut operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
    walk(&mut operations);

    operations
}

/// Recurses into children, scrambling any [`Block`] found along the way before wrapping its own level.
fn walk(operations: &mut Vec<Box<dyn Encode>>) {
    for operation in operations.iter_mut() {
        if let Some(block) = operation.as_any_mut().downcast_mut::<Block>() {
            reorder(block);
        } else if let Some(children) = operation.children_mut() {
            walk(children);
        }
    }

    let mut block = Block::new(mem::take(operations), vec![]);
    reorder(&mut block);
    operations.push(Box::new(block));
}

/// Atomizes and chains a [`Block`]'s children, rewriting it in place.
fn reorder(block: &mut Block) {
    let mut atoms = atomize(mem::take(block.children_mut().unwrap()));

    if atoms.len() > 1 {
        block.jumps.extend(chain(&mut atoms));
    }

    *block.children_mut().unwrap() = atoms.into_iter().flatten().collect();
}

/// Places atoms in physical order with a [`Jump`] chain, falling through where order already agrees.
fn chain(atoms: &mut Vec<Vec<Box<dyn Encode>>>) -> Vec<Jump> {
    let count = atoms.len();

    let mut rng = rand::thread_rng();

    let mut groups = Vec::new();

    let mut group = Vec::new();

    for i in 0..count {
        group.push(i);

        if i + 1 == count || rng.gen_bool(0.5) {
            groups.push(mem::take(&mut group));
        }
    }

    let end = groups.pop().unwrap();
    groups.shuffle(&mut rng);
    groups.push(end);

    let order = groups.into_iter().flatten().collect::<Vec<usize>>();

    let mut anchors = vec![None; count];

    for (i, atom) in atoms.iter().enumerate() {
        anchors[i] = atom
            .first()
            .and_then(|op| op.as_any().downcast_ref::<Label>())
            .copied();
    }

    let mut reordered = Vec::with_capacity(count);

    for &i in &order {
        reordered.push(mem::take(&mut atoms[i]));
    }

    *atoms = reordered;

    for (k, &i) in order.iter().enumerate() {
        if anchors[i].is_none() {
            let anchor = Label::destination();
            anchors[i] = Some(anchor);
            atoms[k].insert(0, Box::new(anchor));
        }
    }

    let mut pending = Vec::with_capacity(count - 1);

    if order[0] != 0 {
        let (source, procedure) = placeholder(false);
        atoms[0].splice(0..0, procedure);
        pending.push((source, Some(0)));
    }

    for (k, &i) in order.iter().enumerate() {
        let successor = (i + 1 < count).then_some(i + 1);

        let fallthrough = successor
            .map(|next| k + 1 < count && order[k + 1] == next)
            .unwrap_or(false);

        if successor.is_none() {
            continue;
        }

        let (source, procedure) = placeholder(fallthrough);

        atoms[k].extend(procedure);

        pending.push((source, successor));
    }

    pending
        .into_iter()
        .map(|(source, successor)| Jump {
            source,
            destination: match successor {
                Some(index) => Target::Label(anchors[index].unwrap()),
                None => Target::End,
            },
        })
        .collect()
}

/// Placeholder signed-offset [`LoadImmediate`] paired with a [`Jcc`] and [`Block::seal`] rewrites the offset bytes, skipping if `fallthrough` else never taken.
fn placeholder(fallthrough: bool) -> (Label, Vec<Box<dyn Encode>>) {
    let source = Label::source();

    let mut procedure = Vec::<Box<dyn Encode>>::new();
    procedure.push(Box::new(source));
    procedure.push(Box::new(LoadImmediate {
        width: VMWidth::SLower8,
        source: vec![0],
    }));
    procedure.push(Box::new(if fallthrough {
        Jcc::fallthrough()
    } else {
        Jcc::skip()
    }));

    (source, procedure)
}

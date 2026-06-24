use std::mem;

use crate::mapper::Mapper;
use crate::vm::bytecode::VMReg;
use crate::vm::encoders::chain::Chain;
use crate::vm::encoders::label::Label;
use crate::vm::{
    bytecode::Phase,
    encoders::{Effect, Encode},
};

pub mod encrypt;
pub mod mutation;
pub mod peephole;
pub mod permute;
pub mod scramble;

pub trait Transform {
    fn phase(&self) -> Phase;

    fn run(&self, mapper: &mut Mapper, operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>>;
}

/// Groups operations into depth-balanced atoms, appending any trailing unbalanced run as a final atom.
pub fn atomize(operations: Vec<Box<dyn Encode>>) -> Vec<Vec<Box<dyn Encode>>> {
    let mut atoms = Vec::new();
    let mut current = Vec::new();

    let mut depth = 0;

    let mut label = false;

    for operation in operations {
        if operation.as_any().is::<Label>() {
            label = true;
        }

        depth += operation.depth();
        current.push(operation);

        if depth == 0 && !label {
            atoms.push(mem::take(&mut current));
            label = false;
        }
    }
    if !current.is_empty() {
        atoms.push(current);
    }
    atoms
}

/// Recursively descends into [`Encode::children`], applying `f` to each level after its children have been processed.
pub fn descend<F>(operations: &mut Vec<Box<dyn Encode>>, mut f: F)
where
    F: FnMut(&mut Vec<Box<dyn Encode>>),
{
    fn go<F: FnMut(&mut Vec<Box<dyn Encode>>)>(operations: &mut Vec<Box<dyn Encode>>, f: &mut F) {
        for operation in operations.iter_mut() {
            if operation.as_any().downcast_ref::<Chain>().is_some() {
                // continue;
            }

            if let Some(children) = operation.children_mut() {
                go(children, f);
            }
        }

        f(operations);
    }

    go(operations, &mut f);
}

/// Per-leaf deadzone mask computed against `effect` via a backward live-variable walk over the leaves.
pub fn deadzones(
    operations: &mut [Box<dyn Encode>],
    effect: impl Fn(&Effect) -> bool,
) -> Vec<bool> {
    let mut events = Vec::new();

    scan(operations, &mut events, &effect);

    let mut deadzones = vec![false; events.len()];

    let mut live = true;

    for (i, (reads, writes)) in events.iter().enumerate().rev() {
        if *writes {
            live = false;
        }
        if !live {
            deadzones[i] = true;
        }
        if *reads {
            live = true;
        }
    }

    deadzones
}

/// Records each leaf's read/write flags for `effect`, recursing through children.
fn scan(
    operations: &mut [Box<dyn Encode>],
    events: &mut Vec<(bool, bool)>,
    effect: &impl Fn(&Effect) -> bool,
) {
    for op in operations.iter_mut() {
        if let Some(children) = op.children_mut() {
            scan(children, events, effect);
            continue;
        }

        let reads = op.reads().iter().any(effect);
        let writes = op.writes().iter().any(effect);

        events.push((reads, writes));
    }
}

/// Whether `register` is written before it is read in the slice.
fn overwritten(operations: &[Box<dyn Encode>], register: VMReg) -> bool {
    for operation in operations {
        // Check if conditional since writes inside are not guaranteed
        if operation.branches() {
            if operation
                .reads()
                .iter()
                .any(|effect| matches!(effect, Effect::Register(r) if *r == register))
            {
                return false;
            }
            continue;
        }

        if operation
            .writes()
            .iter()
            .any(|effect| matches!(effect, Effect::Register(r) if *r == register))
        {
            return true;
        }

        if operation
            .reads()
            .iter()
            .any(|effect| matches!(effect, Effect::Register(r) if *r == register))
        {
            return false;
        }
    }
    false
}

/// Whether the given atom contains a branch.
fn branches(atom: &Vec<Box<dyn Encode>>) -> bool {
    atom.iter().any(|op| op.branches())
}

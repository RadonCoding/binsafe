use std::rc::Rc;

use crate::mapper::Mapper;
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

    fn run(&self, mapper: &mut Mapper, operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>>;
}

/// Groups operations into depth-balanced atoms, appending any trailing unbalanced run as a final atom.
pub fn atomize(operations: Vec<Rc<dyn Encode>>) -> Vec<Vec<Rc<dyn Encode>>> {
    let mut atoms = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0;

    for op in operations {
        depth += op.depth();
        current.push(op);
        if depth == 0 {
            atoms.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        atoms.push(current);
    }
    atoms
}

/// Stable identity for a refcounted operation.
pub fn address(op: &Rc<dyn Encode>) -> usize {
    &**op as *const dyn Encode as *const () as usize
}

/// Recursively descends into [`Encode::children`], applying `f` to each level after its children have been processed.
pub fn descend<F>(operations: &mut [Rc<dyn Encode>], mut f: F)
where
    F: FnMut(&mut [Rc<dyn Encode>]),
{
    fn go<F: FnMut(&mut [Rc<dyn Encode>])>(operations: &mut [Rc<dyn Encode>], f: &mut F) {
        for op in operations.iter_mut() {
            if let Some(children) = Rc::get_mut(op).unwrap().children() {
                go(children, f);
            }
        }
        f(operations);
    }

    go(operations, &mut f);
}

/// Per-leaf deadzone mask computed against `effect` via a backward live-variable walk over the leaves.
pub fn deadzones(operations: &mut [Rc<dyn Encode>], effect: impl Fn(&Effect) -> bool) -> Vec<bool> {
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
    operations: &mut [Rc<dyn Encode>],
    events: &mut Vec<(bool, bool)>,
    effect: &impl Fn(&Effect) -> bool,
) {
    for op in operations.iter_mut() {
        if let Some(children) = Rc::get_mut(op).unwrap().children() {
            scan(children, events, effect);

            continue;
        }

        let reads = op.reads().iter().any(effect);
        let writes = op.writes().iter().any(effect);

        events.push((reads, writes));
    }
}

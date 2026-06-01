use std::rc::Rc;

use crate::vm::{
    bytecode::Phase,
    encoders::{Effect, Encode},
};

pub mod encrypt;
pub mod mutation;
pub mod permute;

pub trait Transform {
    fn phase(&self) -> Phase;

    fn run(&self, operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>>;
}

/// Recursively descends into [`Encode::children`], applying `f` to each level after its children have been processed.
pub fn descend<F>(operations: &mut Vec<Rc<dyn Encode>>, mut f: F)
where
    F: FnMut(&mut Vec<Rc<dyn Encode>>),
{
    fn go<F: FnMut(&mut Vec<Rc<dyn Encode>>)>(operations: &mut Vec<Rc<dyn Encode>>, f: &mut F) {
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
pub fn deadzones(
    operations: &mut Vec<Rc<dyn Encode>>,
    effect: impl Fn(&Effect) -> bool,
) -> Vec<bool> {
    let mut events = Vec::new();

    scan(operations, &mut events, &effect);

    let mut deadzones = vec![false; events.len()];
    let mut live = true;

    for (i, (reads, writes)) in events.iter().enumerate().rev() {
        if *reads {
            live = true;
        }
        if !live {
            deadzones[i] = true;
        }
        if *writes {
            live = false;
        }
    }

    deadzones
}

/// Records each leaf's read/write flags for `effect`, recursing through children.
fn scan(
    operations: &mut Vec<Rc<dyn Encode>>,
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

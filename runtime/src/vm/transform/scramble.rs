use std::rc::Rc;

use rand::seq::SliceRandom;
use rand::Rng;

use crate::mapper::Mapper;
use crate::vm::bytecode::VMWidth;
use crate::vm::encoders::chain::{Chain, Jump, Target};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::skip::Skip;
use crate::vm::encoders::Encode;
use crate::vm::transform::atomize;

/// Shuffles the physical order of atoms by chaining them in execution order through signed-offset [`Jcc`]s inside a [`Skip`] body.
pub fn scramble(mapper: &mut Mapper, operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
    let atoms = atomize(operations);

    let cut = atoms
        .iter()
        .rposition(|atom| atom.iter().any(|op| op.branches()))
        .unwrap_or(atoms.len());

    let (head, tail) = atoms.split_at(cut);

    if head.len() < 2 {
        return atoms.into_iter().flatten().collect();
    }

    let mut rng = rand::thread_rng();

    let mut result = chain(mapper, head.to_vec(), &mut rng);

    for atom in tail {
        result.extend(atom.iter().cloned());
    }
    result
}

/// Places atoms in physical order with a top-level jump into a [`Skip`] execution chain.
fn chain<R: Rng>(
    mapper: &mut Mapper,
    head: Vec<Vec<Rc<dyn Encode>>>,
    rng: &mut R,
) -> Vec<Rc<dyn Encode>> {
    let n = head.len();

    let mut shuffle = (1..n).collect::<Vec<usize>>();
    shuffle.shuffle(rng);

    let mut operations = Vec::<Rc<dyn Encode>>::new();
    let mut anchors = vec![0; n];
    let mut pending = Vec::<(usize, Option<usize>)>::new();

    pending.push((operations.len(), Some(1)));

    operations.extend(jump());

    for k in 0..(n - 1) {
        let i = shuffle[k];

        anchors[i] = operations.len();

        operations.extend(head[i].clone());

        let successor = if i + 1 == n { None } else { Some(i + 1) };
        pending.push((operations.len(), successor));
        operations.extend(jump());
    }

    let jumps = pending
        .into_iter()
        .map(|(at, successor)| Jump {
            source: at,
            destination: match successor {
                Some(index) => Target::Operation(anchors[index]),
                None => Target::End,
            },
        })
        .collect();

    let chain = Chain::new(operations, jumps);
    let pass = Jcc::pass();
    let skip = Skip::new(
        mapper,
        pass.logic,
        pass.conditions,
        vec![Rc::new(chain) as Rc<dyn Encode>],
    );

    let mut result = Vec::<Rc<dyn Encode>>::new();
    result.extend(head[0].clone());
    result.push(Rc::new(skip));
    result
}

/// Placeholder signed-offset [`LoadImmediate`] paired with an always-skip [`Jcc`]; [`Chain::seal`] rewrites the offset bytes.
fn jump() -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadImmediate {
            width: VMWidth::SLower16,
            source: vec![0, 0],
        }),
        Rc::new(Jcc::skip()),
    ]
}

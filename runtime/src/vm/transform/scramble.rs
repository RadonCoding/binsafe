use std::mem;

use rand::seq::SliceRandom;
use rand::Rng;

use crate::mapper::Mapper;
use crate::vm::bytecode::VMWidth;
use crate::vm::encoders::chain::{Chain, Jump, Target};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::label::Label;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::skip::Skip;
use crate::vm::encoders::Encode;
use crate::vm::transform::{atomize, descend};

/// Shuffles the physical order of atoms by chaining them in execution order through signed-offset [`Jcc`]s inside a [`Skip`] body.
pub fn scramble(mapper: &mut Mapper, mut operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
    descend(&mut operations, |operations| {
        let current = mem::take(operations);

        let mut atoms = atomize(current);

        let cut = atoms
            .iter()
            .rposition(|atom| atom.iter().any(|op| op.branches()))
            .unwrap_or(atoms.len());

        let tail = atoms.split_off(cut);

        if atoms.len() < 2 {
            atoms.extend(tail);
            *operations = atoms.into_iter().flatten().collect();
            return;
        }

        let mut rng = rand::thread_rng();

        let mut result = chain(mapper, atoms, &mut rng);
        result.extend(tail.into_iter().flatten());
        *operations = result;
    });

    operations
}

/// Places atoms in physical order with a top-level jump into a [`Skip`] execution chain.
fn chain<R: Rng>(
    mapper: &mut Mapper,
    mut head: Vec<Vec<Box<dyn Encode>>>,
    rng: &mut R,
) -> Vec<Box<dyn Encode>> {
    let count = head.len();

    let mut shuffle = (1..count).collect::<Vec<usize>>();
    shuffle.shuffle(rng);

    let mut operations = Vec::<Box<dyn Encode>>::new();
    let mut anchors = vec![0; count];
    let mut pending = Vec::<(usize, Option<usize>)>::new();

    let entry = Label::new();
    operations.push(Box::new(entry));
    operations.extend(jump());
    pending.push((operations[1].id(), Some(1)));

    for k in 0..(count - 1) {
        let i = shuffle[k];

        let label = Label::new();
        anchors[i] = label.id();
        operations.push(Box::new(label));

        operations.extend(head[i].drain(..));

        let source = operations.len();
        operations.extend(jump());
        let successor = if i + 1 == count { None } else { Some(i + 1) };
        pending.push((operations[source].id(), successor));
    }

    let jumps = pending
        .into_iter()
        .map(|(source, successor)| Jump {
            source,
            destination: match successor {
                Some(index) => Target::Label(anchors[index]),
                None => Target::End,
            },
        })
        .collect();

    let chain = Chain::new(operations, jumps);
    let pass = Jcc::pass();
    let skip = Skip::new(mapper, pass.logic, pass.conditions, vec![Box::new(chain)]);

    let mut result = Vec::new();
    result.extend(head[0].drain(..));
    result.push(Box::new(skip));

    result
}

/// Placeholder signed-offset [`LoadImmediate`] paired with an always-skip [`Jcc`] and [`Chain::seal`] rewrites the offset bytes.
fn jump() -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadImmediate {
            width: VMWidth::SLower16,
            source: vec![0, 0],
        }),
        Box::new(Jcc::skip()),
    ]
}

use rand::Rng;
use std::any::TypeId;
use std::collections::HashSet;
use std::mem;

use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{Effect, Encode};

type Atom = Vec<Box<dyn Encode>>;

/// Shuffles operations into a randomized but semantically equivalent sequence.
pub fn permute(operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
    let mut atoms = atomize(operations);

    preserve(&mut atoms);

    let mut operations = schedule(atoms).into_iter().flatten().collect();

    cleanup(&mut operations);

    operations
}

/// Groups operations into atoms where each atom leaves the scratch stack balanced.
fn atomize(operations: Vec<Box<dyn Encode>>) -> Vec<Atom> {
    let mut atoms = Vec::new();
    let mut atom = Atom::new();
    let mut depth = 0;

    for operation in operations {
        depth += stores_minus_loads(&*operation);

        atom.push(operation);

        if depth == 0 {
            atoms.push(mem::take(&mut atom));
        }
    }

    atoms
}

/// Inserts [`VMReg::Flags`] save/restore instructions so flag state survives atom reordering.
fn preserve(atoms: &mut [Atom]) {
    let brancher = match atoms.iter().rposition(is_branch) {
        Some(b) => b,
        None => return,
    };
    let flagger = match atoms[..brancher].iter().rposition(writes_flags) {
        Some(l) => l,
        None => return,
    };

    // Push flags onto scratch stack immediately after the atom that sets them
    atoms[flagger].push(Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: VMReg::Flags,
    }));

    // Pop flags from scratch stack immediately before the branch
    atoms[brancher].insert(
        0,
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }),
    );
}

/// Topologically sorts atoms respecting data dependencies, randomizing where order is free.
fn schedule(mut atoms: Vec<Atom>) -> Vec<Atom> {
    let trailing = match atoms.iter().rposition(is_branch) {
        Some(i) => atoms.split_off(i),
        None => Vec::new(),
    };

    let n = atoms.len();
    let mut indegree = vec![0usize; n];
    let mut successors = vec![Vec::new(); n];

    for i in 0..n {
        for j in 0..i {
            if conflicts(&atoms[j], &atoms[i]) {
                successors[j].push(i);
                indegree[i] += 1;
            }
        }
    }

    let mut ready = (0..n).filter(|&i| indegree[i] == 0).collect::<Vec<usize>>();
    let mut order = Vec::with_capacity(n);
    let mut rng = rand::thread_rng();

    while !ready.is_empty() {
        let pick = ready.swap_remove(rng.gen_range(0..ready.len()));
        order.push(pick);
        for &next in &successors[pick] {
            indegree[next] -= 1;
            if indegree[next] == 0 {
                ready.push(next);
            }
        }
    }

    let mut taken = atoms.into_iter().map(Some).collect::<Vec<Option<Atom>>>();

    order
        .into_iter()
        .map(|i| taken[i].take().unwrap())
        .chain(trailing)
        .collect()
}

/// Removes redundant [`LoadRegister`] [`StoreRegister`] pairs introduced by [`preserve`] that cancel each other out.
fn cleanup(operations: &mut Vec<Box<dyn Encode>>) {
    let mut i = 0;

    while i + 1 < operations.len() {
        let op1 = &*operations[i];
        let op2 = &*operations[i + 1];

        if op1.type_id() == TypeId::of::<LoadRegister>()
            && op2.type_id() == TypeId::of::<StoreRegister>()
        {
            let reads = op1.reads();
            let writes = op2.writes();

            if let (Some(Effect::Register(r1)), Some(Effect::Register(r2))) =
                (reads.first(), writes.first())
            {
                if r1 == r2 {
                    operations.drain(i..i + 2);

                    if i > 0 {
                        i -= 1;
                    }
                    continue;
                }
            }
        }
        i += 1;
    }
}

/// If atoms have a read/write or write/write conflict on any register or memory.
fn conflicts(a: &Atom, b: &Atom) -> bool {
    let (ar, aw) = registers(a);
    let (br, bw) = registers(b);
    !aw.is_disjoint(&br)
        || !ar.is_disjoint(&bw)
        || !aw.is_disjoint(&bw)
        || (writes_memory(a) && (reads_memory(b) || writes_memory(b)))
        || (reads_memory(a) && writes_memory(b))
}

/// Collects all [`VMReg`]s read and written across all operations in an atom.
fn registers(atom: &Atom) -> (HashSet<VMReg>, HashSet<VMReg>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();

    for op in atom {
        for effect in op.reads() {
            if let Effect::Register(r) = effect {
                if r != VMReg::None {
                    reads.insert(r);
                }
            }
        }
        for effect in op.writes() {
            if let Effect::Register(r) = effect {
                if r != VMReg::None {
                    writes.insert(r);
                }
            }
        }
    }
    (reads, writes)
}

/// Returns the net [`Effect::Scratch`] depth change for a single operation.
fn stores_minus_loads(op: &dyn Encode) -> i32 {
    scratches(&op.writes()) as i32 - scratches(&op.reads()) as i32
}

/// Counts [`Effect::Scratch`] entries in an effect list.
fn scratches(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|e| matches!(e, Effect::Scratch))
        .count()
}

/// Returns true if any operation in the atom writes to [`VMReg::NBranch`].
fn is_branch(atom: &Atom) -> bool {
    atom.iter().any(|op| {
        op.writes()
            .iter()
            .any(|e| matches!(e, Effect::Register(VMReg::NBranch)))
    })
}

/// Returns true if any operation in the atom writes [`Effect::Flags`].
fn writes_flags(atom: &Atom) -> bool {
    atom.iter()
        .any(|op| op.writes().iter().any(|e| matches!(e, Effect::Flags)))
}

/// Returns true if any operation in the slice is a [`LoadMemory`].
fn reads_memory(operations: &[Box<dyn Encode>]) -> bool {
    operations
        .iter()
        .any(|operation| (**operation).type_id() == TypeId::of::<LoadMemory>())
}

/// Returns true if any operation in the slice is a [`StoreMemory`].
fn writes_memory(operations: &[Box<dyn Encode>]) -> bool {
    operations
        .iter()
        .any(|operation| (**operation).type_id() == TypeId::of::<StoreMemory>())
}

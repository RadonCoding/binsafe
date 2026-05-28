use rand::Rng;
use std::collections::HashSet;
use std::mem;

use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{Effect, Encode};

type Atom = Vec<Box<dyn Encode>>;

pub fn permute(operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
    let mut atoms = atomize(operations);

    preserve(&mut atoms);

    schedule(atoms).into_iter().flatten().collect()
}

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

fn preserve(atoms: &mut [Atom]) {
    let brancher = match atoms.iter().rposition(is_branch) {
        Some(b) => b,
        None => return,
    };
    let flagger = match atoms[..brancher].iter().rposition(writes_flags) {
        Some(l) => l,
        None => return,
    };

    atoms[flagger].push(Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: VMReg::Flags,
    }));
    atoms[flagger].push(Box::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: VMReg::VScratch0,
    }));

    atoms[brancher].insert(
        0,
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::VScratch0,
        }),
    );
    atoms[brancher].insert(
        1,
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }),
    );
}

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

fn conflicts(a: &Atom, b: &Atom) -> bool {
    let (ar, aw) = regs(a);
    let (br, bw) = regs(b);
    !aw.is_disjoint(&br)
        || !ar.is_disjoint(&bw)
        || !aw.is_disjoint(&bw)
        || (writes_memory(a) && (reads_memory(b) || writes_memory(b)))
        || (reads_memory(a) && writes_memory(b))
}

fn regs(atom: &Atom) -> (HashSet<VMReg>, HashSet<VMReg>) {
    let mut reads = HashSet::new();
    let mut writes = HashSet::new();
    for op in atom {
        for effect in op.reads() {
            if let Effect::Reg(r) = effect {
                if r != VMReg::None {
                    reads.insert(r);
                }
            }
        }
        for effect in op.writes() {
            if let Effect::Reg(r) = effect {
                if r != VMReg::None {
                    writes.insert(r);
                }
            }
        }
    }
    (reads, writes)
}

fn stores_minus_loads(op: &dyn Encode) -> i32 {
    scratches(&op.writes()) as i32 - scratches(&op.reads()) as i32
}

fn scratches(effects: &[Effect]) -> usize {
    effects
        .iter()
        .filter(|e| matches!(e, Effect::Scratch))
        .count()
}

fn is_branch(atom: &Atom) -> bool {
    atom.iter().any(|op| {
        op.writes()
            .iter()
            .any(|e| matches!(e, Effect::Reg(VMReg::NBranch)))
    })
}

fn writes_flags(atom: &Atom) -> bool {
    atom.iter()
        .any(|op| op.writes().iter().any(|e| matches!(e, Effect::Flags)))
}

fn reads_memory(atom: &Atom) -> bool {
    atom.iter().any(|op| {
        let r = op.reads();
        let w = op.writes();
        r.len() == 1
            && matches!(r[0], Effect::Scratch)
            && w.len() == 1
            && matches!(w[0], Effect::Scratch)
    })
}

fn writes_memory(atom: &Atom) -> bool {
    atom.iter().any(|op| {
        let r = op.reads();
        let w = op.writes();
        r.len() == 2
            && matches!(r[0], Effect::Scratch)
            && matches!(r[1], Effect::Scratch)
            && w.is_empty()
    })
}

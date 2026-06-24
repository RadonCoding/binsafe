use std::any::Any;
use std::collections::HashSet;
use std::mem;

use crate::mapper::Mappable;
use crate::vm::bytecode::{VMMem, VMReg, VMVec, VMWidth};
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{identity, Effect, Encode};
use crate::vm::transform::{branches, collapse, descend};

struct Access {
    memory: VMMem,
    width: usize,
    write: bool,
}

struct Profile {
    register_reads: u64,
    register_writes: u64,
    vector_reads: u32,
    vector_writes: u32,
    memory_reads: bool,
    memory_writes: bool,
    accesses: Option<Vec<Access>>,
}

/// Shuffles `operations` into a semantically equivalent sequence by using `picker` to select among available atomic blocks.
pub fn permute<F>(mut operations: Vec<Box<dyn Encode>>, picker: &mut F) -> Vec<Box<dyn Encode>>
where
    F: FnMut(&[usize]) -> usize,
{
    descend(&mut operations, |operations| {
        let atoms = collapse(mem::take(operations));

        let live = atoms
            .iter()
            .flat_map(|atom| effects(atom).0)
            .collect::<HashSet<VMReg>>();
        let (atoms, parked) = decouple(atoms, &live);
        let (successors, mut indegree) = dependencies(&atoms);

        let n = successors.len();
        let mut ready = (0..n).filter(|&i| indegree[i] == 0).collect::<Vec<usize>>();
        let mut order = Vec::with_capacity(n);

        while !ready.is_empty() {
            let chosen = ready.swap_remove(picker(&ready));
            order.push(chosen);
            for &next in &successors[chosen] {
                indegree[next] -= 1;
                if indegree[next] == 0 {
                    ready.push(next);
                }
            }
        }

        let mut permutated = schedule(atoms, &order);
        cleanup(&mut permutated, &parked);
        *operations = permutated;
    });

    operations
}

/// Removes adjacent [`StoreRegister`]/[`LoadRegister`] pairs created by incomplete scheduling.
fn cleanup(operations: &mut Vec<Box<dyn Encode>>, parked: &HashSet<usize>) {
    let mut i = 0;

    while i + 1 < operations.len() {
        if !parked.contains(&identity(&operations[i]))
            || !parked.contains(&identity(&operations[i + 1]))
        {
            i += 1;
            continue;
        }

        let store = (&*operations[i] as &dyn Any).downcast_ref::<StoreRegister>();
        let load = (&*operations[i + 1] as &dyn Any).downcast_ref::<LoadRegister>();

        let pair = match (store, load) {
            (Some(s), Some(l)) => s.destination == l.source && s.width == l.width,
            _ => false,
        };

        if pair {
            operations.drain(i..i + 2);

            i = i.saturating_sub(1);
            continue;
        }

        i += 1;
    }
}

/// Decomposes atoms at depth-1 points, using registers to park state across blocks.
fn decouple(
    atoms: Vec<Vec<Box<dyn Encode>>>,
    live: &HashSet<VMReg>,
) -> (Vec<Vec<Box<dyn Encode>>>, HashSet<usize>) {
    let plans = (0..atoms.len())
        .map(|i| {
            let cuts = cuts(&atoms[i]);

            if cuts.is_empty() {
                None
            } else {
                vacant(&atoms, i, cuts.len(), live).map(|registers| (cuts, registers))
            }
        })
        .collect::<Vec<Option<(Vec<usize>, Vec<VMReg>)>>>();

    let mut result = Vec::with_capacity(atoms.len() * 2);
    let mut parked = HashSet::new();

    for (atom, plan) in atoms.into_iter().zip(plans) {
        match plan {
            Some((cuts, registers)) => result.extend(split(atom, &cuts, &registers, &mut parked)),
            None => result.push(atom),
        }
    }

    (result, parked)
}

/// Identifies internal indices where scratch depth is 1.
fn cuts(atom: &Vec<Box<dyn Encode>>) -> Vec<usize> {
    let mut points = Vec::new();
    let mut depth = 0;

    for (i, op) in atom.iter().enumerate() {
        depth += op.depth();

        if depth == 1 && i + 1 < atom.len() {
            points.push(i + 1);
        }
    }

    points
}

/// Finds [`VMReg`]s in future atoms available to store intermediate state without conflicts.
fn vacant(
    atoms: &[Vec<Box<dyn Encode>>],
    pair: usize,
    count: usize,
    live: &HashSet<VMReg>,
) -> Option<Vec<VMReg>> {
    let (taken, _) = effects(&atoms[pair]);
    let mut result = Vec::with_capacity(count);
    let mut scanned = HashSet::new();

    for j in (pair + 1)..atoms.len() {
        let (reads, _) = effects(&atoms[j]);

        for operation in &atoms[j] {
            let Some(store) = (&**operation as &dyn Any).downcast_ref::<StoreRegister>() else {
                continue;
            };

            let register = store.destination;
            let full = matches!(store.width, VMWidth::Lower64 | VMWidth::Lower32);

            if full
                && !taken.contains(&register)
                && !reads.contains(&register)
                && !scanned.contains(&register)
                && !result.contains(&register)
                && live.contains(&register)
            {
                result.push(register);

                if result.len() == count {
                    return Some(result);
                }
            }
        }

        scanned.extend(reads);
    }

    None
}

/// Partitions `atom` at `cuts`, inserting [`LoadRegister`] and [`StoreRegister`] pairs to persist state.
fn split(
    atom: Vec<Box<dyn Encode>>,
    cuts: &[usize],
    registers: &[VMReg],
    parked: &mut HashSet<usize>,
) -> Vec<Vec<Box<dyn Encode>>> {
    let mut operations = atom
        .into_iter()
        .map(Some)
        .collect::<Vec<Option<Box<dyn Encode>>>>();

    let total = operations.len();

    let mut result = Vec::with_capacity(cuts.len() + 1);

    let mut previous = 0;

    for (k, &cut) in cuts.iter().enumerate() {
        let mut piece = Vec::new();

        if k > 0 {
            let load = Box::new(LoadRegister {
                width: VMWidth::Lower64,
                source: registers[k - 1],
            }) as Box<dyn Encode>;

            parked.insert(identity(&load));

            piece.push(load);
        }

        for j in previous..cut {
            piece.push(operations[j].take().unwrap());
        }

        let store = Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: registers[k],
        }) as Box<dyn Encode>;

        parked.insert(identity(&store));

        piece.push(store);

        result.push(piece);

        previous = cut;
    }

    let mut last = Vec::new();

    let load = Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: *registers.last().unwrap(),
    }) as Box<dyn Encode>;

    parked.insert(identity(&load));

    last.push(load);

    for j in previous..total {
        last.push(operations[j].take().unwrap());
    }

    result.push(last);

    result
}

/// Extracts register read and write sets for an atom.
fn effects(atom: &Vec<Box<dyn Encode>>) -> (HashSet<VMReg>, HashSet<VMReg>) {
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

/// Builds a dependency graph and calculates indegrees for atoms.
fn dependencies(atoms: &[Vec<Box<dyn Encode>>]) -> (Vec<Vec<usize>>, Vec<usize>) {
    let head = atoms.iter().rposition(branches).unwrap_or(atoms.len());
    let profiles = atoms[..head].iter().map(profile).collect::<Vec<Profile>>();

    let mut successors = vec![Vec::new(); head];
    let mut indegree = vec![0usize; head];

    for i in 0..head {
        for j in 0..i {
            if conflicts(&profiles[j], &profiles[i]) {
                successors[j].push(i);
                indegree[i] += 1;
            }
        }
    }

    (successors, indegree)
}

/// Flattens scheduled atoms into an ordered sequence of operations.
fn schedule(mut atoms: Vec<Vec<Box<dyn Encode>>>, order: &[usize]) -> Vec<Box<dyn Encode>> {
    let tail = match atoms.iter().rposition(branches) {
        Some(i) => atoms.split_off(i),
        None => Vec::new(),
    };

    let mut pool = atoms
        .into_iter()
        .map(Some)
        .collect::<Vec<Option<Vec<Box<dyn Encode>>>>>();

    order
        .iter()
        .map(|&i| pool[i].take().unwrap())
        .chain(tail)
        .flatten()
        .collect()
}

/// Generates an effect [`Profile`] for an atom.
fn profile(atom: &Vec<Box<dyn Encode>>) -> Profile {
    let mut register_reads = 0;
    let mut register_writes = 0;
    let mut vector_reads = 0;
    let mut vector_writes = 0;
    let mut memory_reads = false;
    let mut memory_writes = false;

    for op in atom {
        for effect in op.reads() {
            match effect {
                Effect::Register(r) if r != VMReg::None => register_reads |= register_bit(r),
                Effect::Vector(v) => vector_reads |= vector_bit(v),
                Effect::Memory => memory_reads = true,
                _ => {}
            }
        }

        for effect in op.writes() {
            match effect {
                Effect::Register(r) if r != VMReg::None => register_writes |= register_bit(r),
                Effect::Vector(v) => vector_writes |= vector_bit(v),
                Effect::Memory => memory_writes = true,
                _ => {}
            }
        }
    }

    Profile {
        register_reads,
        register_writes,
        vector_reads,
        vector_writes,
        memory_reads,
        memory_writes,
        accesses: accesses(atom),
    }
}

/// Checks if two [`Profile`]s have conflicting register or memory effects.
fn conflicts(a: &Profile, b: &Profile) -> bool {
    (a.register_writes & b.register_reads) != 0
        || (a.register_reads & b.register_writes) != 0
        || (a.register_writes & b.register_writes) != 0
        || (a.vector_writes & b.vector_reads) != 0
        || (a.vector_reads & b.vector_writes) != 0
        || (a.vector_writes & b.vector_writes) != 0
        || memory(a, b)
}

/// Determines if two atom memory accesses overlap.
fn memory(a: &Profile, b: &Profile) -> bool {
    match (&a.accesses, &b.accesses) {
        (Some(x), Some(y)) => x.iter().any(|p| y.iter().any(|q| aliases(p, q))),
        _ => {
            (a.memory_writes && (b.memory_reads || b.memory_writes))
                || (a.memory_reads && b.memory_writes)
        }
    }
}

/// Returns the bitmask position for a [`VMReg`].
fn register_bit(reg: VMReg) -> u64 {
    1u64 << VMReg::VARIANTS.iter().position(|&r| r == reg).unwrap()
}

/// Returns the bitmask position for a [`VMVec`].
fn vector_bit(vec: VMVec) -> u32 {
    1u32 << VMVec::VARIANTS.iter().position(|&v| v == vec).unwrap()
}

/// Pairs memory operations with address loads for dependency analysis.
fn accesses(atom: &Vec<Box<dyn Encode>>) -> Option<Vec<Access>> {
    let mut result = Vec::new();

    for i in 0..atom.len() {
        let op = &*atom[i];

        let any: &dyn Any = op;

        let here = if let Some(l) = any.downcast_ref::<LoadMemory>() {
            Some((l.width.size(), false))
        } else if let Some(s) = any.downcast_ref::<StoreMemory>() {
            Some((s.width.size(), true))
        } else {
            None
        };

        if let Some((width, write)) = here {
            if i == 0 {
                return None;
            }

            let load = (&*atom[i - 1] as &dyn Any).downcast_ref::<LoadAddress>()?;

            result.push(Access {
                memory: load.source,
                width,
                write,
            });
        } else if op.reads().iter().any(|e| matches!(e, Effect::Memory))
            || op.writes().iter().any(|e| matches!(e, Effect::Memory))
        {
            return None;
        }
    }

    Some(result)
}

/// Checks if two [`Access`]es alias.
fn aliases(a: &Access, b: &Access) -> bool {
    if !a.write && !b.write {
        return false;
    }

    if a.memory.base != b.memory.base
        || a.memory.index != b.memory.index
        || a.memory.scale != b.memory.scale
        || a.memory.segment != b.memory.segment
    {
        return true;
    }

    let start_a = a.memory.displacement as isize;
    let end_a = start_a + a.width as isize;
    let start_b = b.memory.displacement as isize;
    let end_b = start_b + b.width as isize;

    !(end_a <= start_b || end_b <= start_a)
}

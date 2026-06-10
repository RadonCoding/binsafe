use std::any::Any;
use std::collections::HashSet;
use std::mem;
use std::rc::Rc;

use crate::mapper::Mappable;
use crate::vm::bytecode::{VMMem, VMReg, VMVec, VMWidth};
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{Effect, Encode};
use crate::vm::transform::address;

struct Access {
    memory: VMMem,
    width: i64,
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

/// Shuffles operations into a semantically equivalent sequence, with `picker` choosing among the ready atoms at each scheduling step.
pub fn permute<F>(operations: Vec<Rc<dyn Encode>>, picker: &mut F) -> Vec<Rc<dyn Encode>>
where
    F: FnMut(&[usize]) -> usize,
{
    let atoms = atomize(operations);

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

    permutated
}

/// Removes adjacent [`decouple`]-inserted [`StoreRegister`]/[`LoadRegister`] pairs left behind when scheduling failed to interleave anything across a parking cut.
fn cleanup(operations: &mut Vec<Rc<dyn Encode>>, parked: &HashSet<usize>) {
    let mut i = 0;

    while i + 1 < operations.len() {
        if !parked.contains(&address(&operations[i]))
            || !parked.contains(&address(&operations[i + 1]))
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

/// Groups operations into atoms where each atom leaves the scratch stack balanced. When the operation list does not end at depth 0 (a trailing unbalanced run), every atom built so far is merged with that run into a single atom so permute cannot reorder across it.
fn atomize(operations: Vec<Rc<dyn Encode>>) -> Vec<Vec<Rc<dyn Encode>>> {
    let mut atoms = Vec::new();
    let mut current = Vec::<Rc<dyn Encode>>::new();
    let mut depth = 0;

    for op in operations {
        depth += op.depth();

        current.push(op);

        if depth == 0 {
            atoms.push(mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        let mut single = Vec::<Rc<dyn Encode>>::new();

        for atom in atoms.drain(..) {
            single.extend(atom);
        }

        single.extend(current);

        atoms.push(single);
    }

    atoms
}

/// Splits each atom at every depth-1 cut by parking the single scratch value across the cut into a register that some later atom is about to kill.
fn decouple(
    atoms: Vec<Vec<Rc<dyn Encode>>>,
    live: &HashSet<VMReg>,
) -> (Vec<Vec<Rc<dyn Encode>>>, HashSet<usize>) {
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

/// Positions inside an atom where cumulative scratch depth equals one and exactly one value is sitting on top ready to be parked.
fn cuts(atom: &Vec<Rc<dyn Encode>>) -> Vec<usize> {
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

/// Finds `count` distinct registers, each fully overwritten by a 64- or 32-bit [`StoreRegister`] in some later atom and not read between the pair and that store.
fn vacant(
    atoms: &[Vec<Rc<dyn Encode>>],
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

/// Splits an atom at the given cut positions, prepending a load and appending a store of the corresponding parking register at each boundary, recording each synthetic op into `parked`.
fn split(
    atom: Vec<Rc<dyn Encode>>,
    cuts: &[usize],
    registers: &[VMReg],
    parked: &mut HashSet<usize>,
) -> Vec<Vec<Rc<dyn Encode>>> {
    let mut operations = atom
        .into_iter()
        .map(Some)
        .collect::<Vec<Option<Rc<dyn Encode>>>>();

    let total = operations.len();

    let mut result = Vec::with_capacity(cuts.len() + 1);

    let mut previous = 0;

    for (k, &cut) in cuts.iter().enumerate() {
        let mut piece = Vec::new();

        if k > 0 {
            let op = load(registers[k - 1]);

            parked.insert(address(&op));
            piece.push(op);
        }

        for j in previous..cut {
            piece.push(operations[j].take().unwrap());
        }

        let op = store(registers[k]);

        parked.insert(address(&op));
        piece.push(op);

        result.push(piece);

        previous = cut;
    }

    let mut last = Vec::new();

    let op = load(*registers.last().unwrap());

    parked.insert(address(&op));

    last.push(op);

    for j in previous..total {
        last.push(operations[j].take().unwrap());
    }

    result.push(last);

    result
}

/// Refcounted [`LoadRegister`] that reads `register` and pushes onto scratch.
fn load(register: VMReg) -> Rc<dyn Encode> {
    Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: register,
    })
}

/// Refcounted [`StoreRegister`] that pops from scratch and writes `register`.
fn store(register: VMReg) -> Rc<dyn Encode> {
    Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: register,
    })
}

/// Register read and write sets for an atom.
fn effects(atom: &Vec<Rc<dyn Encode>>) -> (HashSet<VMReg>, HashSet<VMReg>) {
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

/// Conflict graph over the schedulable head as successor lists with indegree counts.
fn dependencies(atoms: &[Vec<Rc<dyn Encode>>]) -> (Vec<Vec<usize>>, Vec<usize>) {
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

/// Applies `order` to the schedulable head, appends the trailing branch atom, flattens to operations, and drops any adjacent [`VMReg::Flags`] save/restore pair.
fn schedule(mut atoms: Vec<Vec<Rc<dyn Encode>>>, order: &[usize]) -> Vec<Rc<dyn Encode>> {
    let tail = match atoms.iter().rposition(branches) {
        Some(i) => atoms.split_off(i),
        None => Vec::new(),
    };

    let mut pool = atoms
        .into_iter()
        .map(Some)
        .collect::<Vec<Option<Vec<Rc<dyn Encode>>>>>();

    order
        .iter()
        .map(|&i| pool[i].take().unwrap())
        .chain(tail)
        .flatten()
        .collect()
}

/// Pre-computed effect summary for an [`Vec<Rc<dyn Encode>>`], cached by [`dependencies`] so each conflict pair doesn't re-walk the ops.
fn profile(atom: &Vec<Rc<dyn Encode>>) -> Profile {
    let mut register_reads = 0;
    let mut register_writes = 0;
    let mut vector_reads = 0;
    let mut vector_writes = 0;
    let mut memory_reads = false;
    let mut memory_writes = false;

    for op in atom {
        for effect in op.reads() {
            match effect {
                Effect::Register(r) if r != VMReg::None => register_reads |= bit(r),
                Effect::Vector(v) => vector_reads |= vector_bit(v),
                Effect::Memory => memory_reads = true,
                _ => {}
            }
        }

        for effect in op.writes() {
            match effect {
                Effect::Register(r) if r != VMReg::None => register_writes |= bit(r),
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

/// Whether two atoms have a read/write or write/write conflict on any register, memory location, or flag.
fn conflicts(a: &Profile, b: &Profile) -> bool {
    (a.register_writes & b.register_reads) != 0
        || (a.register_reads & b.register_writes) != 0
        || (a.register_writes & b.register_writes) != 0
        || (a.vector_writes & b.vector_reads) != 0
        || (a.vector_reads & b.vector_writes) != 0
        || (a.vector_writes & b.vector_writes) != 0
        || memory(a, b)
}

/// Whether two atoms' memory accesses overlap, conservatively treating unpaired accesses as overlapping any other memory touch.
fn memory(a: &Profile, b: &Profile) -> bool {
    match (&a.accesses, &b.accesses) {
        (Some(x), Some(y)) => x.iter().any(|p| y.iter().any(|q| aliases(p, q))),
        _ => {
            (a.memory_writes && (b.memory_reads || b.memory_writes))
                || (a.memory_reads && b.memory_writes)
        }
    }
}

/// Bit position assigned to a [`VMReg`] inside the register bitmask.
fn bit(reg: VMReg) -> u64 {
    1u64 << VMReg::VARIANTS.iter().position(|&r| r == reg).unwrap()
}

/// Bit position assigned to a [`VMVec`] inside the vector bitmask.
fn vector_bit(vec: VMVec) -> u32 {
    1u32 << VMVec::VARIANTS.iter().position(|&v| v == vec).unwrap()
}

/// Pairs each [`LoadMemory`]/[`StoreMemory`] with its preceding [`LoadAddress`] to extract concrete addressed accesses.
fn accesses(atom: &Vec<Rc<dyn Encode>>) -> Option<Vec<Access>> {
    let mut result = Vec::new();

    for i in 0..atom.len() {
        let op = &*atom[i];

        let any: &dyn Any = op;

        let here = if let Some(l) = any.downcast_ref::<LoadMemory>() {
            Some((bytes(l.width), false))
        } else if let Some(s) = any.downcast_ref::<StoreMemory>() {
            Some((bytes(s.width), true))
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

/// Whether two memory accesses overlap, conservatively treating mismatched addressing schemes as overlapping.
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

    let start_a = a.memory.displacement as i64;
    let end_a = start_a + a.width;
    let start_b = b.memory.displacement as i64;
    let end_b = start_b + b.width;

    !(end_a <= start_b || end_b <= start_a)
}

/// Whether the atom writes [`VMReg::NBranch`].
fn branches(atom: &Vec<Rc<dyn Encode>>) -> bool {
    atom.iter().any(|op| op.branches())
}

/// Byte width of a [`VMWidth`].
fn bytes(width: VMWidth) -> i64 {
    if width == VMWidth::Lower256 {
        32
    } else if width == VMWidth::Lower128 {
        16
    } else if width == VMWidth::Lower64 {
        8
    } else if width == VMWidth::Lower32 || width == VMWidth::SLower32 {
        4
    } else if width == VMWidth::Lower16 || width == VMWidth::SLower16 {
        2
    } else {
        1
    }
}

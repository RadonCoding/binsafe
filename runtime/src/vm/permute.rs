use std::any::TypeId;
use std::collections::HashSet;
use std::mem;

use crate::mapper::Mappable;
use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{Effect, Encode};

type Atom = Vec<Box<dyn Encode>>;

struct Access {
    memory: VMMem,
    width: i64,
    write: bool,
}

struct Profile {
    reads: u64,
    writes: u64,
    flags_reads: bool,
    flags_writes: bool,
    memory_reads: bool,
    memory_writes: bool,
    accesses: Option<Vec<Access>>,
}

/// Shuffles operations into a semantically equivalent sequence, with `pick` choosing among the ready atoms at each scheduling step.
pub fn permute<F>(operations: Vec<Box<dyn Encode>>, mut picker: F) -> Vec<Box<dyn Encode>>
where
    F: FnMut(&[usize]) -> usize,
{
    let atoms = atomize(operations);

    let live = atoms
        .iter()
        .flat_map(|atom| effects(atom).0)
        .collect::<HashSet<VMReg>>();

    let atoms = decouple(atoms, &live);

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

    schedule(atoms, &order)
}

/// Groups operations into atoms where each atom leaves the scratch stack balanced.
fn atomize(operations: Vec<Box<dyn Encode>>) -> Vec<Atom> {
    let mut atoms = Vec::new();
    let mut current = Atom::new();
    let mut depth = 0;

    for op in operations {
        depth += op.depth();

        current.push(op);

        if depth == 0 {
            atoms.push(mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        let mut single = Atom::new();

        for atom in atoms.drain(..) {
            single.extend(atom);
        }

        single.extend(current);

        atoms.push(single);
    }

    atoms
}

/// Splits each atom at every depth-1 cut by parking the single scratch value across the cut into a register that some later atom is about to kill.
fn decouple(atoms: Vec<Atom>, live: &HashSet<VMReg>) -> Vec<Atom> {
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

    for (atom, plan) in atoms.into_iter().zip(plans) {
        match plan {
            Some((cuts, registers)) => result.extend(split(atom, &cuts, &registers)),
            None => result.push(atom),
        }
    }

    result
}

/// Positions inside an atom where cumulative scratch depth equals one and exactly one value is sitting on top ready to be parked.
fn cuts(atom: &Atom) -> Vec<usize> {
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
fn vacant(atoms: &[Atom], pair: usize, count: usize, live: &HashSet<VMReg>) -> Option<Vec<VMReg>> {
    let (taken, _) = effects(&atoms[pair]);
    let mut result = Vec::with_capacity(count);
    let mut scanned = HashSet::new();

    for j in (pair + 1)..atoms.len() {
        let (reads, _) = effects(&atoms[j]);

        for operation in &atoms[j] {
            let Some(store) = downcast::<StoreRegister>(&**operation) else {
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

/// Splits an atom at the given cut positions, prepending a load and appending a store of the corresponding parking register at each boundary.
fn split(atom: Atom, cuts: &[usize], registers: &[VMReg]) -> Vec<Atom> {
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
            piece.push(load(registers[k - 1]));
        }

        for j in previous..cut {
            piece.push(operations[j].take().unwrap());
        }

        piece.push(store(registers[k]));

        result.push(piece);

        previous = cut;
    }

    let mut last = Vec::new();

    last.push(load(*registers.last().unwrap()));

    for j in previous..total {
        last.push(operations[j].take().unwrap());
    }

    result.push(last);

    result
}

/// Boxed [`LoadRegister`] that reads `register` and pushes onto scratch.
fn load(register: VMReg) -> Box<dyn Encode> {
    Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: register,
    })
}

/// Boxed [`StoreRegister`] that pops from scratch and writes `register`.
fn store(register: VMReg) -> Box<dyn Encode> {
    Box::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: register,
    })
}

/// Register read and write sets for an atom.
fn effects(atom: &Atom) -> (HashSet<VMReg>, HashSet<VMReg>) {
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
fn dependencies(atoms: &[Atom]) -> (Vec<Vec<usize>>, Vec<usize>) {
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
fn schedule(mut atoms: Vec<Atom>, order: &[usize]) -> Vec<Box<dyn Encode>> {
    let tail = match atoms.iter().rposition(branches) {
        Some(i) => atoms.split_off(i),
        None => Vec::new(),
    };

    let mut pool = atoms.into_iter().map(Some).collect::<Vec<Option<Atom>>>();

    order
        .iter()
        .map(|&i| pool[i].take().unwrap())
        .chain(tail)
        .flatten()
        .collect()
}

/// Pre-computed effect summary for an [`Atom`], cached by [`dependencies`] so each conflict pair doesn't re-walk the ops.
fn profile(atom: &Atom) -> Profile {
    let mut reads = 0;
    let mut writes = 0;
    let mut flags_reads = false;
    let mut flags_writes = false;
    let mut memory_reads = false;
    let mut memory_writes = false;

    for op in atom {
        for effect in op.reads() {
            match effect {
                Effect::Register(r) if r != VMReg::None => reads |= bit(r),
                Effect::Flags => flags_reads = true,
                Effect::Memory => memory_reads = true,
                _ => {}
            }
        }

        for effect in op.writes() {
            match effect {
                Effect::Register(r) if r != VMReg::None => writes |= bit(r),
                Effect::Flags => flags_writes = true,
                Effect::Memory => memory_writes = true,
                _ => {}
            }
        }
    }

    Profile {
        reads,
        writes,
        flags_reads,
        flags_writes,
        memory_reads,
        memory_writes,
        accesses: accesses(atom),
    }
}

/// Whether two atoms have a read/write or write/write conflict on any register, memory location, or flag.
fn conflicts(a: &Profile, b: &Profile) -> bool {
    (a.writes & b.reads) != 0
        || (a.reads & b.writes) != 0
        || (a.writes & b.writes) != 0
        || memory(a, b)
        || (a.flags_writes && (b.flags_writes || b.flags_reads))
        || (a.flags_reads && b.flags_writes)
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

/// Pairs each [`LoadMemory`]/[`StoreMemory`] with its preceding [`LoadAddress`] to extract concrete addressed accesses.
fn accesses(atom: &Atom) -> Option<Vec<Access>> {
    let mut result = Vec::new();

    for i in 0..atom.len() {
        let op = &*atom[i];

        let here = if let Some(l) = downcast::<LoadMemory>(op) {
            Some((bytes(l.width), false))
        } else if let Some(s) = downcast::<StoreMemory>(op) {
            Some((bytes(s.width), true))
        } else {
            None
        };

        if let Some((width, write)) = here {
            if i == 0 {
                return None;
            }

            let addr = downcast::<LoadAddress>(&*atom[i - 1])?;

            result.push(Access {
                memory: addr.source,
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
fn branches(atom: &Atom) -> bool {
    atom.iter().any(|op| {
        op.writes()
            .iter()
            .any(|e| matches!(e, Effect::Register(VMReg::NBranch)))
    })
}

/// Byte width of a [`VMWidth`].
fn bytes(width: VMWidth) -> i64 {
    if width == VMWidth::Lower64 {
        8
    } else if width == VMWidth::Lower32 || width == VMWidth::SLower32 {
        4
    } else if width == VMWidth::Lower16 || width == VMWidth::SLower16 {
        2
    } else {
        1
    }
}

/// Downcasts a `dyn Encode` reference to a concrete encoder type when its underlying type matches.
fn downcast<T: Encode + 'static>(op: &dyn Encode) -> Option<&T> {
    if op.type_id() == TypeId::of::<T>() {
        Some(unsafe { &*(op as *const dyn Encode as *const T) })
    } else {
        None
    }
}

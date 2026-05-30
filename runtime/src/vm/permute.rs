use rand::Rng;
use std::any::TypeId;
use std::collections::HashSet;
use std::mem;

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{Effect, Encode};

type Atom = Vec<Box<dyn Encode>>;

struct MemoryAccess {
    memory: VMMem,
    width: i64,
    write: bool,
}

/// Shuffles operations into a randomized but semantically equivalent sequence.
pub fn permute(operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
    let mut atoms = atomize(operations);

    preserve(&mut atoms);

    let atoms = decouple(atoms);

    let mut operations = schedule(atoms).into_iter().flatten().collect();

    cleanup(&mut operations);

    operations
}

/// Splits two-op producer-consumer atoms by parking the intermediate value into a register that some later atom is about to overwrite.
fn decouple(atoms: Vec<Atom>) -> Vec<Atom> {
    let parking = (0..atoms.len())
        .map(|i| {
            let atom = &atoms[i];
            if atom.len() == 2
                && stores_minus_loads(&*atom[0]) == 1
                && stores_minus_loads(&*atom[1]) == -1
            {
                find_parking(&atoms, i)
            } else {
                None
            }
        })
        .collect::<Vec<Option<VMReg>>>();

    let mut result = Vec::with_capacity(atoms.len() * 2);

    for (i, atom) in atoms.into_iter().enumerate() {
        if let Some(register) = parking[i] {
            let mut iter = atom.into_iter();
            let producer = iter.next().unwrap();
            let consumer = iter.next().unwrap();

            result.push(vec![
                producer,
                Box::new(StoreRegister {
                    width: VMWidth::Lower64,
                    destination: register,
                }),
            ]);
            result.push(vec![
                Box::new(LoadRegister {
                    width: VMWidth::Lower64,
                    source: register,
                }),
                consumer,
            ]);
        } else {
            result.push(atom);
        }
    }

    result
}

/// Finds a register that some atom after the pair kills (writes without reading), where no atom between reads it first.
fn find_parking(atoms: &[Atom], pair: usize) -> Option<VMReg> {
    let mut read_in_window = HashSet::new();

    for j in (pair + 1)..atoms.len() {
        let (reads, writes) = registers(&atoms[j]);

        for &register in &writes {
            if !reads.contains(&register)
                && !read_in_window.contains(&register)
                && is_parking_register(register)
            {
                return Some(register);
            }
        }

        read_in_window.extend(reads);
    }

    None
}

/// Returns true if the register is a general purpose x86-64 register safe to use as a temporary parking slot.
fn is_parking_register(register: VMReg) -> bool {
    matches!(
        register,
        VMReg::Rax
            | VMReg::Rcx
            | VMReg::Rdx
            | VMReg::Rbx
            | VMReg::Rsi
            | VMReg::Rdi
            | VMReg::R8
            | VMReg::R9
            | VMReg::R10
            | VMReg::R11
            | VMReg::R12
            | VMReg::R13
            | VMReg::R14
            | VMReg::R15
    )
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

    if !atom.is_empty() {
        let mut single = Atom::new();

        for atom in atoms.drain(..) {
            single.extend(atom);
        }
        single.extend(atom);

        atoms.push(single);
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

/// If atoms have a read/write or write/write conflict on any register, memory, or flags.
fn conflicts(a: &Atom, b: &Atom) -> bool {
    let (ar, aw) = registers(a);
    let (br, bw) = registers(b);
    // a writes a register b reads
    !aw.is_disjoint(&br)
        // a reads a register b writes
        || !ar.is_disjoint(&bw)
        // both write the same register
        || !aw.is_disjoint(&bw)
        // memory aliasing
        || memory_conflicts(a, b)
        // a writes flags b reads or writes
        || (writes_flags(a) && (reads_flags(b) || writes_flags(b)))
        // a reads flags b writes
        || (reads_flags(a) && writes_flags(b))
}

/// Extracts the memory accesses performed by an atom by pairing each [`LoadMemory`] or [`StoreMemory`] with the [`LoadAddress`] immediately preceding it.
fn memory_accesses(atom: &Atom) -> Option<Vec<MemoryAccess>> {
    let mut result = Vec::new();

    for i in 0..atom.len() {
        let op = &*atom[i];

        let width_and_kind = if let Some(load) = downcast::<LoadMemory>(op) {
            Some((width_bytes(load.width), false))
        } else if let Some(store) = downcast::<StoreMemory>(op) {
            Some((width_bytes(store.width), true))
        } else {
            None
        };

        if let Some((width, is_store)) = width_and_kind {
            if i == 0 {
                return None;
            }
            let prev = &*atom[i - 1];
            let address = downcast::<LoadAddress>(prev)?;
            result.push(MemoryAccess {
                memory: address.source,
                width,
                write: is_store,
            });
        }
    }

    Some(result)
}

/// Checks if two memory accesses overlap, falling back to a conservative conflict when the addressing schemes differ.
fn aliases(a: &MemoryAccess, b: &MemoryAccess) -> bool {
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

    let a_start = a.memory.displacement as i64;
    let a_end = a_start + a.width;
    let b_start = b.memory.displacement as i64;
    let b_end = b_start + b.width;

    !(a_end <= b_start || b_end <= a_start)
}

/// Resolves memory aliasing between two atoms, falling back to a conservative effect check when accesses can't be paired with an address.
fn memory_conflicts(a: &Atom, b: &Atom) -> bool {
    match (memory_accesses(a), memory_accesses(b)) {
        (Some(av), Some(bv)) => av.iter().any(|x| bv.iter().any(|y| aliases(x, y))),
        _ => {
            (writes_memory(a) && (reads_memory(b) || writes_memory(b)))
                || (reads_memory(a) && writes_memory(b))
        }
    }
}

/// Returns the byte width of a [`VMWidth`].
fn width_bytes(width: VMWidth) -> i64 {
    if width == VMWidth::Lower64 {
        8
    } else if width == VMWidth::Lower32 {
        4
    } else if width == VMWidth::Lower16 {
        2
    } else {
        1
    }
}

/// Downcasts a `dyn Encode` reference into a concrete encoder type when the underlying type matches.
fn downcast<T: Encode + 'static>(op: &dyn Encode) -> Option<&T> {
    if op.type_id() == TypeId::of::<T>() {
        Some(unsafe { &*(op as *const dyn Encode as *const T) })
    } else {
        None
    }
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

/// Returns true if any operation in the atom reads [`Effect::Flags`].
fn reads_flags(atom: &Atom) -> bool {
    atom.iter()
        .any(|op| op.reads().iter().any(|e| matches!(e, Effect::Flags)))
}

/// Returns true if any operation in the atom writes [`Effect::Flags`].
fn writes_flags(atom: &Atom) -> bool {
    atom.iter()
        .any(|op| op.writes().iter().any(|e| matches!(e, Effect::Flags)))
}

/// Returns true if any operation in the atom reads [`Effect::Memory`].
fn reads_memory(atom: &Atom) -> bool {
    atom.iter()
        .any(|op| op.reads().iter().any(|e| matches!(e, Effect::Memory)))
}

/// Returns true if any operation in the atom writes [`Effect::Memory`].
fn writes_memory(atom: &Atom) -> bool {
    atom.iter()
        .any(|op| op.writes().iter().any(|e| matches!(e, Effect::Memory)))
}

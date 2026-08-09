use crate::vm::bytecode::{VMMem, VMReg, VMSeg, VMWidth};
use crate::vm::encoders::add::Add;
use crate::vm::encoders::and::And;
use crate::vm::encoders::discard::Discard;
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::or::Or;
use crate::vm::encoders::pop::Pop;
use crate::vm::encoders::push::Push;
use crate::vm::encoders::shl::Shl;
use crate::vm::encoders::xor::Xor;
use crate::vm::encoders::{Effect, Encode};
use crate::vm::transform::{deadzones, descend};
use rand::Rng;

/// Rewrites each [`Add`] in place via equivalent MBA identities:
///
///     a + b = (a | b) + (a & b)
///     a + b = (a & b) + (a | b)
///     a + b = (a ^ b) + ((a & b) << 1)
///     a + b = ((a & b) << 1) + (a ^ b)
pub fn mutate<R: Rng>(operations: &mut Vec<Box<dyn Encode>>, rng: &mut R) {
    descend(operations, |operations| {
        let deadzones = deadzones(operations, |effect| {
            matches!(effect, Effect::Register(VMReg::Flags))
        });

        let mut i = 0;

        let mut position = 0;

        while i < operations.len() {
            let Some(add) = operations[i].as_any().downcast_ref::<Add>() else {
                i += 1;
                position += 1;
                continue;
            };

            if !deadzones[position] {
                i += 1;
                position += 1;
                continue;
            }

            let width = add.width;

            let a = VMMem {
                base: VMReg::Rsp,
                index: VMReg::None,
                scale: 0,
                displacement: 0,
                segment: VMSeg::None,
            };

            let b = VMMem {
                base: VMReg::Rsp,
                index: VMReg::None,
                scale: 0,
                displacement: 8,
                segment: VMSeg::None,
            };

            let depth = rng.gen_range(1..3);

            let mut replacement = Vec::<Box<dyn Encode>>::new();

            replacement.push(Box::new(Push::new()));
            replacement.push(Box::new(Push::new()));

            emit_add(&mut replacement, a, b, width, depth, rng);

            replacement.push(Box::new(Pop::new()));
            replacement.push(Box::new(Pop::new()));
            replacement.push(Box::new(Discard::new()));
            replacement.push(Box::new(Discard::new()));

            let length = replacement.len();

            operations.splice(i..=i, replacement);

            i += length;
            position += 1;
        }
    });
}

/// Load a value from memory.
fn load_memory(operations: &mut Vec<Box<dyn Encode>>, source: VMMem, width: VMWidth) {
    operations.push(Box::new(LoadAddress { source }));
    operations.push(Box::new(LoadMemory { width }));
}

/// Load an immediate value.
fn load_immediate(operations: &mut Vec<Box<dyn Encode>>, value: u64, width: VMWidth) {
    let source = match width {
        VMWidth::Lower8 => (value as u8).to_le_bytes().to_vec(),
        VMWidth::Lower16 => (value as u16).to_le_bytes().to_vec(),
        VMWidth::Lower32 => (value as u32).to_le_bytes().to_vec(),
        VMWidth::Lower64 => value.to_le_bytes().to_vec(),
        _ => unreachable!(),
    };

    operations.push(Box::new(LoadImmediate { source, width }));
}

/// Emit `a + b` using an equivalent identity.
fn emit_add<R: Rng>(
    operations: &mut Vec<Box<dyn Encode>>,
    a: VMMem,
    b: VMMem,
    width: VMWidth,
    depth: usize,
    rng: &mut R,
) {
    if depth == 0 {
        load_memory(operations, a, width);
        load_memory(operations, b, width);
        operations.push(Box::new(Add { width }));
        return;
    }

    match rng.gen_range(0..4) {
        0 => {
            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(Or { width }));

            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(And { width }));

            operations.push(Box::new(Add { width }));
        }
        1 => {
            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(And { width }));

            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(Or { width }));

            operations.push(Box::new(Add { width }));
        }
        2 => {
            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(Xor { width }));

            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(And { width }));

            load_immediate(operations, 1, width);
            operations.push(Box::new(Shl { width }));
            operations.push(Box::new(Add { width }));
        }
        _ => {
            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(And { width }));

            load_immediate(operations, 1, width);
            operations.push(Box::new(Shl { width }));

            load_memory(operations, a, width);
            load_memory(operations, b, width);
            operations.push(Box::new(Xor { width }));

            operations.push(Box::new(Add { width }));
        }
    }
}

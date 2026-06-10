use iced_x86::{Instruction, Register};
use runtime::vm::{
    bytecode::{self, VMReg},
    encoders::Encode,
    transform::permute,
};
use std::rc::Rc;

use crate::{encrypt, instruction, Difference, Executor, State, FAKE_BRANCH_ADDRESS};

#[derive(Default)]
struct Enumerator {
    decisions: Vec<u32>,
    counts: Vec<u32>,
    cursor: usize,
}

impl Enumerator {
    fn pick(&mut self, ready: &[usize]) -> usize {
        let level = self.cursor;

        let choice = if level < self.decisions.len() {
            self.decisions[level] as usize
        } else {
            self.decisions.push(0);
            self.counts.push(ready.len() as u32);
            0
        };

        self.cursor += 1;

        choice
    }

    fn advance(&mut self) -> bool {
        self.cursor = 0;

        while let Some(&count) = self.counts.last() {
            let last = self.decisions.len() - 1;

            if self.decisions[last] + 1 < count {
                self.decisions[last] += 1;
                return true;
            }

            self.decisions.pop();
            self.counts.pop();
        }

        false
    }
}

fn dump(operations: &[Rc<dyn Encode>]) -> String {
    let mut lines = Vec::new();

    for (i, op) in operations.iter().enumerate() {
        lines.push(format!("  {:>3}  {:?}", i, op));
    }

    lines.join("\n")
}

struct Run {
    state: State,
    memory: Vec<u64>,
}

fn exhaust(instructions: &[Instruction], state: State, memory: &mut [u64]) {
    let mut executor = Executor::new();
    let lifted = bytecode::lift(&mut executor.rt.mapper, instructions).unwrap();
    let input = dump(&lifted);

    let baseline = memory.to_vec();

    let mut enumerator = Enumerator::default();

    let mut reference = None;

    loop {
        memory.copy_from_slice(&baseline);

        let mut executor = Executor::new();
        let lifted = bytecode::lift(&mut executor.rt.mapper, instructions).unwrap();
        let permuted = permute::permute(lifted, &mut |ready| enumerator.pick(ready));
        let output = dump(&permuted);
        let mut bytes = bytecode::assemble(&mut executor.rt.mapper, &permuted);

        encrypt(&mut bytes);

        let current = Run {
            state: executor.run_virtual(state.clone(), &bytes),
            memory: memory.to_vec(),
        };

        match &reference {
            None => reference = Some(current),
            Some(reference) => {
                let mut differences = Vec::new();

                for difference in reference.state.compare(&current.state) {
                    differences.push(match difference {
                        Difference::Register(reg, expected, received) => format!(
                            "{:?}: expected=0x{:X} received=0x{:X}",
                            reg, expected, received,
                        ),
                        Difference::Vector(vec, expected, received) => format!(
                            "{:?}: expected={:02X?} received={:02X?}",
                            vec, expected, received,
                        ),
                    });
                }

                for (i, (expected, received)) in reference
                    .memory
                    .iter()
                    .zip(current.memory.iter())
                    .enumerate()
                {
                    if expected != received {
                        differences.push(format!(
                            "mem[{}]: expected=0x{:X} received=0x{:X}",
                            i, expected, received,
                        ));
                    }
                }

                assert!(
                    differences.is_empty(),
                    "{:?} | decisions={:?}\ninput:\n{}\noutput:\n{}\ndifferences: {}",
                    instructions[0].code(),
                    enumerator.decisions,
                    input,
                    output,
                    differences.join(", "),
                );
            }
        }

        if !enumerator.advance() {
            break;
        }
    }
}

#[test]
fn test_permutation() {
    exhaust(
        &[
            instruction!(Mov_r64_rm64, Register::RBX, Register::RAX),
            instruction!(Mov_r64_rm64, Register::RCX, Register::RBX),
            instruction!(Cmp_rm64_imm32, Register::RCX, 0x1111_1111),
            instruction!(branch Je_rel8_64, FAKE_BRANCH_ADDRESS),
        ],
        State::default().with(VMReg::Rax, 0x1111_1111),
        &mut [],
    );
}

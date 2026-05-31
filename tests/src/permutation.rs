use iced_x86::{Instruction, MemoryOperand, Register};
use runtime::{
    mapper::Mappable,
    vm::{
        bytecode::{self, VMReg},
        encoders::Encode,
        permute,
    },
};

use crate::{encrypt, instruction, Executor};

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

fn snapshot(executor: &mut Executor, state: [u64; VMReg::COUNT]) -> Vec<(VMReg, u64)> {
    VMReg::VARIANTS
        .iter()
        .filter(|r| {
            !matches!(
                **r,
                VMReg::BPointer | VMReg::BLength | VMReg::VStack | VMReg::VScratch
            )
        })
        .map(|r| (*r, state[executor.rt.mapper.index(*r) as usize]))
        .collect()
}

fn dump(operations: &[Box<dyn Encode>]) -> String {
    let mut lines = Vec::new();

    for (i, op) in operations.iter().enumerate() {
        lines.push(format!("  {:>3}  {:?}", i, op));
    }

    lines.join("\n")
}

fn exhaust(instructions: &[Instruction], setup: &[(VMReg, u64)], memory: &mut [u64]) {
    let input = dump(&bytecode::lift(instructions).unwrap());
    let initial = memory.to_vec();

    let mut enumerator = Enumerator::default();
    let mut reference: Option<(Vec<(VMReg, u64)>, Vec<u64>)> = None;

    loop {
        memory.copy_from_slice(&initial);

        let mut executor = Executor::new();
        let lifted = bytecode::lift(instructions).unwrap();
        let operations = permute::permute(lifted, |ready| enumerator.pick(ready));
        let output = dump(&operations);
        let mut bytes = bytecode::assemble(&mut executor.rt.mapper, &operations);

        encrypt(&mut bytes);

        let raw = executor.run(setup, &bytes);
        let regs = snapshot(&mut executor, raw);
        let mem = memory.to_vec();

        match &reference {
            None => reference = Some((regs, mem)),
            Some((ref_regs, ref_mem)) => {
                let mut differences = Vec::new();

                for ((reg, expected), (_, received)) in ref_regs.iter().zip(regs.iter()) {
                    if expected != received {
                        differences.push(format!(
                            "{:?}: expected=0x{:X} received=0x{:X}",
                            reg, expected, received,
                        ));
                    }
                }

                for (i, (expected, received)) in ref_mem.iter().zip(mem.iter()).enumerate() {
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
fn test_permutation_registers() {
    exhaust(
        &[
            instruction!(Mov_r64_rm64, Register::RBX, Register::RAX),
            instruction!(Mov_r64_rm64, Register::RAX, Register::RCX),
            instruction!(Mov_r64_rm64, Register::RDX, Register::RAX),
            instruction!(Cmp_rm64_imm32, Register::RDX, 0x1111_1111),
            instruction!(branch Je_rel8_64, 0x1111_1111),
        ],
        &[
            (VMReg::Rax, 0x1111_1111),
            (VMReg::Rbx, 0x2222_2222),
            (VMReg::Rcx, 0x3333_3333),
            (VMReg::Rdx, 0x4444_4444),
        ],
        &mut [],
    );
}

#[test]
fn test_permutation_memory() {
    let mut buf = [0u64; 4];
    let base = buf.as_mut_ptr() as u64;

    exhaust(
        &[
            instruction!(
                Mov_rm64_r64,
                MemoryOperand::with_base_displ_size(Register::RCX, 0, 8),
                Register::RAX
            ),
            instruction!(
                Mov_r64_rm64,
                Register::RBX,
                MemoryOperand::with_base_displ_size(Register::RCX, 0, 8)
            ),
            instruction!(
                Mov_rm64_r64,
                MemoryOperand::with_base_displ_size(Register::RCX, 8, 8),
                Register::RDX
            ),
            instruction!(Cmp_rm64_imm32, Register::RBX, 0x1111_1111),
            instruction!(branch Je_rel8_64, 0x1111_1111),
        ],
        &[
            (VMReg::Rax, 0x1111_1111),
            (VMReg::Rcx, base),
            (VMReg::Rdx, 0x3333_3333),
        ],
        &mut buf,
    );
}

#[test]
fn test_permutation_flags() {
    exhaust(
        &[
            instruction!(Add_r64_rm64, Register::RAX, Register::RBX),
            instruction!(Sub_r64_rm64, Register::RCX, Register::RDX),
            instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
            instruction!(branch Je_rel8_64, 0x1111_1111),
        ],
        &[
            (VMReg::Rax, 0x1111_1111),
            (VMReg::Rbx, 0x1111_1111),
            (VMReg::Rcx, 0x2222_2222),
            (VMReg::Rdx, 0x1111_1111),
        ],
        &mut [],
    );
}

#[test]
fn test_permutation_scratch() {
    let mut stack = [0u64; 8];
    let top = unsafe { stack.as_mut_ptr().add(stack.len()) as u64 };

    exhaust(
        &[
            instruction!(Push_r64, Register::RAX),
            instruction!(Push_r64, Register::RBX),
            instruction!(Pop_r64, Register::RCX),
            instruction!(Pop_r64, Register::RDX),
            instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
            instruction!(branch Je_rel8_64, 0x1111_1111),
        ],
        &[
            (VMReg::Rax, 0x1111_1111),
            (VMReg::Rbx, 0x2222_2222),
            (VMReg::Rsp, top),
        ],
        &mut stack,
    );
}

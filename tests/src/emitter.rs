use iced_x86::code_asm::{al, ax, bl, bx, eax, ebx, rax, rbx};
use iced_x86::Instruction;
use runtime::{emitter::Emitter, vm::bytecode::VMReg};

use crate::{
    constants::{baseline, IMM16_A, IMM32_A, IMM64_A, IMM64_B, IMM8_A, SIMM32_A},
    Executor,
};

fn dump(instructions: &[Instruction]) -> String {
    instructions
        .into_iter()
        .map(|i| format!("{}", i))
        .collect::<Vec<_>>()
        .join("\n")
}

macro_rules! obfuscated {
    ($name:ident, $setup:expr, $state:expr, $expected:expr, $actual:expr) => {
        #[test]
        fn $name() {
            let mut executor = Executor::new();
            let mut asm = Emitter::new(64).unwrap();
            $setup(&mut asm);
            let instructions = asm.instructions();

            for _ in 0..100 {
                let state = $state;
                let result = executor.run_native(state, instructions);
                let expected = $expected(&result);
                let actual = $actual(&result);
                assert_eq!(actual, expected, "{}", dump(instructions));
            }
        }
    };
}

obfuscated!(
    test_add_r64_r64,
    |asm: &mut Emitter| asm.add(rax, rbx).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rbx, IMM64_B)
    },
    |_| IMM64_A.wrapping_add(IMM64_B),
    |r: &crate::State| r.registers[&VMReg::Rax]
);

obfuscated!(
    test_sub_r64_r64,
    |asm: &mut Emitter| asm.sub(rax, rbx).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rbx, IMM64_B)
    },
    |_| IMM64_A.wrapping_sub(IMM64_B),
    |r: &crate::State| r.registers[&VMReg::Rax]
);

obfuscated!(
    test_add_r64_imm64,
    |asm: &mut Emitter| {
        asm.mov(rbx, IMM64_A).unwrap();
        asm.add(rax, rbx).unwrap();
    },
    { baseline().with(VMReg::Rax, IMM64_B) },
    |_| IMM64_B.wrapping_add(IMM64_A),
    |r: &crate::State| r.registers[&VMReg::Rax]
);

obfuscated!(
    test_sub_r64_imm64,
    |asm: &mut Emitter| {
        asm.mov(rbx, IMM64_A).unwrap();
        asm.sub(rax, rbx).unwrap();
    },
    { baseline().with(VMReg::Rax, IMM64_B) },
    |_| IMM64_B.wrapping_sub(IMM64_A),
    |r: &crate::State| r.registers[&VMReg::Rax]
);

obfuscated!(
    test_add_r32_r32,
    |asm: &mut Emitter| asm.add(eax, ebx).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM32_A as u64)
            .with(VMReg::Rbx, IMM32_A as u64)
    },
    |_| (IMM32_A as u32).wrapping_add(IMM32_A as u32) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u32 as u64
);

obfuscated!(
    test_sub_r32_r32,
    |asm: &mut Emitter| asm.sub(eax, ebx).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM32_A as u64)
            .with(VMReg::Rbx, IMM32_A as u64)
    },
    |_| (IMM32_A as u32).wrapping_sub(IMM32_A as u32) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u32 as u64
);

obfuscated!(
    test_add_r32_imm32,
    |asm: &mut Emitter| asm.add(eax, SIMM32_A).unwrap(),
    { baseline().with(VMReg::Rax, IMM32_A as u64) },
    |_| (IMM32_A as u32).wrapping_add(SIMM32_A as i32 as u32) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u32 as u64
);

obfuscated!(
    test_sub_r32_imm32,
    |asm: &mut Emitter| asm.sub(eax, SIMM32_A).unwrap(),
    { baseline().with(VMReg::Rax, IMM32_A as u64) },
    |_| (IMM32_A as u32).wrapping_sub(SIMM32_A as i32 as u32) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u32 as u64
);

obfuscated!(
    test_add_r16_r16,
    |asm: &mut Emitter| asm.add(ax, bx).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM16_A as u64)
            .with(VMReg::Rbx, IMM16_A as u64)
    },
    |_| (IMM16_A as u16).wrapping_add(IMM16_A as u16) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u16 as u64
);

obfuscated!(
    test_sub_r16_r16,
    |asm: &mut Emitter| asm.sub(ax, bx).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM16_A as u64)
            .with(VMReg::Rbx, IMM16_A as u64)
    },
    |_| (IMM16_A as u16).wrapping_sub(IMM16_A as u16) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u16 as u64
);

obfuscated!(
    test_add_r16_imm16,
    |asm: &mut Emitter| asm.add(ax, IMM16_A as i32).unwrap(),
    { baseline().with(VMReg::Rax, IMM16_A as u64) },
    |_| (IMM16_A as u16).wrapping_add(IMM16_A as u16) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u16 as u64
);

obfuscated!(
    test_sub_r16_imm16,
    |asm: &mut Emitter| asm.sub(ax, IMM16_A as i32).unwrap(),
    { baseline().with(VMReg::Rax, IMM16_A as u64) },
    |_| (IMM16_A as u16).wrapping_sub(IMM16_A as u16) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u16 as u64
);

obfuscated!(
    test_add_r8_r8,
    |asm: &mut Emitter| asm.add(al, bl).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM8_A as u64)
            .with(VMReg::Rbx, IMM8_A as u64)
    },
    |_| (IMM8_A as u8).wrapping_add(IMM8_A as u8) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u8 as u64
);

obfuscated!(
    test_sub_r8_r8,
    |asm: &mut Emitter| asm.sub(al, bl).unwrap(),
    {
        baseline()
            .with(VMReg::Rax, IMM8_A as u64)
            .with(VMReg::Rbx, IMM8_A as u64)
    },
    |_| (IMM8_A as u8).wrapping_sub(IMM8_A as u8) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u8 as u64
);

obfuscated!(
    test_add_r8_imm8,
    |asm: &mut Emitter| asm.add(al, IMM8_A as i32).unwrap(),
    { baseline().with(VMReg::Rax, IMM8_A as u64) },
    |_| (IMM8_A as u8).wrapping_add(IMM8_A as u8) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u8 as u64
);

obfuscated!(
    test_sub_r8_imm8,
    |asm: &mut Emitter| asm.sub(al, IMM8_A as i32).unwrap(),
    { baseline().with(VMReg::Rax, IMM8_A as u64) },
    |_| (IMM8_A as u8).wrapping_sub(IMM8_A as u8) as u64,
    |r: &crate::State| r.registers[&VMReg::Rax] as u8 as u64
);

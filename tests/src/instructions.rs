use iced_x86::{Instruction, MemoryOperand, Register};
use rand::Rng;
use runtime::vm::bytecode::{self, VMFlag, VMReg};

use crate::{decrypt, encrypt, instruction, Executor, BRANCH};

fn template(instructions: &[Instruction], setup: &[(VMReg, u64)], target: VMReg, expected: u64) {
    let mut executor = Executor::new();

    let lifted = bytecode::lift(&mut executor.rt.mapper, instructions).unwrap();

    let mut rng = rand::thread_rng();

    let bytecode = bytecode::transform(&mut executor.rt.mapper, lifted, |ready| {
        rng.gen_range(0..ready.len())
    });
    let mut bytes = bytecode::assemble(&mut executor.rt.mapper, &bytecode.operations);

    encrypt(&mut bytes);

    let state = executor.run(setup, &bytes);

    let received = state[(executor.rt.mapper.index(target)) as usize];

    assert_eq!(
        received,
        expected,
        "{:?} | {:?}: expected=0x{:X} received=0x{:X}",
        instructions[0].code(),
        target,
        expected,
        received,
    );
}

fn flag(f: VMFlag) -> u64 {
    1 << (f as u64)
}

macro_rules! case {
    ([$($i:expr),* $(,)?], [$($r:ident = $v:expr),* $(,)?], $t:ident => $e:expr) => {
        template(
            &[$($i),*],
            &[$((VMReg::$r, $v)),*],
            VMReg::$t,
            $e,
        );
    };
}

macro_rules! binary {
    ($name:ident, $op:ident,
        ($a64:expr, $b64:expr => $r64:expr),
        ($a32:expr, $i32:expr => $r32:expr),
        ($a16:expr, $i16:expr => $r16:expr),
        ($a8:expr,  $i8:expr  => $r8:expr) $(,)?
    ) => {
        #[test]
        fn $name() {
            paste::paste! {
                case!([instruction!([<$op _r64_rm64>], Register::RAX, Register::RBX)],
                      [Rax = $a64, Rbx = $b64], Rax => $r64);
                case!([instruction!([<$op _rm32_imm32>], Register::EAX, $i32)],
                      [Rax = $a32], Rax => $r32);
                case!([instruction!([<$op _rm16_imm16>], Register::AX, $i16)],
                      [Rax = $a16], Rax => $r16);
                case!([instruction!([<$op _rm8_imm8>], Register::AL, $i8)],
                      [Rax = $a8], Rax => $r8);
            }
        }
    };
}

macro_rules! cmov_case {
    ($cmov:ident, $cmp:expr, $rax:expr, $expected:expr) => {
        case!(
            [
                instruction!(Cmp_rm64_imm32, Register::RAX, $cmp),
                instruction!($cmov, Register::RBX, Register::RCX),
            ],
            [Rax = $rax, Rbx = 0x2222_2222, Rcx = 0x1111_1111],
            Rbx => $expected
        );
    };
}

#[test]
fn test_crypt() {
    let mut buffer = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let before = buffer.clone();

    encrypt(&mut buffer);

    decrypt(&mut buffer);

    let after = buffer.clone();

    assert_eq!(before, after);
}

#[test]
fn test_mov() {
    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x1111_1111_1111_1111u64)],
          [], Rax => 0x1111_1111_1111_1111);
    case!([instruction!(Mov_r32_imm32, Register::EAX, 0x1111_1111)],
          [], Rax => 0x1111_1111);
    case!([instruction!(Mov_r16_imm16, Register::AX, 0x1111)],
          [], Rax => 0x1111);
    case!([instruction!(Mov_r8_imm8, Register::AL, 0x11)],
          [], Rax => 0x11);
}

#[test]
fn test_jcc() {
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0x1111_1111], NBranch => BRANCH);
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(branch Jne_rel8_64, BRANCH)],
          [Rax = 0x2222_2222], NBranch => BRANCH);
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(branch Ja_rel8_64, BRANCH)],
          [Rax = 0x2222_2222], NBranch => BRANCH);
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(branch Jae_rel8_64, BRANCH)],
          [Rax = 0x2222_2222], NBranch => BRANCH);
}

#[test]
fn test_jmp() {
    case!([instruction!(Jmp_rm64, Register::RAX)],
          [Rax = BRANCH], NBranch => BRANCH);
    case!([instruction!(branch Jmp_rel32_64, BRANCH)],
          [], NBranch => BRANCH);
}

#[test]
fn test_lea() {
    case!([instruction!(Lea_r64_m, Register::RAX,
              MemoryOperand::with_base_displ_size(Register::RBX, 0x1111_1111, 8))],
          [Rbx = 0x1111_1111], Rax => 0x2222_2222);
    case!([instruction!(Lea_r32_m, Register::EAX,
              MemoryOperand::with_base_displ_size(Register::RBX, 0x1111_1111, 4))],
          [Rbx = 0x1111_1111], Rax => 0x2222_2222);
    case!([instruction!(Lea_r16_m, Register::AX,
              MemoryOperand::with_base_displ_size(Register::RBX, 0x1111, 2))],
          [Rbx = 0x1111], Rax => 0x2222);
    case!([instruction!(Lea_r16_m, Register::AX,
              MemoryOperand::with_base_displ_size(Register::RBX, 0x11, 2))],
          [Rbx = 0x11], Rax => 0x22);
}

#[test]
fn test_memory() {
    let mut buf = [0u64; 4];

    let base = buf.as_mut_ptr() as u64;

    let middle = unsafe { buf.as_mut_ptr().add(2) as u64 };

    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x1111_1111_1111_1111u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ_size(Register::RCX, 0, 8),
               Register::RAX),
           instruction!(Mov_r64_rm64, Register::RBX,
               MemoryOperand::with_base_displ_size(Register::RCX, 0, 8))],
          [Rcx = base], Rbx => 0x1111_1111_1111_1111);

    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x2222_2222_2222_2222u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ_size(Register::RCX, 16, 8),
               Register::RAX),
           instruction!(Mov_r64_rm64, Register::RBX,
               MemoryOperand::with_base_displ_size(Register::RCX, 16, 8))],
          [Rcx = base], Rbx => 0x2222_2222_2222_2222);

    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x3333_3333_3333_3333u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ_size(Register::RCX, -16, 8),
               Register::RAX),
           instruction!(Mov_r64_rm64, Register::RBX,
               MemoryOperand::with_base_displ_size(Register::RCX, -16, 8))],
          [Rcx = middle], Rbx => 0x3333_3333_3333_3333);
}

binary!(
    test_add, Add,
    (0x1111_1111, 0x1111_1111 => 0x2222_2222),
    (0x1111_1111, 0x1111_1111 => 0x2222_2222),
    (0x1111, 0x1111 => 0x2222),
    (0x11, 0x11 => 0x22),
);

binary!(
    test_sub, Sub,
    (0x2222_2222, 0x1111_1111 => 0x1111_1111),
    (0x2222_2222, 0x1111_1111 => 0x1111_1111),
    (0x2222, 0x1111 => 0x1111),
    (0x22, 0x11 => 0x11),
);

#[test]
fn test_cmp() {
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0x1111_1111], NBranch => BRANCH);
    case!([instruction!(Cmp_rm32_imm32, Register::EAX, 0x1111_1111),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0x1111_1111], NBranch => BRANCH);
    case!([instruction!(Cmp_rm16_imm16, Register::AX, 0x1111),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0x1111], NBranch => BRANCH);
    case!([instruction!(Cmp_rm8_imm8, Register::AL, 0x11),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0x11], NBranch => BRANCH);
}

binary!(
    test_and, And,
    (0xFF00_FF00, 0x0FF0_0FF0 => 0x0F00_0F00),
    (0xFF00_FF00, 0x0FF0_0FF0 => 0x0F00_0F00),
    (0xFF00, 0x0FF0 => 0x0F00),
    (0xFF, 0x0F => 0x0F),
);

binary!(
    test_or, Or,
    (0xFF00_0000, 0x0000_00FF => 0xFF00_00FF),
    (0xFF00_0000, 0x0000_00FF => 0xFF00_00FF),
    (0xFF00, 0x00FF => 0xFFFF),
    (0xF0, 0x0F => 0xFF),
);

binary!(
    test_xor, Xor,
    (0xFFFF_FFFF, 0x0F0F_0F0F => 0xF0F0_F0F0),
    (0xFFFF_FFFF, 0x0F0F_0F0F => 0xF0F0_F0F0),
    (0xFFFF, 0x0F0F => 0xF0F0),
    (0xFF, 0x0F => 0xF0),
);

#[test]
fn test_test() {
    case!([instruction!(Test_rm64_imm32, Register::RAX, 0x00FF),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0xFF00], NBranch => BRANCH);
    case!([instruction!(Test_rm32_imm32, Register::EAX, 0x00FF),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0xFF00], NBranch => BRANCH);
    case!([instruction!(Test_rm16_imm16, Register::AX, 0x00FF),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0xFF00], NBranch => BRANCH);
    case!([instruction!(Test_rm8_imm8, Register::AL, 0x0F),
           instruction!(branch Je_rel8_64, BRANCH)],
          [Rax = 0xF0], NBranch => BRANCH);
}

#[test]
fn test_rol() {
    case!([instruction!(Rol_rm64_CL, Register::RAX, Register::CL)],
          [Rax = 0x1111_1111_1111_1111, Rcx = 4], Rax => 0x1111_1111_1111_1111);
    case!([instruction!(Rol_rm32_imm8, Register::EAX, 4)],
          [Rax = 0x1111_1111], Rax => 0x1111_1111);
    case!([instruction!(Rol_rm16_imm8, Register::AX, 4)],
          [Rax = 0x1111], Rax => 0x1111);
    case!([instruction!(Rol_rm8_imm8, Register::AL, 4)],
          [Rax = 0x11], Rax => 0x11);
}

#[test]
fn test_ror() {
    case!([instruction!(Ror_rm64_CL, Register::RAX, Register::CL)],
          [Rax = 0x1111_1111_1111_1111, Rcx = 4], Rax => 0x1111_1111_1111_1111);
    case!([instruction!(Ror_rm32_imm8, Register::EAX, 4)],
          [Rax = 0x1111_1111], Rax => 0x1111_1111);
    case!([instruction!(Ror_rm16_imm8, Register::AX, 4)],
          [Rax = 0x1111], Rax => 0x1111);
    case!([instruction!(Ror_rm8_imm8, Register::AL, 4)],
          [Rax = 0x11], Rax => 0x11);
}

#[test]
fn test_shl() {
    case!([instruction!(Shl_rm64_CL, Register::RAX, Register::CL)],
          [Rax = 0x1111_1111_1111_1111, Rcx = 4], Rax => 0x1111_1111_1111_1110);
    case!([instruction!(Shl_rm32_imm8, Register::EAX, 4)],
          [Rax = 0x1111_1111], Rax => 0x1111_1110);
    case!([instruction!(Shl_rm16_imm8, Register::AX, 4)],
          [Rax = 0x1111], Rax => 0x1110);
    case!([instruction!(Shl_rm8_imm8, Register::AL, 4)],
          [Rax = 0x11], Rax => 0x10);
}

#[test]
fn test_shr() {
    case!([instruction!(Shr_rm64_CL, Register::RAX, Register::CL)],
          [Rax = 0x1111_1111_1111_1111, Rcx = 4], Rax => 0x0111_1111_1111_1111);
    case!([instruction!(Shr_rm32_imm8, Register::EAX, 4)],
          [Rax = 0x1111_1111], Rax => 0x0111_1111);
    case!([instruction!(Shr_rm16_imm8, Register::AX, 4)],
          [Rax = 0x1111], Rax => 0x0111);
    case!([instruction!(Shr_rm8_imm8, Register::AL, 4)],
          [Rax = 0x11], Rax => 0x01);
}

#[test]
fn test_sar() {
    case!([instruction!(Sar_rm64_CL, Register::RAX, Register::CL)],
          [Rax = 0xF111_1111_1111_1111, Rcx = 4], Rax => 0xFF11_1111_1111_1111);
    case!([instruction!(Sar_rm32_imm8, Register::EAX, 4)],
          [Rax = 0xF111_1111], Rax => 0xFF11_1111);
    case!([instruction!(Sar_rm16_imm8, Register::AX, 4)],
          [Rax = 0xF111], Rax => 0xFF11);
    case!([instruction!(Sar_rm8_imm8, Register::AL, 4)],
          [Rax = 0xF1], Rax => 0xFF);
}

#[test]
fn test_inc() {
    case!([instruction!(Inc_rm64, Register::RAX)],
          [Rax = 0x1111_1111_1111_1111], Rax => 0x1111_1111_1111_1112);
    case!([instruction!(Inc_rm32, Register::EAX)],
          [Rax = 0x1111_1111], Rax => 0x1111_1112);
    case!([instruction!(Inc_rm16, Register::AX)],
          [Rax = 0x1111], Rax => 0x1112);
    case!([instruction!(Inc_rm8, Register::AL)],
          [Rax = 0x11], Rax => 0x12);
}

#[test]
fn test_dec() {
    case!([instruction!(Dec_rm64, Register::RAX)],
          [Rax = 0x1111_1111_1111_1111], Rax => 0x1111_1111_1111_1110);
    case!([instruction!(Dec_rm32, Register::EAX)],
          [Rax = 0x1111_1111], Rax => 0x1111_1110);
    case!([instruction!(Dec_rm16, Register::AX)],
          [Rax = 0x1111], Rax => 0x1110);
    case!([instruction!(Dec_rm8, Register::AL)],
          [Rax = 0x11], Rax => 0x10);
}

#[test]
fn test_neg() {
    case!([instruction!(Neg_rm64, Register::RAX)],
          [Rax = 0x1111_1111_1111_1111], Rax => 0xEEEE_EEEE_EEEE_EEEF);
    case!([instruction!(Neg_rm32, Register::EAX)],
          [Rax = 0x1111_1111], Rax => 0xEEEE_EEEF);
    case!([instruction!(Neg_rm16, Register::AX)],
          [Rax = 0x1111], Rax => 0xEEEF);
    case!([instruction!(Neg_rm8, Register::AL)],
          [Rax = 0x11], Rax => 0xEF);
}

#[test]
fn test_not() {
    case!([instruction!(Not_rm64, Register::RAX)],
          [Rax = 0x1111_1111_1111_1111], Rax => 0xEEEE_EEEE_EEEE_EEEE);
    case!([instruction!(Not_rm32, Register::EAX)],
          [Rax = 0x1111_1111], Rax => 0xEEEE_EEEE);
    case!([instruction!(Not_rm16, Register::AX)],
          [Rax = 0x1111], Rax => 0xEEEE);
    case!([instruction!(Not_rm8, Register::AL)],
          [Rax = 0x11], Rax => 0xEE);
}

#[test]
fn test_mul() {
    case!([instruction!(Mul_rm64, Register::RBX)],
          [Rax = 0x1111_1111_1111_1111, Rbx = 0x10], Rax => 0x1111_1111_1111_1110);
    case!([instruction!(Mul_rm64, Register::RBX)],
          [Rax = 0x1111_1111_1111_1111, Rbx = 0x10], Rdx => 0x1);
    case!([instruction!(Mul_rm32, Register::EBX)],
          [Rax = 0x1111_1111, Rbx = 0x10], Rax => 0x1111_1110);
    case!([instruction!(Mul_rm32, Register::EBX)],
          [Rax = 0x1111_1111, Rbx = 0x10], Rdx => 0x1);
    case!([instruction!(Mul_rm8, Register::BL)],
          [Rax = 0x11, Rbx = 0x10], Rax => 0x110);
}

#[test]
fn test_imul() {
    case!([instruction!(Imul_rm64, Register::RBX)],
          [Rax = 0xFFFF_FFFF_FFFF_FFFF, Rbx = 0x10], Rax => 0xFFFF_FFFF_FFFF_FFF0);
    case!([instruction!(Imul_rm64, Register::RBX)],
          [Rax = 0xFFFF_FFFF_FFFF_FFFF, Rbx = 0x10], Rdx => 0xFFFF_FFFF_FFFF_FFFF);
    case!([instruction!(Imul_r64_rm64, Register::RAX, Register::RBX)],
          [Rax = 0x1111_1111_1111_1111, Rbx = 0x10], Rax => 0x1111_1111_1111_1110);
    case!([instruction!(Imul_r32_rm32, Register::EAX, Register::EBX)],
          [Rax = 0x1111_1111, Rbx = 0x10], Rax => 0x1111_1110);
}

#[test]
fn test_cmov() {
    cmov_case!(Cmove_r64_rm64, 0x1111_1111, 0x1111_1111, 0x1111_1111);
    cmov_case!(Cmovne_r64_rm64, 0x1111_1111, 0x2222_2222, 0x1111_1111);
    cmov_case!(Cmova_r64_rm64, 0x1111_1111, 0x2222_2222, 0x1111_1111);
    cmov_case!(Cmovae_r64_rm64, 0x1111_1111, 0x2222_2222, 0x1111_1111);
}

#[test]
fn test_push() {
    let mut stack = [0u64; 8];
    let top = unsafe { stack.as_mut_ptr().add(8) as u64 };

    case!([instruction!(Push_r64, Register::RAX),
           instruction!(Pop_r64, Register::RBX)],
          [Rax = 0x1111_1111, Rsp = top], Rbx => 0x1111_1111);
    case!([instruction!(Push_r64, Register::RCX),
           instruction!(Pop_r64, Register::RBX)],
          [Rcx = 0x1111_1111, Rsp = top], Rbx => 0x1111_1111);
    case!([instruction!(Push_r64, Register::RDX),
           instruction!(Pop_r64, Register::RBX)],
          [Rdx = 0x1111_1111, Rsp = top], Rbx => 0x1111_1111);
    case!([instruction!(Push_r64, Register::RSI),
           instruction!(Pop_r64, Register::RBX)],
          [Rsi = 0x1111_1111, Rsp = top], Rbx => 0x1111_1111);
}

#[test]
fn test_pop() {
    let mut stack = [0u64; 8];
    let top = unsafe { stack.as_mut_ptr().add(8) as u64 };

    case!([instruction!(Push_r64, Register::RAX),
           instruction!(Pop_r64, Register::RBX)],
          [Rax = 0x1111_1111, Rsp = top], Rbx => 0x1111_1111);
    case!([instruction!(Push_r64, Register::RAX),
           instruction!(Pop_r64, Register::RCX)],
          [Rax = 0x1111_1111, Rsp = top], Rcx => 0x1111_1111);
    case!([instruction!(Push_r64, Register::RAX),
           instruction!(Pop_r64, Register::RDX)],
          [Rax = 0x1111_1111, Rsp = top], Rdx => 0x1111_1111);
    case!([instruction!(Push_r64, Register::RAX),
           instruction!(Pop_r64, Register::RSI)],
          [Rax = 0x1111_1111, Rsp = top], Rsi => 0x1111_1111);
}

#[test]
fn test_set() {
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(Sete_rm8, Register::BL)],
          [Rax = 0x1111_1111], Rbx => 0x1);
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(Setne_rm8, Register::BL)],
          [Rax = 0x2222_2222], Rbx => 0x1);
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(Seta_rm8, Register::BL)],
          [Rax = 0x2222_2222], Rbx => 0x1);
    case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
           instruction!(Setae_rm8, Register::BL)],
          [Rax = 0x2222_2222], Rbx => 0x1);
}

#[test]
fn test_movzx() {
    case!([instruction!(Movzx_r16_rm8, Register::BX, Register::AL)],
          [Rax = 0xFF], Rbx => 0x00FF);
    case!([instruction!(Movzx_r32_rm8, Register::EBX, Register::AL)],
          [Rax = 0xFF], Rbx => 0x0000_00FF);
    case!([instruction!(Movzx_r64_rm8, Register::RBX, Register::AL)],
          [Rax = 0xFF], Rbx => 0x0000_0000_0000_00FF);
    case!([instruction!(Movzx_r64_rm16, Register::RBX, Register::AX)],
          [Rax = 0xFFFF], Rbx => 0x0000_0000_0000_FFFF);
}

#[test]
fn test_movsx() {
    case!([instruction!(Movsx_r16_rm8, Register::BX, Register::AL)],
          [Rax = 0xFF], Rbx => 0xFFFF);
    case!([instruction!(Movsx_r64_rm8, Register::RBX, Register::AL)],
          [Rax = 0xFF], Rbx => 0xFFFF_FFFF_FFFF_FFFF);
    case!([instruction!(Movsx_r64_rm16, Register::RBX, Register::AX)],
          [Rax = 0xFFFF], Rbx => 0xFFFF_FFFF_FFFF_FFFF);
    case!([instruction!(Movsxd_r64_rm32, Register::RBX, Register::EAX)],
          [Rax = 0xFFFF_FFFF], Rbx => 0xFFFF_FFFF_FFFF_FFFF);
}

#[test]
fn test_movups() {
    let mut buf = [0u64; 4];

    let base = buf.as_mut_ptr() as u64;

    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x1111_1111_1111_1111u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base(Register::RCX),
               Register::RAX),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ(Register::RCX, 8),
               Register::RAX),
           instruction!(Movups_xmm_xmmm128, Register::XMM0,
               MemoryOperand::with_base(Register::RCX)),
           instruction!(Movups_xmm_xmmm128, Register::XMM1, Register::XMM0),
           instruction!(Movups_xmmm128_xmm,
               MemoryOperand::with_base_displ(Register::RCX, 16),
               Register::XMM1),
           instruction!(Mov_r64_rm64, Register::RBX,
               MemoryOperand::with_base_displ(Register::RCX, 16))],
          [Rcx = base], Rbx => 0x1111_1111_1111_1111);
}

#[test]
fn test_pmovmskb() {
    let mut buf = [0u64; 2];

    let base = buf.as_mut_ptr() as u64;

    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x0000_0000_0000_0000u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base(Register::RCX),
               Register::RAX),
           instruction!(Mov_r64_imm64, Register::RAX, 0xFFFF_FFFF_FFFF_FFFFu64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ(Register::RCX, 8),
               Register::RAX),
           instruction!(Movups_xmm_xmmm128, Register::XMM0,
               MemoryOperand::with_base(Register::RCX)),
           instruction!(Pmovmskb_r32_xmm, Register::EAX, Register::XMM0)],
          [Rcx = base], Rax => 0xFF00);
}

#[test]
fn test_pcmpeqb() {
    let mut buf = [0u64; 6];

    let base = buf.as_mut_ptr() as u64;

    case!([instruction!(Mov_r64_imm64, Register::RAX, 0x1111_1111_1111_1111u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base(Register::RCX),
               Register::RAX),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ(Register::RCX, 8),
               Register::RAX),
           instruction!(Mov_r64_imm64, Register::RAX, 0x1111_1111_0000_0000u64),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ(Register::RCX, 16),
               Register::RAX),
           instruction!(Mov_rm64_r64,
               MemoryOperand::with_base_displ(Register::RCX, 24),
               Register::RAX),
           instruction!(Movups_xmm_xmmm128, Register::XMM0,
               MemoryOperand::with_base(Register::RCX)),
           instruction!(Movups_xmm_xmmm128, Register::XMM1,
               MemoryOperand::with_base_displ(Register::RCX, 16)),
           instruction!(Pcmpeqb_xmm_xmmm128, Register::XMM0, Register::XMM1),
           instruction!(Movups_xmmm128_xmm,
               MemoryOperand::with_base_displ(Register::RCX, 32),
               Register::XMM0),
           instruction!(Mov_r64_rm64, Register::RBX,
               MemoryOperand::with_base_displ(Register::RCX, 32))],
          [Rcx = base], Rbx => 0xFFFF_FFFF_0000_0000u64);
}

#[test]
fn test_tzcnt() {
    case!([instruction!(Tzcnt_r16_rm16, Register::BX, Register::AX)],
          [Rax = 0x100], Rbx => 8);
    case!([instruction!(Tzcnt_r32_rm32, Register::EBX, Register::EAX)],
          [Rax = 0x100], Rbx => 8);
    case!([instruction!(Tzcnt_r64_rm64, Register::RBX, Register::RAX)],
          [Rax = 0x100], Rbx => 8);
}

#[test]
fn test_flags() {
    // PF
    case!([instruction!(Add_rm64_imm8, Register::RAX, 0x1)],
          [Rax = 0x2],
          Flags => flag(VMFlag::Parity));
    // SF & PF
    case!([instruction!(Add_rm64_imm8, Register::RAX, -0x1)],
          [Rax = 0x0],
          Flags => flag(VMFlag::Sign) | flag(VMFlag::Parity));
    // OF & SF & AF & PF
    case!([instruction!(Add_rm64_imm8, Register::RAX, 0x1)],
          [Rax = 0x7FFF_FFFF_FFFF_FFFF],
          Flags => flag(VMFlag::Overflow) | flag(VMFlag::Sign)
                 | flag(VMFlag::Auxiliary) | flag(VMFlag::Parity));
    // ZF & CF & AF & PF
    case!([instruction!(Add_rm64_imm8, Register::RAX, 0x1)],
          [Rax = 0xFFFF_FFFF_FFFF_FFFF],
          Flags => flag(VMFlag::Carry) | flag(VMFlag::Parity)
                 | flag(VMFlag::Auxiliary) | flag(VMFlag::Zero));
}

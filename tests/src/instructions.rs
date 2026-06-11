use iced_x86::MemoryOperand;
use iced_x86::Register::{AL, CL, EAX, RAX, RBX, RCX, XMM0, XMM1, XMM2};
use iced_x86::{Instruction, RflagsBits};
use runtime::mapper::Mappable;
use runtime::vm::bytecode::{self, VMFlag, VMReg, VMVec};

use crate::{
    decrypt, encrypt, instruction, Difference, Executor, State, IMM128_A, IMM128_B, IMM128_C,
    IMM32_A, IMM64_A, IMM64_B, IMM64_C, IMM8_A,
};

#[test]
fn test_crypt() {
    let mut buffer = vec![0xDE, 0xAD, 0xC0, 0xDE];

    let before = buffer.clone();

    encrypt(&mut buffer);

    decrypt(&mut buffer);

    let after = buffer.clone();

    assert_eq!(before, after);
}

fn baseline() -> State {
    let mut state = State::default();

    for register in [
        VMReg::Rax,
        VMReg::Rcx,
        VMReg::Rdx,
        VMReg::Rbx,
        VMReg::Rbp,
        VMReg::Rsi,
        VMReg::Rdi,
        VMReg::R8,
        VMReg::R9,
        VMReg::R10,
        VMReg::R11,
        VMReg::R12,
        VMReg::R13,
        VMReg::R14,
        VMReg::R15,
        VMReg::Flags,
    ] {
        state.registers.insert(register, 0);
    }

    for &vector in VMVec::VARIANTS {
        state.vectors.insert(vector, [0u128; 2]);
    }

    state
}

fn vector(mut state: State, register: VMVec, bytes: [u128; 2]) -> State {
    state.vectors.insert(register, bytes);
    state
}

fn bytes16(value: u128) -> [u128; 2] {
    let mut vector = [0u128; 2];
    vector[0] = value;
    vector
}

fn gpr() -> State {
    baseline()
        .with(VMReg::Rax, IMM64_A)
        .with(VMReg::Rcx, IMM64_B)
        .with(VMReg::Rdx, IMM64_C)
}

fn simd() -> State {
    let state = baseline();
    let state = vector(state, VMVec::Ymm0, bytes16(IMM128_A));
    let state = vector(state, VMVec::Ymm1, bytes16(IMM128_B));
    vector(state, VMVec::Ymm2, bytes16(IMM128_C))
}

fn check(state: State, instruction: Instruction) {
    check_with_memory(state, instruction, &mut []);
}

fn check_with_memory(state: State, instruction: Instruction, memory: &mut [u8]) {
    let baseline = memory.to_vec();

    let mut executor = Executor::new();
    let mut native = executor.run_native(state.clone(), &instruction);

    memory.copy_from_slice(&baseline);

    let mut executor = Executor::new();
    let lifted = bytecode::lift(&mut executor.rt.mapper, &[instruction])
        .unwrap_or_else(|| panic!("{instruction} is not implemented"));
    let transformed = bytecode::transform(&mut executor.rt.mapper, lifted, |_| 0);

    let mut bytes = bytecode::assemble(&mut executor.rt.mapper, &transformed.operations);
    encrypt(&mut bytes);
    let mut emulated = executor.run_virtual(state.clone(), &bytes);

    normalize_and_compare(&mut native, &mut emulated, instruction);
}

fn normalize_and_compare(native: &mut State, emulated: &mut State, instruction: Instruction) {
    let normalize = |state: &mut State| {
        state.registers.remove(&VMReg::Rsp);

        if let Some(flags) = state.registers.get_mut(&VMReg::Flags) {
            let mask = instruction.rflags_written()
                | instruction.rflags_cleared()
                | instruction.rflags_set();
            *flags &= ((mask & RflagsBits::CF != 0) as u64 * VMFlag::Carry.bit64())
                | ((mask & RflagsBits::PF != 0) as u64 * VMFlag::Parity.bit64())
                | ((mask & RflagsBits::AF != 0) as u64 * VMFlag::Auxiliary.bit64())
                | ((mask & RflagsBits::ZF != 0) as u64 * VMFlag::Zero.bit64())
                | ((mask & RflagsBits::SF != 0) as u64 * VMFlag::Sign.bit64())
                | ((mask & RflagsBits::OF != 0) as u64 * VMFlag::Overflow.bit64());
        }
    };

    normalize(native);
    normalize(emulated);

    let differences = native.compare(emulated);

    assert!(differences.is_empty(), "{}", dump(&differences));
}

fn dump(differences: &[Difference]) -> String {
    let mut lines = Vec::new();

    for difference in differences {
        match difference {
            Difference::Register(register, native, emulated) => {
                lines.push(format!(
                    "{register:?}: native={native:016X} virtual={emulated:016X}"
                ));
            }
            Difference::Vector(register, native, emulated) => {
                lines.push(format!(
                    "{register:?}: native={native:02X?} virtual={emulated:02X?}"
                ));
            }
        }
    }

    lines.join("\n")
}

macro_rules! testing {
    ($name:ident, $state:expr, $instruction:expr) => {
        #[test]
        fn $name() {
            check($state, $instruction);
        }
    };
}

testing!(test_mov, gpr(), instruction!(Mov_r64_rm64, RAX, RCX));
testing!(test_movzx, gpr(), instruction!(Movzx_r64_rm8, RAX, CL));
testing!(test_movzsx, gpr(), instruction!(Movsx_r64_rm8, RAX, CL));
testing!(test_movzsxd, gpr(), instruction!(Movsxd_r64_rm32, RAX, EAX));
testing!(test_add, gpr(), instruction!(Add_rm64_r64, RAX, RCX));
testing!(test_sub, gpr(), instruction!(Sub_rm64_r64, RAX, RCX));
testing!(
    test_adc,
    gpr().with(VMReg::Flags, 0b0000000000000001u64),
    instruction!(Adc_rm64_r64, RAX, RCX)
);
testing!(
    test_sbb,
    gpr().with(VMReg::Flags, 0b0000000000000001u64),
    instruction!(Sbb_rm64_r64, RAX, RCX)
);
testing!(test_cmp, gpr(), instruction!(Cmp_rm64_r64, RAX, RCX));
testing!(test_test, gpr(), instruction!(Test_rm64_r64, RAX, RCX));
testing!(test_and, gpr(), instruction!(And_rm64_r64, RAX, RCX));
testing!(test_or, gpr(), instruction!(Or_rm64_r64, RAX, RCX));
testing!(test_xor, gpr(), instruction!(Xor_rm64_r64, RAX, RCX));
testing!(
    test_rol,
    gpr().with(VMReg::Rcx, IMM8_A),
    instruction!(Rol_rm64_CL, RAX, CL)
);
testing!(
    test_ror,
    gpr().with(VMReg::Rcx, IMM8_A),
    instruction!(Ror_rm64_CL, RAX, CL)
);
testing!(
    test_shl,
    gpr().with(VMReg::Rcx, IMM8_A),
    instruction!(Shl_rm64_CL, RAX, CL)
);
testing!(
    test_shr,
    gpr().with(VMReg::Rcx, IMM8_A),
    instruction!(Shr_rm64_CL, RAX, CL)
);
testing!(
    test_sar,
    gpr().with(VMReg::Rcx, IMM8_A),
    instruction!(Sar_rm64_CL, RAX, CL)
);
testing!(test_inc, gpr(), instruction!(Inc_rm64, RAX));
testing!(test_dec, gpr(), instruction!(Dec_rm64, RAX));
testing!(test_neg, gpr(), instruction!(Neg_rm64, RAX));
testing!(test_not, gpr(), instruction!(Not_rm64, RAX));
testing!(test_mul, gpr(), instruction!(Mul_rm64, RCX));
testing!(test_imul, gpr(), instruction!(Imul_rm64, RCX));
testing!(test_imul2, gpr(), instruction!(Imul_r64_rm64, RAX, RCX));
testing!(
    test_div,
    gpr().zeroed(VMReg::Rdx).with(VMReg::Rax, IMM64_A),
    instruction!(Div_rm64, RCX)
);
testing!(
    test_idiv,
    gpr().zeroed(VMReg::Rdx).with(VMReg::Rax, IMM64_A),
    instruction!(Idiv_rm64, RCX)
);
testing!(test_tzcnt, gpr(), instruction!(Tzcnt_r64_rm64, RAX, RCX));
testing!(test_bsr, gpr(), instruction!(Bsr_r64_rm64, RAX, RCX));
testing!(test_bswap, gpr(), instruction!(Bswap_r64, RAX));
testing!(test_bt, gpr(), instruction!(Bt_rm64_r64, RAX, RCX));
testing!(test_bts, gpr(), instruction!(Bts_rm64_r64, RAX, RCX));
testing!(test_btr, gpr(), instruction!(Btr_rm64_r64, RAX, RCX));
testing!(test_btc, gpr(), instruction!(Btc_rm64_r64, RAX, RCX));
testing!(test_xchg, gpr(), instruction!(Xchg_rm64_r64, RAX, RCX));
testing!(test_xadd, gpr(), instruction!(Xadd_rm64_r64, RAX, RCX));
testing!(
    test_cmpxchg,
    gpr(),
    instruction!(Cmpxchg_rm64_r64, RBX, RCX)
);
testing!(test_cmove, gpr(), instruction!(Cmove_r64_rm64, RAX, RCX));
testing!(test_cmovne, gpr(), instruction!(Cmovne_r64_rm64, RAX, RCX));
testing!(test_cmova, gpr(), instruction!(Cmova_r64_rm64, RAX, RCX));
testing!(test_cmovae, gpr(), instruction!(Cmovae_r64_rm64, RAX, RCX));
testing!(test_cmovb, gpr(), instruction!(Cmovb_r64_rm64, RAX, RCX));
testing!(test_cmovbe, gpr(), instruction!(Cmovbe_r64_rm64, RAX, RCX));
testing!(test_cmovg, gpr(), instruction!(Cmovg_r64_rm64, RAX, RCX));
testing!(test_cmovge, gpr(), instruction!(Cmovge_r64_rm64, RAX, RCX));
testing!(test_cmovl, gpr(), instruction!(Cmovl_r64_rm64, RAX, RCX));
testing!(test_cmovle, gpr(), instruction!(Cmovle_r64_rm64, RAX, RCX));
testing!(test_cmovo, gpr(), instruction!(Cmovo_r64_rm64, RAX, RCX));
testing!(test_cmovno, gpr(), instruction!(Cmovno_r64_rm64, RAX, RCX));
testing!(test_cmovp, gpr(), instruction!(Cmovp_r64_rm64, RAX, RCX));
testing!(test_cmovnp, gpr(), instruction!(Cmovnp_r64_rm64, RAX, RCX));
testing!(test_cmovs, gpr(), instruction!(Cmovs_r64_rm64, RAX, RCX));
testing!(test_cmovns, gpr(), instruction!(Cmovns_r64_rm64, RAX, RCX));
testing!(test_seta, gpr(), instruction!(Seta_rm8, AL));
testing!(test_setae, gpr(), instruction!(Setae_rm8, AL));
testing!(test_setb, gpr(), instruction!(Setb_rm8, AL));
testing!(test_setbe, gpr(), instruction!(Setbe_rm8, AL));
testing!(test_sete, gpr(), instruction!(Sete_rm8, AL));
testing!(test_setg, gpr(), instruction!(Setg_rm8, AL));
testing!(test_setge, gpr(), instruction!(Setge_rm8, AL));
testing!(test_setl, gpr(), instruction!(Setl_rm8, AL));
testing!(test_setle, gpr(), instruction!(Setle_rm8, AL));
testing!(test_setne, gpr(), instruction!(Setne_rm8, AL));
testing!(test_seto, gpr(), instruction!(Seto_rm8, AL));
testing!(test_setno, gpr(), instruction!(Setno_rm8, AL));
testing!(test_setp, gpr(), instruction!(Setp_rm8, AL));
testing!(test_setnp, gpr(), instruction!(Setnp_rm8, AL));
testing!(test_sets, gpr(), instruction!(Sets_rm8, AL));
testing!(test_setns, gpr(), instruction!(Setns_rm8, AL));
testing!(
    test_movaps,
    simd(),
    instruction!(Movaps_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_movups,
    simd(),
    instruction!(Movups_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_movapd,
    simd(),
    instruction!(Movapd_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_movupd,
    simd(),
    instruction!(Movupd_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_movdqa,
    simd(),
    instruction!(Movdqa_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_movdqu,
    simd(),
    instruction!(Movdqu_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_movss,
    simd(),
    instruction!(Movss_xmm_xmmm32, XMM0, XMM1)
);
testing!(
    test_movsd,
    simd(),
    instruction!(Movsd_xmm_xmmm64, XMM0, XMM1)
);
testing!(
    test_pand,
    simd(),
    instruction!(Pand_xmm_xmmm128, XMM0, XMM1)
);
testing!(test_por, simd(), instruction!(Por_xmm_xmmm128, XMM0, XMM1));
testing!(
    test_pxor,
    simd(),
    instruction!(Pxor_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_pandn,
    simd(),
    instruction!(Pandn_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_andps,
    simd(),
    instruction!(Andps_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_andpd,
    simd(),
    instruction!(Andpd_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_andnps,
    simd(),
    instruction!(Andnps_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_andnpd,
    simd(),
    instruction!(Andnpd_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_orps,
    simd(),
    instruction!(Orps_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_orpd,
    simd(),
    instruction!(Orpd_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_xorps,
    simd(),
    instruction!(Xorps_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_xorpd,
    simd(),
    instruction!(Xorpd_xmm_xmmm128, XMM0, XMM1)
);
testing!(
    test_vandps,
    simd(),
    instruction!(VEX_Vandps_xmm_xmm_xmmm128, XMM0, XMM1, XMM2)
);
testing!(
    test_vpxor,
    simd(),
    instruction!(VEX_Vpxor_xmm_xmm_xmmm128, XMM0, XMM1, XMM2)
);
testing!(
    test_vxorps,
    simd(),
    instruction!(VEX_Vxorps_xmm_xmm_xmmm128, XMM0, XMM1, XMM2)
);

testing!(
    test_mov_imm64,
    gpr(),
    instruction!(Mov_r64_imm64, RAX, IMM64_A as i64)
);
testing!(
    test_mov_imm32,
    gpr(),
    instruction!(Mov_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_add_imm32,
    gpr(),
    instruction!(Add_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_add_imm8,
    gpr(),
    instruction!(Add_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_sub_imm32,
    gpr(),
    instruction!(Sub_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_sub_imm8,
    gpr(),
    instruction!(Sub_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_adc_imm32,
    gpr().with(VMReg::Flags, 0b0000000000000001u64),
    instruction!(Adc_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_adc_imm8,
    gpr().with(VMReg::Flags, 0b0000000000000001u64),
    instruction!(Adc_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_sbb_imm32,
    gpr().with(VMReg::Flags, 0b0000000000000001u64),
    instruction!(Sbb_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_sbb_imm8,
    gpr().with(VMReg::Flags, 0b0000000000000001u64),
    instruction!(Sbb_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_cmp_imm32,
    gpr(),
    instruction!(Cmp_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_cmp_imm8,
    gpr(),
    instruction!(Cmp_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_and_imm32,
    gpr(),
    instruction!(And_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_and_imm8,
    gpr(),
    instruction!(And_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_or_imm32,
    gpr(),
    instruction!(Or_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_or_imm8,
    gpr(),
    instruction!(Or_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_xor_imm32,
    gpr(),
    instruction!(Xor_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_xor_imm8,
    gpr(),
    instruction!(Xor_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_test_imm32,
    gpr(),
    instruction!(Test_rm64_imm32, RAX, IMM32_A as i32)
);
testing!(
    test_rol_imm8,
    gpr(),
    instruction!(Rol_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_ror_imm8,
    gpr(),
    instruction!(Ror_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_shl_imm8,
    gpr(),
    instruction!(Shl_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_shr_imm8,
    gpr(),
    instruction!(Shr_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_sar_imm8,
    gpr(),
    instruction!(Sar_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_imul3,
    gpr(),
    instruction!(Imul_r64_rm64_imm32, RAX, RCX, IMM32_A as i32)
);
testing!(
    test_imul3_imm8,
    gpr(),
    instruction!(Imul_r64_rm64_imm8, RAX, RCX, IMM8_A as i32)
);
testing!(
    test_bt_imm8,
    gpr(),
    instruction!(Bt_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_bts_imm8,
    gpr(),
    instruction!(Bts_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_btr_imm8,
    gpr(),
    instruction!(Btr_rm64_imm8, RAX, IMM8_A as i32)
);
testing!(
    test_btc_imm8,
    gpr(),
    instruction!(Btc_rm64_imm8, RAX, IMM8_A as i32)
);

#[test]
fn test_mov_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Mov_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_mov_store() {
    let mut buf = [0u64];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Mov_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_movzx_load() {
    let buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Movzx_r64_rm8, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_movsx_load() {
    let buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Movsx_r64_rm8, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_movsxd_load() {
    let buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Movsxd_r64_rm32, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_add_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Add_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_add_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Add_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_sub_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Sub_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_sub_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Sub_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_adc_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Flags, 0b0000000000000001u64)
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Adc_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_adc_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Flags, 0b0000000000000001u64)
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Adc_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_sbb_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Flags, 0b0000000000000001u64)
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Sbb_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_sbb_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Flags, 0b0000000000000001u64)
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Sbb_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_cmp_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Cmp_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_cmp_store() {
    let buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Cmp_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_test_store() {
    let buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Test_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_and_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(And_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_and_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(And_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_or_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Or_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_or_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Or_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_xor_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_A),
        instruction!(Xor_r64_rm64, RCX, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_xor_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Xor_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_inc_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Inc_rm64, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_dec_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Dec_rm64, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_neg_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Neg_rm64, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_not_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Not_rm64, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_mul_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Mul_rm64, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_imul_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Imul_rm64, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_imul2_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Imul_r64_rm64, RAX, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_div_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rdx, 0u64)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Div_rm64, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_idiv_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rdx, 0u64)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Idiv_rm64, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_tzcnt_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Tzcnt_r64_rm64, RAX, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_bsr_load() {
    let buf = [IMM64_B];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rcx, buf.as_ptr() as u64),
        instruction!(Bsr_r64_rm64, RAX, MemoryOperand::with_base(RCX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_bt_store() {
    let buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Bt_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_bts_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Bts_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_btr_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Btr_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_btc_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Btc_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_xchg_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Xchg_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_xadd_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Xadd_rm64_r64, MemoryOperand::with_base(RAX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_cmpxchg_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, IMM64_A)
            .with(VMReg::Rbx, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM64_B),
        instruction!(Cmpxchg_rm64_r64, MemoryOperand::with_base(RBX), RCX),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_rol_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM8_A),
        instruction!(Rol_rm64_CL, MemoryOperand::with_base(RAX), CL),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_ror_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM8_A),
        instruction!(Ror_rm64_CL, MemoryOperand::with_base(RAX), CL),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_shl_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM8_A),
        instruction!(Shl_rm64_CL, MemoryOperand::with_base(RAX), CL),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_shr_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM8_A),
        instruction!(Shr_rm64_CL, MemoryOperand::with_base(RAX), CL),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_sar_store() {
    let mut buf = [IMM64_A];
    check_with_memory(
        baseline()
            .with(VMReg::Rax, buf.as_mut_ptr() as u64)
            .with(VMReg::Rcx, IMM8_A),
        instruction!(Sar_rm64_CL, MemoryOperand::with_base(RAX), CL),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 8) },
    );
}

#[test]
fn test_seta_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Seta_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setae_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setae_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setb_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setb_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setbe_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setbe_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_sete_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Sete_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setg_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setg_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setge_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setge_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setl_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setl_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setle_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setle_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setne_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setne_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_seto_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Seto_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setno_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setno_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setp_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setp_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setnp_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setnp_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_sets_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Sets_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_setns_store() {
    let mut buf = [0u8];
    check_with_memory(
        baseline().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Setns_rm8, MemoryOperand::with_base(RAX)),
        &mut buf,
    );
}

#[test]
fn test_movaps_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movaps_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movaps_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movaps_xmmm128_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movups_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movups_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movups_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movups_xmmm128_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movapd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movapd_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movapd_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movapd_xmmm128_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movupd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movupd_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movupd_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movupd_xmmm128_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movdqa_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movdqa_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movdqa_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movdqa_xmmm128_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movdqu_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movdqu_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movdqu_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movdqu_xmmm128_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movss_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movss_xmm_xmmm32, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movss_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movss_xmmm32_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movsd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Movsd_xmm_xmmm64, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_movsd_store() {
    let mut buf = [0u128, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_mut_ptr() as u64),
        instruction!(Movsd_xmmm64_xmm, MemoryOperand::with_base(RAX), XMM1),
        unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_pand_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Pand_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_por_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Por_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_pxor_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Pxor_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_pandn_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Pandn_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_andps_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Andps_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_andpd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Andpd_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_andnps_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Andnps_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_andnpd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Andnpd_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_orps_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Orps_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_orpd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Orpd_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_xorps_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Xorps_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_xorpd_load() {
    let buf = [IMM128_B, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(Xorpd_xmm_xmmm128, XMM0, MemoryOperand::with_base(RAX)),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_vandps_load() {
    let buf = [IMM128_C, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(
            VEX_Vandps_xmm_xmm_xmmm128,
            XMM0,
            XMM1,
            MemoryOperand::with_base(RAX)
        ),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_vpxor_load() {
    let buf = [IMM128_C, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(
            VEX_Vpxor_xmm_xmm_xmmm128,
            XMM0,
            XMM1,
            MemoryOperand::with_base(RAX)
        ),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

#[test]
fn test_vxorps_load() {
    let buf = [IMM128_C, 0u128];
    check_with_memory(
        simd().with(VMReg::Rax, buf.as_ptr() as u64),
        instruction!(
            VEX_Vxorps_xmm_xmm_xmmm128,
            XMM0,
            XMM1,
            MemoryOperand::with_base(RAX)
        ),
        unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, 32) },
    );
}

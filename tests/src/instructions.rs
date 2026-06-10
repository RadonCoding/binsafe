use iced_x86::Register::{AL, CL, RAX, RBX, RCX, XMM0, XMM1, XMM2};
use iced_x86::{Instruction, RflagsBits};
use rand::Rng;
use runtime::mapper::Mappable;
use runtime::vm::bytecode::{self, VMFlag, VMReg, VMVec};

use crate::{decrypt, encrypt, instruction, Difference, Executor, State};

const A: u64 = 0x1111_1111_1111_1111;
const B: u64 = 0x2222_2222_2222_2222;
const C: u64 = 0x3333_3333_3333_3333;
const D: u64 = 0x4444_4444_4444_4444;

const P0: u128 = 0x1111_1111_1111_1111_1111_1111_1111_1111;
const P1: u128 = 0x2222_2222_2222_2222_2222_2222_2222_2222;
const P2: u128 = 0x3333_3333_3333_3333_3333_3333_3333_3333;

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
        .with(VMReg::Rax, A)
        .with(VMReg::Rcx, B)
        .with(VMReg::Rdx, C)
        .with(VMReg::Rbx, D)
}

fn simd() -> State {
    let state = baseline();
    let state = vector(state, VMVec::Ymm0, bytes16(P0));
    let state = vector(state, VMVec::Ymm1, bytes16(P1));
    vector(state, VMVec::Ymm2, bytes16(P2))
}

fn check(state: State, instruction: Instruction) {
    let mut executor = Executor::new();

    let mut native = executor.run_native(state.clone(), &instruction);

    let mut executor = Executor::new();

    let lifted = bytecode::lift(&mut executor.rt.mapper, &[instruction])
        .unwrap_or_else(|| panic!("{instruction} is not implemented"));

    let mut rng = rand::thread_rng();

    let transformed = bytecode::transform(&mut executor.rt.mapper, lifted, |ready| {
        rng.gen_range(0..ready.len())
    });

    let mut bytes = bytecode::assemble(&mut executor.rt.mapper, &transformed.operations);

    encrypt(&mut bytes);

    let mut emulated = executor.run_virtual(state, &bytes);

    for state in [&mut native, &mut emulated] {
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
    }

    let differences = native.compare(&emulated);

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
testing!(test_add, gpr(), instruction!(Add_rm64_r64, RAX, RCX));
testing!(test_sub, gpr(), instruction!(Sub_rm64_r64, RAX, RCX));
testing!(
    test_adc,
    gpr().with(VMReg::Flags, 0b0000000000000001),
    instruction!(Adc_rm64_r64, RAX, RCX)
);
testing!(
    test_sbb,
    gpr().with(VMReg::Flags, 0b0000000000000001),
    instruction!(Sbb_rm64_r64, RAX, RCX)
);
testing!(test_cmp, gpr(), instruction!(Cmp_rm64_r64, RAX, RCX));
testing!(test_test, gpr(), instruction!(Test_rm64_r64, RAX, RCX));
testing!(test_and, gpr(), instruction!(And_rm64_r64, RAX, RCX));
testing!(test_or, gpr(), instruction!(Or_rm64_r64, RAX, RCX));
testing!(test_xor, gpr(), instruction!(Xor_rm64_r64, RAX, RCX));
testing!(
    test_rol,
    gpr().with(VMReg::Rcx, 3),
    instruction!(Rol_rm64_CL, RAX, CL)
);
testing!(
    test_ror,
    gpr().with(VMReg::Rcx, 3),
    instruction!(Ror_rm64_CL, RAX, CL)
);
testing!(
    test_shl,
    gpr().with(VMReg::Rcx, 3),
    instruction!(Shl_rm64_CL, RAX, CL)
);
testing!(
    test_shr,
    gpr().with(VMReg::Rcx, 3),
    instruction!(Shr_rm64_CL, RAX, CL)
);
testing!(
    test_sar,
    gpr().with(VMReg::Rcx, 3),
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
    gpr().with(VMReg::Rdx, 0).with(VMReg::Rax, A),
    instruction!(Div_rm64, RCX)
);
testing!(
    test_idiv,
    gpr().with(VMReg::Rdx, 0).with(VMReg::Rax, A),
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

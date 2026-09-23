use std::slice;

use iced_x86::{
    Code, Instruction, InstructionInfoFactory, OpAccess, OpCodeOperandKind, OpKind, Register,
    RflagsBits,
};
use runtime::vm::bytecode::{self, Flag, VMReg, VMVec};

use crate::constants::{available, baseline, register, vector, IMMEDIATES};
use crate::{decrypt_block, decrypt_payload, encrypt_block, Difference, Executor, State};

#[test]
fn test_crypt() {
    let mut buffer = vec![0xDE, 0xAD, 0xC0, 0xDE];

    let before = buffer.clone();

    encrypt_block(&mut buffer);

    decrypt_block(&mut buffer);

    assert_eq!(before, buffer);
}

macro_rules! define {
    ($($code:ident)+ $(,)?) => {
        $(
            paste::paste! {
                #[test]
                fn [<test_ $code:lower>]() {
                    test(Code::$code);
                }
            }
        )+
    };
}

define!(
Adc_r64_rm64
Adc_rm16_r16
Adc_rm32_r32
Adc_rm64_imm32
Adc_rm64_imm8
Adc_rm64_r64
Adc_rm8_r8
Add_r64_rm64
Add_rm16_r16
Add_rm32_r32
Add_rm64_imm32
Add_rm64_imm8
Add_rm64_r64
Add_rm8_r8
Addpd_xmm_xmmm128
Addps_xmm_xmmm128
And_r64_rm64
And_rm16_r16
And_rm32_r32
And_rm64_imm32
And_rm64_imm8
And_rm64_r64
And_rm8_r8
Andnpd_xmm_xmmm128
Andnps_xmm_xmmm128
Andpd_xmm_xmmm128
Andps_xmm_xmmm128
Bsr_r64_rm64
Bswap_r64
Bt_rm64_imm8
Bt_rm64_r64
Btc_rm64_imm8
Btc_rm64_r64
Btr_rm64_imm8
Btr_rm64_r64
Bts_rm64_imm8
Bts_rm64_r64
Cmp_r64_rm64
Cmp_rm16_r16
Cmp_rm32_r32
Cmp_rm64_imm32
Cmp_rm64_imm8
Cmp_rm64_r64
Cmp_rm8_r8
Cmpxchg_rm64_r64
Dec_rm64
Div_rm64
Divpd_xmm_xmmm128
Divps_xmm_xmmm128
Idiv_rm64
Imul_r64_rm64
Imul_r64_rm64_imm32
Imul_r64_rm64_imm8
Imul_rm64
Inc_rm64
Mov_r64_imm64
Mov_r64_rm64
Mov_rm64_imm32
Mov_rm64_r64
Movapd_xmm_xmmm128
Movapd_xmmm128_xmm
Movaps_xmm_xmmm128
Movaps_xmmm128_xmm
Movd_rm32_xmm
Movd_xmm_rm32
Movdqa_xmm_xmmm128
Movdqa_xmmm128_xmm
Movdqu_xmm_xmmm128
Movdqu_xmmm128_xmm
Movq_rm64_xmm
Movq_xmm_rm64
Movsd_xmm_xmmm64
Movsd_xmmm64_xmm
Movss_xmm_xmmm32
Movss_xmmm32_xmm
Movsx_r64_rm8
Movsxd_r64_rm32
Movupd_xmm_xmmm128
Movupd_xmmm128_xmm
Movups_xmm_xmmm128
Movups_xmmm128_xmm
Movzx_r64_rm8
Mul_rm64
Mulpd_xmm_xmmm128
Mulps_xmm_xmmm128
Neg_rm64
Not_rm64
Or_r64_rm64
Or_rm16_r16
Or_rm32_r32
Or_rm64_imm32
Or_rm64_imm8
Or_rm64_r64
Or_rm8_r8
Orpd_xmm_xmmm128
Orps_xmm_xmmm128
Paddb_xmm_xmmm128
Paddd_xmm_xmmm128
Paddq_xmm_xmmm128
Paddw_xmm_xmmm128
Pand_xmm_xmmm128
Pandn_xmm_xmmm128
Pcmpeqb_xmm_xmmm128
Pmovmskb_r64_xmm
Pmulld_xmm_xmmm128
Pmullw_xmm_xmmm128
Por_xmm_xmmm128
Psubb_xmm_xmmm128
Psubd_xmm_xmmm128
Psubq_xmm_xmmm128
Psubw_xmm_xmmm128
Pxor_xmm_xmmm128
Rol_rm64_CL
Rol_rm64_imm8
Ror_rm64_CL
Ror_rm64_imm8
Sar_rm64_CL
Sar_rm64_imm8
Sbb_r64_rm64
Sbb_rm16_r16
Sbb_rm32_r32
Sbb_rm64_imm32
Sbb_rm64_imm8
Sbb_rm64_r64
Sbb_rm8_r8
Seta_rm8
Setae_rm8
Setb_rm8
Setbe_rm8
Sete_rm8
Setg_rm8
Setge_rm8
Setl_rm8
Setle_rm8
Setne_rm8
Setno_rm8
Setnp_rm8
Setns_rm8
Seto_rm8
Setp_rm8
Sets_rm8
Shl_rm64_CL
Shl_rm64_imm8
Shr_rm64_CL
Shr_rm64_imm8
Sub_r64_rm64
Sub_rm16_r16
Sub_rm32_r32
Sub_rm64_imm32
Sub_rm64_imm8
Sub_rm64_r64
Sub_rm8_r8
Subpd_xmm_xmmm128
Subps_xmm_xmmm128
Test_rm16_r16
Test_rm32_r32
Test_rm64_imm32
Test_rm64_r64
Test_rm8_r8
Tzcnt_r64_rm64
VEX_Vaddpd_xmm_xmm_xmmm128
VEX_Vaddps_xmm_xmm_xmmm128
VEX_Vandps_xmm_xmm_xmmm128
VEX_Vdivpd_xmm_xmm_xmmm128
VEX_Vdivps_xmm_xmm_xmmm128
VEX_Vmulpd_xmm_xmm_xmmm128
VEX_Vmulps_xmm_xmm_xmmm128
VEX_Vpmulhw_xmm_xmm_xmmm128
VEX_Vpmulld_xmm_xmm_xmmm128
VEX_Vpmullw_xmm_xmm_xmmm128
VEX_Vpxor_xmm_xmm_xmmm128
VEX_Vsubpd_xmm_xmm_xmmm128
VEX_Vsubps_xmm_xmm_xmmm128
VEX_Vxorps_xmm_xmm_xmmm128
Xadd_rm64_r64
Xchg_rm64_r64
Xor_r64_rm64
Xor_rm16_r16
Xor_rm32_r32
Xor_rm64_imm32
Xor_rm64_imm8
Xor_rm64_r64
Xor_rm8_r8
Xorpd_xmm_xmmm128
Xorps_xmm_xmmm128
Adc_r8_rm8
Adc_r16_rm16
Adc_r32_rm32
Add_r8_rm8
Add_r16_rm16
Add_r32_rm32
And_r8_rm8
And_r16_rm16
And_r32_rm32
Cmp_r8_rm8
Cmp_r16_rm16
Cmp_r32_rm32
Or_r8_rm8
Or_r16_rm16
Or_r32_rm32
Sbb_r8_rm8
Sbb_r16_rm16
Sbb_r32_rm32
Sub_r8_rm8
Sub_r16_rm16
Sub_r32_rm32
Xor_r8_rm8
Xor_r16_rm16
Xor_r32_rm32
Mov_rm8_r8
Mov_rm16_r16
Mov_rm32_r32
Mov_r8_rm8
Mov_r16_rm16
Mov_r32_rm32
Mov_r8_imm8
Mov_r16_imm16
Mov_r32_imm32
Mov_rm8_imm8
Mov_rm16_imm16
Mov_rm32_imm32
Inc_rm8
Inc_rm16
Inc_rm32
Dec_rm8
Dec_rm16
Dec_rm32
Neg_rm8
Neg_rm16
Neg_rm32
Not_rm8
Not_rm16
Not_rm32
Bswap_r32
Rol_rm8_CL
Rol_rm16_CL
Rol_rm32_CL
Ror_rm8_CL
Ror_rm16_CL
Ror_rm32_CL
Shl_rm8_CL
Shl_rm16_CL
Shl_rm32_CL
Shr_rm8_CL
Shr_rm16_CL
Shr_rm32_CL
Sar_rm8_CL
Sar_rm16_CL
Sar_rm32_CL
Rol_rm8_imm8
Rol_rm16_imm8
Rol_rm32_imm8
Ror_rm8_imm8
Ror_rm16_imm8
Ror_rm32_imm8
Shl_rm8_imm8
Shl_rm16_imm8
Shl_rm32_imm8
Shr_rm8_imm8
Shr_rm16_imm8
Shr_rm32_imm8
Sar_rm8_imm8
Sar_rm16_imm8
Sar_rm32_imm8
Mul_rm8
Mul_rm16
Mul_rm32
Imul_rm8
Imul_rm16
Imul_rm32
Imul_r16_rm16
Imul_r32_rm32
Imul_r16_rm16_imm16
Imul_r32_rm32_imm32
Imul_r16_rm16_imm8
Imul_r32_rm32_imm8
Div_rm8
Div_rm16
Div_rm32
Idiv_rm8
Idiv_rm16
Idiv_rm32
Bt_rm16_r16
Bt_rm32_r32
Btc_rm16_r16
Btc_rm32_r32
Btr_rm16_r16
Btr_rm32_r32
Bts_rm16_r16
Bts_rm32_r32
Bt_rm16_imm8
Bt_rm32_imm8
Btc_rm16_imm8
Btc_rm32_imm8
Btr_rm16_imm8
Btr_rm32_imm8
Bts_rm16_imm8
Bts_rm32_imm8
Bsr_r16_rm16
Bsr_r32_rm32
Tzcnt_r16_rm16
Tzcnt_r32_rm32
Xadd_rm8_r8
Xadd_rm16_r16
Xadd_rm32_r32
Xchg_rm8_r8
Xchg_rm16_r16
Xchg_rm32_r32
Cmpxchg_rm8_r8
Cmpxchg_rm16_r16
Cmpxchg_rm32_r32
Movsx_r16_rm8
Movsx_r32_rm8
Movsx_r16_rm16
Movsx_r32_rm16
Movzx_r16_rm8
Movzx_r32_rm8
Movzx_r16_rm16
Movzx_r32_rm16
Test_rm8_imm8
Test_rm16_imm16
Test_rm32_imm32
Add_rm8_imm8
Add_rm16_imm16
Add_rm32_imm32
Add_rm16_imm8
Add_rm32_imm8
Or_rm8_imm8
Or_rm16_imm16
Or_rm32_imm32
Or_rm16_imm8
Or_rm32_imm8
Adc_rm8_imm8
Adc_rm16_imm16
Adc_rm32_imm32
Adc_rm16_imm8
Adc_rm32_imm8
Sbb_rm8_imm8
Sbb_rm16_imm16
Sbb_rm32_imm32
Sbb_rm16_imm8
And_rm8_imm8
And_rm16_imm16
And_rm32_imm32
And_rm16_imm8
Sub_rm8_imm8
Sub_rm16_imm16
Sub_rm32_imm32
Sub_rm16_imm8
Sub_rm32_imm8
Xor_rm8_imm8
Xor_rm16_imm16
Xor_rm32_imm32
Xor_rm16_imm8
Xor_rm32_imm8
Cmp_rm8_imm8
Cmp_rm16_imm16
Cmp_rm32_imm32
Cmp_rm16_imm8
Cmp_rm32_imm8
Cmova_r16_rm16
Cmova_r32_rm32
Cmova_r64_rm64
Cmovae_r16_rm16
Cmovae_r32_rm32
Cmovae_r64_rm64
Cmovb_r16_rm16
Cmovb_r32_rm32
Cmovb_r64_rm64
Cmovbe_r16_rm16
Cmovbe_r32_rm32
Cmovbe_r64_rm64
Cmove_r16_rm16
Cmove_r32_rm32
Cmove_r64_rm64
Cmovg_r16_rm16
Cmovg_r32_rm32
Cmovg_r64_rm64
Cmovge_r16_rm16
Cmovge_r32_rm32
Cmovge_r64_rm64
Cmovl_r16_rm16
Cmovl_r32_rm32
Cmovl_r64_rm64
Cmovle_r16_rm16
Cmovle_r32_rm32
Cmovle_r64_rm64
Cmovne_r16_rm16
Cmovne_r32_rm32
Cmovne_r64_rm64
Cmovno_r16_rm16
Cmovno_r32_rm32
Cmovno_r64_rm64
Cmovnp_r16_rm16
Cmovnp_r32_rm32
Cmovnp_r64_rm64
Cmovns_r16_rm16
Cmovns_r32_rm32
Cmovns_r64_rm64
Cmovo_r16_rm16
Cmovo_r32_rm32
Cmovo_r64_rm64
Cmovp_r16_rm16
Cmovp_r32_rm32
Cmovp_r64_rm64
Cmovs_r16_rm16
Cmovs_r32_rm32
Cmovs_r64_rm64
);

fn test(code: Code) {
    for &immediate in IMMEDIATES {
        let instruction = build(code, Test::Registers, Register::None, immediate);

        case(instruction, None, immediate);

        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(&instruction);

        if !info.used_memory().is_empty() {
            let base = available(info.used_registers());
            let instruction = build(code, Test::Memory, base, immediate);
            let size = instruction.memory_size().size() as usize;

            let words = size.div_ceil(16);

            let mut backing = vec![(immediate as u128) | ((immediate as u128) << 64); words.max(1)];

            let memory = unsafe {
                slice::from_raw_parts_mut(backing.as_mut_ptr() as *mut u8, backing.len() * 16)
            };

            case(instruction, Some(&mut memory[..size]), immediate);
        }
    }
}

#[derive(Clone, Copy)]
enum Test {
    Registers,
    Memory,
}

fn build(code: Code, test: Test, memory_base: Register, immediate: u64) -> Instruction {
    let info = code.op_code();
    let kinds = [
        info.op0_kind(),
        info.op1_kind(),
        info.op2_kind(),
        info.op3_kind(),
        info.op4_kind(),
    ];

    let memory_operand = if matches!(test, Test::Memory) {
        kinds.iter().position(|kind| memory(*kind))
    } else {
        None
    };

    let mut instruction = Instruction::default();
    instruction.set_code(code);

    for index in 0..5 {
        let kind = kinds[index];

        if kind == OpCodeOperandKind::None {
            continue;
        }

        if Some(index) == memory_operand {
            instruction.set_op_kind(index as u32, OpKind::Memory);
            instruction.set_memory_base(memory_base);
            instruction.set_memory_index(Register::None);
            instruction.set_memory_index_scale(1);
            instruction.set_memory_displacement64(0);
            instruction.set_memory_displ_size(0);
            continue;
        }

        operand(&mut instruction, index as u32, kind, immediate);
    }

    instruction
}

fn operand(instruction: &mut Instruction, operand: u32, kind: OpCodeOperandKind, immediate: u64) {
    let op = match kind {
        OpCodeOperandKind::r8_or_mem
        | OpCodeOperandKind::r16_or_mem
        | OpCodeOperandKind::r32_or_mem
        | OpCodeOperandKind::r32_or_mem_mpx
        | OpCodeOperandKind::r64_or_mem
        | OpCodeOperandKind::r64_or_mem_mpx
        | OpCodeOperandKind::mm_or_mem
        | OpCodeOperandKind::xmm_or_mem
        | OpCodeOperandKind::ymm_or_mem
        | OpCodeOperandKind::zmm_or_mem
        | OpCodeOperandKind::bnd_or_mem_mpx
        | OpCodeOperandKind::k_or_mem
        | OpCodeOperandKind::r8_reg
        | OpCodeOperandKind::r8_opcode
        | OpCodeOperandKind::r16_reg
        | OpCodeOperandKind::r16_reg_mem
        | OpCodeOperandKind::r16_rm
        | OpCodeOperandKind::r16_opcode
        | OpCodeOperandKind::r32_reg
        | OpCodeOperandKind::r32_reg_mem
        | OpCodeOperandKind::r32_rm
        | OpCodeOperandKind::r32_opcode
        | OpCodeOperandKind::r32_vvvv
        | OpCodeOperandKind::r64_reg
        | OpCodeOperandKind::r64_reg_mem
        | OpCodeOperandKind::r64_rm
        | OpCodeOperandKind::r64_opcode
        | OpCodeOperandKind::r64_vvvv
        | OpCodeOperandKind::seg_reg
        | OpCodeOperandKind::k_reg
        | OpCodeOperandKind::kp1_reg
        | OpCodeOperandKind::k_rm
        | OpCodeOperandKind::k_vvvv
        | OpCodeOperandKind::mm_reg
        | OpCodeOperandKind::mm_rm
        | OpCodeOperandKind::xmm_reg
        | OpCodeOperandKind::xmm_rm
        | OpCodeOperandKind::xmm_vvvv
        | OpCodeOperandKind::xmmp3_vvvv
        | OpCodeOperandKind::xmm_is4
        | OpCodeOperandKind::xmm_is5
        | OpCodeOperandKind::ymm_reg
        | OpCodeOperandKind::ymm_rm
        | OpCodeOperandKind::ymm_vvvv
        | OpCodeOperandKind::ymm_is4
        | OpCodeOperandKind::ymm_is5
        | OpCodeOperandKind::zmm_reg
        | OpCodeOperandKind::zmm_rm
        | OpCodeOperandKind::zmm_vvvv
        | OpCodeOperandKind::zmmp3_vvvv
        | OpCodeOperandKind::cr_reg
        | OpCodeOperandKind::dr_reg
        | OpCodeOperandKind::tr_reg
        | OpCodeOperandKind::bnd_reg
        | OpCodeOperandKind::es
        | OpCodeOperandKind::cs
        | OpCodeOperandKind::ss
        | OpCodeOperandKind::ds
        | OpCodeOperandKind::fs
        | OpCodeOperandKind::gs
        | OpCodeOperandKind::al
        | OpCodeOperandKind::cl
        | OpCodeOperandKind::ax
        | OpCodeOperandKind::dx
        | OpCodeOperandKind::eax
        | OpCodeOperandKind::rax
        | OpCodeOperandKind::st0
        | OpCodeOperandKind::sti_opcode
        | OpCodeOperandKind::tmm_reg
        | OpCodeOperandKind::tmm_rm
        | OpCodeOperandKind::tmm_vvvv => OpKind::Register,
        OpCodeOperandKind::imm4_m2z | OpCodeOperandKind::imm8 | OpCodeOperandKind::imm8_const_1 => {
            OpKind::Immediate8
        }
        OpCodeOperandKind::imm8sex16 => OpKind::Immediate8to16,
        OpCodeOperandKind::imm8sex32 => OpKind::Immediate8to32,
        OpCodeOperandKind::imm8sex64 => OpKind::Immediate8to64,
        OpCodeOperandKind::imm16 => OpKind::Immediate16,
        OpCodeOperandKind::imm32 => OpKind::Immediate32,
        OpCodeOperandKind::imm32sex64 => OpKind::Immediate32to64,
        OpCodeOperandKind::imm64 => OpKind::Immediate64,
        _ => panic!("unsupported operand kind: {kind:?}"),
    };

    instruction.set_op_kind(operand, op);

    if op == OpKind::Register {
        instruction.set_op_register(operand, register_for(kind, operand as usize));
    } else {
        let value = match kind {
            OpCodeOperandKind::imm4_m2z => 0,
            OpCodeOperandKind::imm8_const_1 => 1,
            OpCodeOperandKind::imm8
            | OpCodeOperandKind::imm8sex16
            | OpCodeOperandKind::imm8sex32
            | OpCodeOperandKind::imm8sex64 => immediate as u8 as u64,
            OpCodeOperandKind::imm16 => immediate as u16 as u64,
            OpCodeOperandKind::imm32 | OpCodeOperandKind::imm32sex64 => immediate as u32 as u64,
            OpCodeOperandKind::imm64 => immediate,
            _ => unreachable!(),
        };

        instruction.set_immediate_u64(operand, value);
    }
}

fn register_for(kind: OpCodeOperandKind, operand: usize) -> Register {
    match kind {
        OpCodeOperandKind::al => Register::AL,
        OpCodeOperandKind::cl => Register::CL,
        OpCodeOperandKind::ax => Register::AX,
        OpCodeOperandKind::dx => Register::DX,
        OpCodeOperandKind::eax => Register::EAX,
        OpCodeOperandKind::rax => Register::RAX,
        OpCodeOperandKind::r8_reg | OpCodeOperandKind::r8_opcode | OpCodeOperandKind::r8_or_mem => {
            register(operand, 1)
        }
        OpCodeOperandKind::r16_reg
        | OpCodeOperandKind::r16_opcode
        | OpCodeOperandKind::r16_reg_mem
        | OpCodeOperandKind::r16_rm
        | OpCodeOperandKind::r16_or_mem => register(operand, 2),
        OpCodeOperandKind::r32_reg
        | OpCodeOperandKind::r32_opcode
        | OpCodeOperandKind::r32_vvvv
        | OpCodeOperandKind::r32_reg_mem
        | OpCodeOperandKind::r32_rm
        | OpCodeOperandKind::r32_or_mem
        | OpCodeOperandKind::r32_or_mem_mpx => register(operand, 4),
        OpCodeOperandKind::r64_reg
        | OpCodeOperandKind::r64_opcode
        | OpCodeOperandKind::r64_vvvv
        | OpCodeOperandKind::r64_reg_mem
        | OpCodeOperandKind::r64_rm
        | OpCodeOperandKind::r64_or_mem
        | OpCodeOperandKind::r64_or_mem_mpx => register(operand, 8),
        OpCodeOperandKind::xmm_reg
        | OpCodeOperandKind::xmm_rm
        | OpCodeOperandKind::xmm_vvvv
        | OpCodeOperandKind::xmmp3_vvvv
        | OpCodeOperandKind::xmm_is4
        | OpCodeOperandKind::xmm_is5
        | OpCodeOperandKind::xmm_or_mem => Register::XMM0 + ((operand % 16) as u32),
        OpCodeOperandKind::ymm_reg
        | OpCodeOperandKind::ymm_rm
        | OpCodeOperandKind::ymm_vvvv
        | OpCodeOperandKind::ymm_is4
        | OpCodeOperandKind::ymm_is5
        | OpCodeOperandKind::ymm_or_mem => Register::YMM0 + ((operand % 16) as u32),
        OpCodeOperandKind::zmm_reg
        | OpCodeOperandKind::zmm_rm
        | OpCodeOperandKind::zmm_vvvv
        | OpCodeOperandKind::zmmp3_vvvv
        | OpCodeOperandKind::zmm_or_mem => Register::ZMM0 + ((operand % 16) as u32),
        _ => panic!("unsupported operand kind: {kind:?}"),
    }
}

fn memory(kind: OpCodeOperandKind) -> bool {
    matches!(
        kind,
        OpCodeOperandKind::mem
            | OpCodeOperandKind::mem_mpx
            | OpCodeOperandKind::mem_mib
            | OpCodeOperandKind::mem_vsib32x
            | OpCodeOperandKind::mem_vsib64x
            | OpCodeOperandKind::mem_vsib32y
            | OpCodeOperandKind::mem_vsib64y
            | OpCodeOperandKind::mem_vsib32z
            | OpCodeOperandKind::mem_vsib64z
            | OpCodeOperandKind::r8_or_mem
            | OpCodeOperandKind::r16_or_mem
            | OpCodeOperandKind::r32_or_mem
            | OpCodeOperandKind::r32_or_mem_mpx
            | OpCodeOperandKind::r64_or_mem
            | OpCodeOperandKind::r64_or_mem_mpx
            | OpCodeOperandKind::mm_or_mem
            | OpCodeOperandKind::xmm_or_mem
            | OpCodeOperandKind::ymm_or_mem
            | OpCodeOperandKind::zmm_or_mem
            | OpCodeOperandKind::bnd_or_mem_mpx
            | OpCodeOperandKind::k_or_mem
            | OpCodeOperandKind::r16_reg_mem
            | OpCodeOperandKind::r32_reg_mem
            | OpCodeOperandKind::r64_reg_mem
    )
}

fn case(instruction: Instruction, memory: Option<&mut [u8]>, immediate: u64) {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(&instruction);

    let mut state = baseline();

    for used in info.used_registers() {
        let register = used.register();

        if register.is_gpr() {
            state = state.with(VMReg::from(register.full_register()), immediate);
        }
    }

    for index in 0..instruction.op_count() {
        let register = instruction.op_register(index);

        if register.is_vector_register() {
            let immediate = (immediate as u128) | ((immediate as u128) << 64);
            state = vector(state, VMVec::from(register), [immediate, immediate]);
        }
    }

    let has_rax = info
        .used_registers()
        .iter()
        .any(|used| used.register().full_register() == Register::RAX);

    let has_rdx = info
        .used_registers()
        .iter()
        .any(|used| used.register().full_register() == Register::RDX);

    let reads_rdx = info.used_registers().iter().any(|used| {
        used.register().full_register() == Register::RDX
            && matches!(
                used.access(),
                OpAccess::Read | OpAccess::ReadWrite | OpAccess::ReadCondWrite | OpAccess::CondRead
            )
    });

    if has_rax && has_rdx && reads_rdx {
        state = state.with(VMReg::from(Register::RDX), 0);
    }

    if instruction.rflags_read() != RflagsBits::NONE
        || instruction.rflags_written() != RflagsBits::NONE
    {
        state = state.with(
            VMReg::Flags,
            Flag::Carry.bit64()
                | Flag::Parity.bit64()
                | Flag::Auxiliary.bit64()
                | Flag::Zero.bit64()
                | Flag::Sign.bit64()
                | Flag::Overflow.bit64(),
        );
    }

    if let Some(memory) = memory {
        state = state.with(
            VMReg::from(instruction.memory_base()),
            memory.as_mut_ptr() as u64,
        );
        compare_memory(state, instruction, memory);
    } else {
        compare(state, instruction);
    }
}

fn compare(state: State, instruction: Instruction) {
    compare_memory(state, instruction, &mut []);
}

fn compare_memory(state: State, instruction: Instruction, memory: &mut [u8]) {
    let baseline = memory.to_vec();

    let mut executor = Executor::new();
    let mut native = executor.run_native(state.clone(), &[instruction]);

    memory.copy_from_slice(&baseline);

    let mut executor = Executor::new();
    let lifted = bytecode::lift(&[instruction])
        .unwrap_or_else(|| panic!("{instruction} is not implemented"));

    let transformed = bytecode::transform(&mut executor.rt.mapper, lifted, |_| 0);

    let mut bytes = bytecode::assemble(&mut executor.rt.mapper, &transformed);
    encrypt_block(&mut bytes);
    decrypt_payload(&mut bytes);
    let mut emulated = executor.run_virtual(state.clone(), &bytes);

    normalize(&mut native, &mut emulated, instruction);
}

fn normalize(native: &mut State, emulated: &mut State, instruction: Instruction) {
    native.registers.remove(&VMReg::Rsp);
    emulated.registers.remove(&VMReg::Rsp);

    for state in [&mut *native, &mut *emulated] {
        let flags = state.registers.get_mut(&VMReg::Flags).unwrap();
        let mask =
            instruction.rflags_written() | instruction.rflags_cleared() | instruction.rflags_set();

        *flags &= ((mask & RflagsBits::CF != 0) as u64 * Flag::Carry.bit64())
            | ((mask & RflagsBits::PF != 0) as u64 * Flag::Parity.bit64())
            | ((mask & RflagsBits::AF != 0) as u64 * Flag::Auxiliary.bit64())
            | ((mask & RflagsBits::ZF != 0) as u64 * Flag::Zero.bit64())
            | ((mask & RflagsBits::SF != 0) as u64 * Flag::Sign.bit64())
            | ((mask & RflagsBits::OF != 0) as u64 * Flag::Overflow.bit64());
    }

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
            Difference::Exception(native, emulated) => {
                lines.push(format!("Exception: native={native:?} virtual={emulated:?}"));
            }
        }
    }

    lines.join("\n")
}

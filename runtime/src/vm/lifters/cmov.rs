use iced_x86::{Code, Instruction};
use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMFlag, VMLogic};
use crate::vm::encoders::skip::Skip;
use crate::vm::encoders::Encode;
use crate::vm::lifters::branch::{cmp, eq, neq};
use crate::vm::lifters::transfer;

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let code = instruction.code();

    let (logic, conditions) = match code {
        Code::Cmove_r16_rm16 | Code::Cmove_r32_rm32 | Code::Cmove_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Zero, 0)])
        }
        Code::Cmovne_r16_rm16 | Code::Cmovne_r32_rm32 | Code::Cmovne_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Zero, 1)])
        }
        Code::Cmova_r16_rm16 | Code::Cmova_r32_rm32 | Code::Cmova_r64_rm64 => (
            VMLogic::SOR,
            vec![cmp(VMFlag::Carry, 1), cmp(VMFlag::Zero, 1)],
        ),
        Code::Cmovae_r16_rm16 | Code::Cmovae_r32_rm32 | Code::Cmovae_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Carry, 1)])
        }
        Code::Cmovb_r16_rm16 | Code::Cmovb_r32_rm32 | Code::Cmovb_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Carry, 0)])
        }
        Code::Cmovbe_r16_rm16 | Code::Cmovbe_r32_rm32 | Code::Cmovbe_r64_rm64 => (
            VMLogic::SAND,
            vec![cmp(VMFlag::Carry, 0), cmp(VMFlag::Zero, 0)],
        ),
        Code::Cmovg_r16_rm16 | Code::Cmovg_r32_rm32 | Code::Cmovg_r64_rm64 => (
            VMLogic::SOR,
            vec![cmp(VMFlag::Zero, 1), neq(VMFlag::Sign, VMFlag::Overflow)],
        ),
        Code::Cmovge_r16_rm16 | Code::Cmovge_r32_rm32 | Code::Cmovge_r64_rm64 => {
            (VMLogic::SAND, vec![neq(VMFlag::Sign, VMFlag::Overflow)])
        }
        Code::Cmovl_r16_rm16 | Code::Cmovl_r32_rm32 | Code::Cmovl_r64_rm64 => {
            (VMLogic::SAND, vec![eq(VMFlag::Sign, VMFlag::Overflow)])
        }
        Code::Cmovle_r16_rm16 | Code::Cmovle_r32_rm32 | Code::Cmovle_r64_rm64 => (
            VMLogic::SAND,
            vec![cmp(VMFlag::Zero, 0), eq(VMFlag::Sign, VMFlag::Overflow)],
        ),
        Code::Cmovno_r16_rm16 | Code::Cmovno_r32_rm32 | Code::Cmovno_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Overflow, 1)])
        }
        Code::Cmovnp_r16_rm16 | Code::Cmovnp_r32_rm32 | Code::Cmovnp_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Parity, 1)])
        }
        Code::Cmovns_r16_rm16 | Code::Cmovns_r32_rm32 | Code::Cmovns_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Sign, 1)])
        }
        Code::Cmovo_r16_rm16 | Code::Cmovo_r32_rm32 | Code::Cmovo_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Overflow, 0)])
        }
        Code::Cmovp_r16_rm16 | Code::Cmovp_r32_rm32 | Code::Cmovp_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Parity, 0)])
        }
        Code::Cmovs_r16_rm16 | Code::Cmovs_r32_rm32 | Code::Cmovs_r64_rm64 => {
            (VMLogic::SAND, vec![cmp(VMFlag::Sign, 0)])
        }
        _ => panic!("unsupported code: {:?}", instruction.code()),
    };

    let body = transfer::encode(instruction)?;

    Some(vec![Rc::new(Skip::new(mapper, logic, conditions, body))])
}

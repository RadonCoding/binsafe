use iced_x86::{Code, Instruction};

use crate::vm::bytecode::{VMBits, VMMem, VMReg};
use crate::vm::encoders::{compose_2, load_addr::LoadAddr, store_reg::StoreReg, Encode};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let width = match instruction.code() {
        Code::Lea_r64_m => VMBits::Lower64,
        Code::Lea_r32_m => VMBits::Lower32,
        Code::Lea_r16_m => VMBits::Lower16,
        _ => return None,
    };

    Some(compose_2(
        LoadAddr {
            source: VMMem::from(instruction),
        },
        StoreReg {
            width,
            destination: VMReg::from(instruction.op0_register()),
        },
    ))
}

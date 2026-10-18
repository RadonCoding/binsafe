use iced_x86::{Instruction, Mnemonic};

use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::{
    load_register::LoadRegister, store_register::StoreRegister, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let (source, destination) = match instruction.mnemonic() {
        Mnemonic::Cbw => (VMWidth::Lower8, VMWidth::Lower16),
        Mnemonic::Cwde => (VMWidth::Lower16, VMWidth::Lower32),
        Mnemonic::Cdqe => (VMWidth::Lower32, VMWidth::Lower64),
        _ => return None,
    };

    Some(vec![
        Box::new(LoadRegister {
            width: source.signed(),
            source: VMReg::Rax,
        }),
        Box::new(StoreRegister {
            width: destination,
            destination: VMReg::Rax,
        }),
    ])
}

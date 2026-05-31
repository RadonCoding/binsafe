use std::rc::Rc;
use iced_x86::{Code, Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_register::LoadRegister,
    store_register::StoreRegister, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let source_width = match instruction.code() {
        Code::Movzx_r16_rm8 | Code::Movzx_r32_rm8 | Code::Movzx_r64_rm8 => VMWidth::Lower8,
        Code::Movzx_r16_rm16 | Code::Movzx_r32_rm16 | Code::Movzx_r64_rm16 => VMWidth::Lower16,
        _ => return None,
    };

    let destination_register = instruction.op0_register();
    let destination = VMReg::from(destination_register);
    let destination_width = match VMWidth::from(destination_register) {
        VMWidth::Lower16 => VMWidth::Lower16,
        _ => VMWidth::Lower64,
    };

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_register = instruction.op1_register();
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::from(source_register),
                source: VMReg::from(source_register),
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(LoadMemory {
                width: source_width,
            }));
        }
        _ => return None,
    }

    operations.push(Rc::new(StoreRegister {
        width: destination_width,
        destination,
    }));

    Some(operations)
}

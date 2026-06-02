use std::rc::Rc;
use iced_x86::{Code, Instruction, OpKind};

use crate::vm::bytecode::{VMMem, VMReg, VMWidth};
use crate::vm::encoders::{
    load_address::LoadAddress, load_memory::LoadMemory, load_register::LoadRegister,
    store_register::StoreRegister, Encode,
};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let source_width = match instruction.code() {
        Code::Movsx_r16_rm8 | Code::Movsx_r32_rm8 | Code::Movsx_r64_rm8 => VMWidth::SLower8,
        Code::Movsx_r16_rm16 | Code::Movsx_r32_rm16 | Code::Movsx_r64_rm16 => VMWidth::SLower16,
        Code::Movsxd_r16_rm16 | Code::Movsxd_r32_rm32 | Code::Movsxd_r64_rm32 => VMWidth::SLower32,
        _ => return None,
    };

    let destination_width = match VMWidth::from(instruction.op0_register()) {
        VMWidth::Lower16 => VMWidth::Lower16,
        _ => VMWidth::Lower64,
    };
    let destination_register = VMReg::from(instruction.op0_register());

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    match instruction.op1_kind() {
        OpKind::Register => {
            let source_register = VMReg::from(instruction.op1_register());
            operations.push(Rc::new(LoadRegister {
                width: source_width,
                source: source_register,
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
        destination: destination_register,
    }));

    Some(operations)
}

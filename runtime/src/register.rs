use iced_x86::Register;

pub fn sized(register: Register, size: usize) -> Option<Register> {
    let number = register.number() as usize;

    match size {
        1 => match number {
            0 => Some(Register::AL),
            1 => Some(Register::CL),
            2 => Some(Register::DL),
            3 => Some(Register::BL),
            4 => Some(Register::SPL),
            5 => Some(Register::BPL),
            6 => Some(Register::SIL),
            7 => Some(Register::DIL),
            8 => Some(Register::R8L),
            9 => Some(Register::R9L),
            10 => Some(Register::R10L),
            11 => Some(Register::R11L),
            12 => Some(Register::R12L),
            13 => Some(Register::R13L),
            14 => Some(Register::R14L),
            15 => Some(Register::R15L),
            _ => None,
        },
        2 => {
            let base = register.full_register().number() as u32;
            Some(Register::AX + base)
        }
        4 => {
            let base = register.full_register().number() as u32;
            Some(Register::EAX + base)
        }
        8 => {
            let base = register.full_register().number() as u32;
            Some(Register::RAX + base)
        }
        _ => None,
    }
}

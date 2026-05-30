use iced_x86::{Code, Instruction, OpKind};

use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMMem, VMReg, VMSeg, VMTest, VMWidth};
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_memory::LoadMemory;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::ret::Ret;
use crate::vm::encoders::{jcc::Jcc, Encode};

pub fn encode(instruction: &Instruction) -> Option<Vec<Box<dyn Encode>>> {
    let code = instruction.code();

    match code {
        Code::Jmp_rm64 => match instruction.op0_kind() {
            OpKind::Register => Some(vec![
                Box::new(LoadRegister {
                    width: VMWidth::Lower64,
                    source: VMReg::from(instruction.op0_register()),
                }),
                Box::new(Jcc::jump()),
            ]),
            OpKind::Memory => Some(vec![
                Box::new(LoadAddress {
                    source: VMMem::from(instruction),
                }),
                Box::new(LoadMemory {
                    width: VMWidth::Lower64,
                }),
                Box::new(Jcc::jump()),
            ]),
            _ => None,
        },

        Code::Jmp_rel32_64 | Code::Jmp_rel8_64 => {
            let displacement = instruction.memory_displacement64().try_into().unwrap();

            Some(vec![
                Box::new(LoadAddress {
                    source: VMMem {
                        base: VMReg::VImage,
                        index: VMReg::None,
                        scale: 1,
                        displacement,
                        segment: VMSeg::None,
                    },
                }),
                Box::new(Jcc::jump()),
            ])
        }

        Code::Call_rel32_64 => {
            let displacement = instruction.memory_displacement64().try_into().unwrap();

            Some(vec![
                Box::new(LoadAddress {
                    source: VMMem {
                        base: VMReg::VImage,
                        index: VMReg::None,
                        scale: 1,
                        displacement,
                        segment: VMSeg::None,
                    },
                }),
                Box::new(Jcc::call()),
            ])
        }

        Code::Retnq => Some(vec![Box::new(Ret)]),

        Code::Call_rm64 => match instruction.op0_kind() {
            OpKind::Register => Some(vec![
                Box::new(LoadRegister {
                    width: VMWidth::Lower64,
                    source: VMReg::from(instruction.op0_register()),
                }),
                Box::new(Jcc::call()),
            ]),
            OpKind::Memory => Some(vec![
                Box::new(LoadAddress {
                    source: VMMem::from(instruction),
                }),
                Box::new(LoadMemory {
                    width: VMWidth::Lower64,
                }),
                Box::new(Jcc::call()),
            ]),
            _ => None,
        },

        _ => {
            let displacement = instruction.memory_displacement64().try_into().unwrap();

            let (logic, conditions) = match code {
                // JA = CF=0 AND ZF=0
                Code::Ja_rel32_64 | Code::Ja_rel8_64 => (
                    VMLogic::JAND,
                    vec![cmp(VMFlag::Carry, 0), cmp(VMFlag::Zero, 0)],
                ),
                // JAE = CF=0
                Code::Jae_rel32_64 | Code::Jae_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Carry, 0)])
                }
                // JB = CF=1
                Code::Jb_rel32_64 | Code::Jb_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Carry, 1)])
                }
                // JBE = CF=1 OR ZF=1
                Code::Jbe_rel32_64 | Code::Jbe_rel8_64 => (
                    VMLogic::JOR,
                    vec![cmp(VMFlag::Carry, 1), cmp(VMFlag::Zero, 1)],
                ),
                // JE = ZF=1
                Code::Je_rel32_64 | Code::Je_rel8_64 => (VMLogic::JAND, vec![cmp(VMFlag::Zero, 1)]),
                // JG = ZF=0 AND SF=OF
                Code::Jg_rel32_64 | Code::Jg_rel8_64 => (
                    VMLogic::JAND,
                    vec![cmp(VMFlag::Zero, 0), eq(VMFlag::Sign, VMFlag::Overflow)],
                ),
                // JGE = SF=OF
                Code::Jge_rel32_64 | Code::Jge_rel8_64 => {
                    (VMLogic::JAND, vec![eq(VMFlag::Sign, VMFlag::Overflow)])
                }
                // JL = SF<>OF
                Code::Jl_rel32_64 | Code::Jl_rel8_64 => {
                    (VMLogic::JAND, vec![neq(VMFlag::Sign, VMFlag::Overflow)])
                }
                // JLE = ZF=1 OR SF<>OF
                Code::Jle_rel32_64 | Code::Jle_rel8_64 => (
                    VMLogic::JOR,
                    vec![cmp(VMFlag::Zero, 1), neq(VMFlag::Sign, VMFlag::Overflow)],
                ),
                // JNE = ZF=0
                Code::Jne_rel32_64 | Code::Jne_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Zero, 0)])
                }
                // JNO = OF=0
                Code::Jno_rel32_64 | Code::Jno_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Overflow, 0)])
                }
                // JNP = PF=0
                Code::Jnp_rel32_64 | Code::Jnp_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Parity, 0)])
                }
                // JNS = SF=0
                Code::Jns_rel32_64 | Code::Jns_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Sign, 0)])
                }
                // JO = OF=1
                Code::Jo_rel32_64 | Code::Jo_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Overflow, 1)])
                }
                // JP = PF=1
                Code::Jp_rel32_64 | Code::Jp_rel8_64 => {
                    (VMLogic::JAND, vec![cmp(VMFlag::Parity, 1)])
                }
                // JS = SF=1
                Code::Js_rel32_64 | Code::Js_rel8_64 => (VMLogic::JAND, vec![cmp(VMFlag::Sign, 1)]),
                _ => return None,
            };

            // TODO: Mutation of conditions to equilavent logic

            Some(vec![
                Box::new(LoadAddress {
                    source: VMMem {
                        base: VMReg::VImage,
                        index: VMReg::None,
                        scale: 1,
                        displacement,
                        segment: VMSeg::None,
                    },
                }),
                Box::new(Jcc { logic, conditions }),
            ])
        }
    }
}

pub fn cmp(lhs: VMFlag, rhs: u8) -> VMCondition {
    VMCondition {
        test: VMTest::CMP,
        lhs: lhs as u8,
        rhs,
    }
}

pub fn eq(lhs: VMFlag, rhs: VMFlag) -> VMCondition {
    VMCondition {
        test: VMTest::EQ,
        lhs: lhs as u8,
        rhs: rhs as u8,
    }
}

pub fn neq(lhs: VMFlag, rhs: VMFlag) -> VMCondition {
    VMCondition {
        test: VMTest::NEQ,
        lhs: lhs as u8,
        rhs: rhs as u8,
    }
}

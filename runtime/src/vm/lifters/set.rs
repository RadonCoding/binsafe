use iced_x86::{Code, Instruction, OpKind};
use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMFlag, VMLogic, VMMem, VMReg, VMWidth};
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::skip::Skip;
use crate::vm::encoders::store_memory::StoreMemory;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::Encode;
use crate::vm::lifters::jcc::{cmp, eq, neq};

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    let code = instruction.code();

    let (logic, conditions) = match code {
        // SETE = ZF=1
        Code::Sete_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Zero, 0)]),
        // SETNE = ZF=0
        Code::Setne_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Zero, 1)]),
        // SETA = CF=0 AND ZF=0
        Code::Seta_rm8 => (
            VMLogic::SOR,
            vec![cmp(VMFlag::Carry, 1), cmp(VMFlag::Zero, 1)],
        ),
        // SETAE = CF=0
        Code::Setae_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Carry, 1)]),
        // SETB = CF=1
        Code::Setb_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Carry, 0)]),
        // SETBE = CF=1 OR ZF=1
        Code::Setbe_rm8 => (
            VMLogic::SAND,
            vec![cmp(VMFlag::Carry, 0), cmp(VMFlag::Zero, 0)],
        ),
        // SETG = ZF=0 AND SF=OF
        Code::Setg_rm8 => (
            VMLogic::SOR,
            vec![cmp(VMFlag::Zero, 1), neq(VMFlag::Sign, VMFlag::Overflow)],
        ),
        // SETGE = SF=OF
        Code::Setge_rm8 => (VMLogic::SAND, vec![neq(VMFlag::Sign, VMFlag::Overflow)]),
        // SETL = SF<>OF
        Code::Setl_rm8 => (VMLogic::SAND, vec![eq(VMFlag::Sign, VMFlag::Overflow)]),
        // SETLE = ZF=1 OR SF<>OF
        Code::Setle_rm8 => (
            VMLogic::SAND,
            vec![cmp(VMFlag::Zero, 0), eq(VMFlag::Sign, VMFlag::Overflow)],
        ),
        // SETNO = OF=0
        Code::Setno_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Overflow, 1)]),
        // SETNP = PF=0
        Code::Setnp_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Parity, 1)]),
        // SETNS = SF=0
        Code::Setns_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Sign, 1)]),
        // SETO = OF=1
        Code::Seto_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Overflow, 0)]),
        // SETP = PF=1
        Code::Setp_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Parity, 0)]),
        // SETS = SF=1
        Code::Sets_rm8 => (VMLogic::SAND, vec![cmp(VMFlag::Sign, 0)]),
        _ => return None,
    };

    let zero = || -> Rc<dyn Encode> {
        Rc::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![0],
        })
    };
    let one = || -> Rc<dyn Encode> {
        Rc::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![1],
        })
    };

    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let body: Vec<Rc<dyn Encode>>;

    match instruction.op0_kind() {
        OpKind::Register => {
            let destination = VMReg::from(instruction.op0_register());
            operations.push(zero());
            operations.push(Rc::new(StoreRegister {
                width: VMWidth::Lower8,
                destination,
            }));
            body = vec![
                one(),
                Rc::new(StoreRegister {
                    width: VMWidth::Lower8,
                    destination,
                }),
            ];
        }
        OpKind::Memory => {
            operations.push(zero());
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory {
                width: VMWidth::Lower8,
            }));
            body = vec![
                one(),
                Rc::new(LoadAddress {
                    source: VMMem::from(instruction),
                }),
                Rc::new(StoreMemory {
                    width: VMWidth::Lower8,
                }),
            ];
        }
        _ => return None,
    }

    operations.push(Rc::new(Skip::new(mapper, logic, conditions, body)));

    Some(operations)
}

use std::collections::HashMap;

use runtime::vm::bytecode::{
    VMBits, VMCmd, VMCond, VMFlag, VMLogic, VMMem, VMOp, VMReg, VMSeg, VMTest,
};

use crate::engine::Block;

pub struct AntiDebug;

impl AntiDebug {
    pub fn transform(xrefs: &HashMap<u64, usize>, block: &Block) -> Option<Vec<u8>> {
        const THRESHOLD: usize = 10;

        if xrefs.get(&block.ip).map_or(0, |&c| c) < THRESHOLD {
            return None;
        }

        let vblock = Self::gen_peb_check();

        Some(vblock.into_iter().flat_map(|cmd| cmd.encode()).collect())
    }

    fn gen_peb_check() -> Vec<VMCmd<'static>> {
        const TRUE: [u8; 1] = [0x1];

        vec![
            VMCmd::RegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::V0,
                sbits: VMBits::Lower64,
                src: VMReg::Rax,
            },
            VMCmd::RegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::V1,
                sbits: VMBits::Lower64,
                src: VMReg::Flags,
            },
            VMCmd::RegMem {
                vop: VMOp::SetRegMem,
                dbits: VMBits::Lower64,
                load: true,
                dst: VMReg::Rax,
                src: VMMem {
                    base: VMReg::None,
                    index: VMReg::None,
                    scale: 1,
                    displacement: 0x60,
                    seg: VMSeg::Gs,
                },
            },
            VMCmd::RegMem {
                vop: VMOp::SetRegMem,
                dbits: VMBits::Lower8,
                load: true,
                dst: VMReg::Rax,
                src: VMMem {
                    base: VMReg::Rax,
                    index: VMReg::None,
                    scale: 1,
                    displacement: 0x02,
                    seg: VMSeg::None,
                },
            },
            VMCmd::AddSubRegImm {
                vop: VMOp::AddSubRegImm,
                dbits: VMBits::Lower8,
                dst: VMReg::Rax,
                sub: true,
                store: false,
                src: &TRUE,
            },
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Zero as u8,
                    rhs: 1,
                }],
                dst: i32::MIN,
            },
            VMCmd::RegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::Flags,
                sbits: VMBits::Lower64,
                src: VMReg::V1,
            },
            VMCmd::RegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::Rax,
                sbits: VMBits::Lower64,
                src: VMReg::V0,
            },
        ]
    }
}

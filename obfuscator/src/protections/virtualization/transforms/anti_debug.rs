use std::collections::HashMap;

use runtime::{
    mapper::Mapper,
    vm::bytecode::{VMBits, VMCmd, VMCond, VMFlag, VMLogic, VMMem, VMOp, VMReg, VMSeg, VMTest},
};

use crate::engine::Block;

pub struct AntiDebug;

impl AntiDebug {
    pub fn transform(
        mapper: &mut Mapper,
        xrefs: &HashMap<u64, usize>,
        block: &Block,
    ) -> Option<Vec<u8>> {
        const THRESHOLD: usize = 10;

        if xrefs.get(&block.rva).map_or(0, |&c| c) < THRESHOLD {
            return None;
        }

        let vblock = Self::gen_peb_check();

        Some(
            vblock
                .into_iter()
                .flat_map(|cmd| cmd.encode(mapper))
                .collect(),
        )
    }

    fn gen_peb_check() -> Vec<VMCmd<'static>> {
        vec![
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
                dst: VMReg::V0,
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
                dst: VMReg::V0,
                src: VMMem {
                    base: VMReg::V0,
                    index: VMReg::None,
                    scale: 1,
                    displacement: 0x02,
                    seg: VMSeg::None,
                },
            },
            VMCmd::AddSubRegReg {
                vop: VMOp::AddSubRegImm,
                dbits: VMBits::Lower8,
                dst: VMReg::Rsp,
                sbits: VMBits::Lower8,
                src: VMReg::V0,
                sub: true,
                store: true,
            },
            VMCmd::RegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::Flags,
                sbits: VMBits::Lower64,
                src: VMReg::V1,
            },
        ]
    }
}

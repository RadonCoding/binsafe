use runtime::{
    mapper::Mapper,
    vm::bytecode::{VMBits, VMCmd, VMMem, VMOp, VMReg, VMSeg},
};

use crate::engine::Block;

pub struct AntiDebug;

impl AntiDebug {
    pub fn transform(mapper: &mut Mapper, block: &Block) -> Option<Vec<u8>> {
        let mut is_relative = false;

        for instruction in &block.instructions {
            if instruction.is_ip_rel_memory_operand() {
                is_relative = true;
                break;
            }
        }

        // Only blocks that have IP relative instructions are affected by the VB displacement.
        if !is_relative {
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
            VMCmd::SetRegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::V1,
                sbits: VMBits::Lower64,
                src: VMReg::Flags,
            },
            VMCmd::SetRegMem {
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
            VMCmd::AddSubRegMem {
                vop: VMOp::AddSubRegMem,
                sub: true,
                store: true,
                dbits: VMBits::Lower8,
                dst: VMReg::VB,
                src: VMMem {
                    base: VMReg::V0,
                    index: VMReg::None,
                    scale: 1,
                    displacement: 0x02,
                    seg: VMSeg::None,
                },
            },
            VMCmd::SetRegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::Flags,
                sbits: VMBits::Lower64,
                src: VMReg::V1,
            },
        ]
    }
}

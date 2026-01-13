use rand::Rng;
use runtime::{
    mapper::Mapper,
    vm::{
        bytecode::{VMBits, VMCmd, VMMem, VMOp, VMReg, VMSeg},
        veh::TRAP_MAGIC,
    },
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

        // Only blocks that have IP-relative instructions are affected by the VB displacement.
        if !is_relative {
            return None;
        }

        let mut rng = rand::thread_rng();

        let transform = if rng.gen() {
            Self::peb_check(mapper)
        } else {
            Self::fake_exception(mapper)
        };

        Some(transform)
    }

    fn fake_exception(mapper: &mut Mapper) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let skip: u8 = rng.gen_range(4..=96);

        let mut junk = vec![0u8; skip as usize];
        rng.fill(&mut junk[..]);

        let entropy: u16 = rng.gen();

        let displacement: i32 =
            ((TRAP_MAGIC as i32) << 24) | ((skip as i32) << 16) | (entropy as i32);

        let trap = VMCmd::SetRegMem {
            vop: VMOp::SetRegMem,
            dbits: VMBits::Lower64,
            load: true,
            dst: VMReg::V0,
            src: VMMem {
                base: VMReg::None,
                index: VMReg::None,
                scale: 1,
                displacement,
                seg: VMSeg::None,
            },
        };

        let mut encoded = trap.encode(mapper);
        encoded.extend_from_slice(&junk);

        encoded
    }

    fn peb_check(mapper: &mut Mapper) -> Vec<u8> {
        let vinstructions: Vec<VMCmd<'static>> = vec![
            VMCmd::SetRegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::V1,
                sbits: VMBits::Lower64,
                src: VMReg::Flags,
            },
            // PEB *TEB->ProcessEnvironmentBlock
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
            // BOOLEAN PEB->BeingDebugged
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
        ];

        vinstructions
            .into_iter()
            .flat_map(|cmd| cmd.encode(mapper))
            .collect()
    }
}

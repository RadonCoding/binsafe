use std::collections::HashMap;

use rand::{seq::SliceRandom, Rng};
use runtime::{
    mapper::Mapper,
    vm::{
        bytecode::{VMBits, VMCmd, VMMem, VMOp, VMReg, VMSeg},
        veh::TRAP_MAGIC,
    },
};

use crate::engine::Block;

pub struct AntiDebug {
    traps: HashMap<u32, TrapType>,
}

#[derive(Clone, Copy)]
enum TrapType {
    FakeException,
    PebCheck,
}

impl AntiDebug {
    pub fn new(blocks: &[Block]) -> Self {
        let mut traps = HashMap::new();

        let mut targets = blocks.iter().map(|b| b.rva).collect::<Vec<u32>>();

        let mut rng = rand::thread_rng();
        targets.shuffle(&mut rng);

        let exception_quota = (blocks.len() * 5 / 100).max(1);
        let peb_quota = (blocks.len() * 25 / 100).max(1);

        for &rva in targets.iter().take(exception_quota) {
            traps.insert(rva, TrapType::FakeException);
        }

        for &rva in targets.iter().skip(exception_quota).take(peb_quota) {
            traps.insert(rva, TrapType::PebCheck);
        }

        Self { traps }
    }

    pub fn transform(&self, mapper: &mut Mapper, block: &Block) -> Option<Vec<u8>> {
        match self.traps.get(&block.rva) {
            Some(TrapType::FakeException) => Some(Self::fake_exception(mapper)),
            Some(TrapType::PebCheck) => Some(Self::peb_check(mapper)),
            None => None,
        }
    }

    fn fake_exception(mapper: &mut Mapper) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let skip: u8 = rng.gen_range(4..=96);

        let mut junk = vec![0u8; skip as usize];
        rng.fill(&mut junk[..]);

        // Set the first type of the junk to a valid operation
        junk[0] = rng.gen_range(0..mapper.count::<VMOp>()) as u8;

        let entropy: u16 = rng.gen();

        let displacement: i32 =
            ((TRAP_MAGIC as i32) << 24) | ((skip as i32) << 16) | (entropy as i32);

        let trap = VMCmd::SetRegMem {
            vop: VMOp::SetRegMem,
            dbits: VMBits::Lower64,
            load: true,
            dst: VMReg::Vs0,
            src: VMMem {
                base: VMReg::None,
                index: VMReg::None,
                scale: 1,
                displ: displacement,
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
                dst: VMReg::Vs1,
                sbits: VMBits::Lower64,
                src: VMReg::Flags,
            },
            // PEB *TEB->ProcessEnvironmentBlock
            VMCmd::SetRegMem {
                vop: VMOp::SetRegMem,
                dbits: VMBits::Lower64,
                load: true,
                dst: VMReg::Vs0,
                src: VMMem {
                    base: VMReg::None,
                    index: VMReg::None,
                    scale: 1,
                    displ: 0x60,
                    seg: VMSeg::Gs,
                },
            },
            // BOOLEAN PEB->BeingDebugged
            VMCmd::AddSubRegMem {
                vop: VMOp::AddSubRegMem,
                sub: true,
                store: true,
                dbits: VMBits::Lower8,
                dst: VMReg::Vib,
                src: VMMem {
                    base: VMReg::Vs0,
                    index: VMReg::None,
                    scale: 1,
                    displ: 0x02,
                    seg: VMSeg::None,
                },
            },
            VMCmd::SetRegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::Flags,
                sbits: VMBits::Lower64,
                src: VMReg::Vs1,
            },
        ];

        vinstructions
            .into_iter()
            .flat_map(|cmd| cmd.encode(mapper))
            .collect()
    }
}

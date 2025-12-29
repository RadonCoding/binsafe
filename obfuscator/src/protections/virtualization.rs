use std::collections::HashMap;

use iced_x86::code_asm::CodeAssembler;
use iced_x86::Mnemonic;
use logger::info;
use runtime::vm::bytecode;
use runtime::{
    runtime::{DataDef, FnDef},
    vm::bytecode::VMOp,
};
use shared::constants::VM_DISPATCH_SIZE;

use crate::engine::Engine;
use crate::protections::Protection;

#[derive(Default)]
pub struct Virtualization {
    vblocks: HashMap<u64, i32>,
    failures: HashMap<Mnemonic, u32>,
}

impl Protection for Virtualization {
    fn initialize(&mut self, engine: &mut Engine) {
        let mut vcode = Vec::new();

        'outer: for block in &mut engine.blocks {
            if block.size < VM_DISPATCH_SIZE {
                continue;
            }

            let mut vblock = Vec::new();

            let next_ip = block.instructions[block.instructions.len() - 1].next_ip() as u32;

            let address = next_ip as u64;

            for instruction in &block.instructions {
                let bytecode = match bytecode::convert(address, instruction) {
                    Some(virtualized) => virtualized,
                    None => {
                        let mnemonic = instruction.mnemonic();
                        *self.failures.entry(mnemonic).or_insert(0) += 1;
                        continue 'outer;
                    }
                };
                vblock.extend(bytecode);
            }

            self.vblocks.insert(block.ip, vcode.len() as i32);

            vblock.splice(0..0, next_ip.to_le_bytes());
            vblock.push(VMOp::Invalid as u8);

            vcode.extend(vblock);
        }

        engine.rt.define_data(DataDef::VmCode, &vcode);
    }

    fn apply(&self, engine: &mut Engine) {
        let ventry = engine.rt.lookup(engine.rt.func_labels[&FnDef::VmEntry]);

        for i in 0..engine.blocks.len() {
            let block = &engine.blocks[i];

            if !self.vblocks.contains_key(&block.ip) {
                continue;
            }

            let voffset = self.vblocks[&block.ip];

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();
            asm.push(voffset).unwrap();
            asm.jmp(ventry).unwrap();

            let dispatch = asm.assemble(block.ip).unwrap();

            assert!(dispatch.len() <= VM_DISPATCH_SIZE);

            info!("PRE-VIRTUALIZATION:\n{}", engine.blocks[i]);
            engine.replace(i, &dispatch);
            info!("POST-VIRTUALIZATION:\n{}", engine.blocks[i]);
        }

        let total = engine.blocks.len();
        let virtualized = self.vblocks.len();
        let percentage = (virtualized as f64 / total.max(1) as f64) * 100.0;

        let mut output = format!(
            "VIRTUALIZED: {}/{} blocks ({:.2}%)",
            virtualized, total, percentage
        );

        if !self.failures.is_empty() {
            let mut sorted = self.failures.iter().collect::<Vec<_>>();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            let top = sorted
                .iter()
                .take(10)
                .map(|(m, _)| format!("{:?}", m).to_lowercase())
                .collect::<Vec<_>>()
                .join(", ");
            output.push(' ');
            output.push_str(&format!("(most failures: {})", top));
        }

        info!("{}", output);
    }
}

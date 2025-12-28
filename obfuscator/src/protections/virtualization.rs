use std::collections::HashMap;

use iced_x86::code_asm::CodeAssembler;
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
                    None => continue 'outer,
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

            info(block);

            engine.replace(i, &dispatch);
        }

        info!("Virtualized {} blocks", self.vblocks.len());
    }
}

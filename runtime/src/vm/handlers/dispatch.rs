use iced_x86::code_asm::{r12, r8, CodeLabel};

use crate::{
    runtime::Runtime,
    vm::{functions::dispatch::HANDLERS, utils::scratch},
};

pub fn build(rt: &mut Runtime) {
    // load r8
    scratch::load(rt, r12, r8);

    let cases = HANDLERS
        .iter()
        .map(|&(op, def)| (rt.mapper.index(op), rt.function_labels[&def]))
        .collect::<Vec<(u8, CodeLabel)>>();

    rt.calls(r8, cases);

    // ret
    rt.asm.ret().unwrap();
}

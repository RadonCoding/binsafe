use iced_x86::code_asm::{r8, r8d, rcx, CodeLabel};

use crate::{runtime::Runtime, vm::utils};

pub fn build(rt: &mut Runtime) {
    let cases = rt
        .compound_labels
        .iter()
        .enumerate()
        .map(|(index, &label)| (index as u8, label))
        .collect::<Vec<(u8, CodeLabel)>>();

    // r8d -> index
    utils::bytecode::read_byte_zx(rt, rcx, r8d);

    rt.calls(r8, cases);

    // ret
    rt.asm.ret().unwrap();
}

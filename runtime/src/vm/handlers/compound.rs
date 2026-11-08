use iced_x86::code_asm::{r8, rcx, CodeLabel};

use crate::{runtime::Runtime, vm::utils};

pub fn build(rt: &mut Runtime) {
    let cases = rt
        .compound_labels
        .iter()
        .enumerate()
        .map(|(index, &label)| (index, label))
        .collect::<Vec<(usize, CodeLabel)>>();

    // r8 -> index
    utils::bytecode::read_qword(rt, rcx, r8);

    rt.calls(r8, cases);

    // ret
    rt.asm.ret().unwrap();
}

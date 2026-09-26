use iced_x86::code_asm::{r12, r8, CodeLabel};

use crate::{
    runtime::Runtime,
    vm::{functions::dispatch::HANDLERS, utils::scratch},
};

pub fn build(rt: &mut Runtime) {
    // load r8
    scratch::load(rt, r12, r8);

    #[cfg(feature = "profile")]
    {
        use crate::debug::print_thread_message;
        use crate::mapper::Mappable;
        use crate::vm::bytecode::VMOp;

        let mut epilogue = rt.asm.create_label();

        let mut cases = Vec::new();

        for op in VMOp::VARIANTS {
            cases.push((rt.mapper.index(*op), rt.asm.create_label()));
        }

        rt.jumps(r8, cases.clone());

        for (op, (_, mut label)) in VMOp::VARIANTS.iter().zip(cases) {
            rt.asm.set_label(&mut label).unwrap();

            print_thread_message(rt, &format!("{:?}", op), None, None);

            rt.asm.jmp(epilogue).unwrap();
        }

        rt.asm.set_label(&mut epilogue).unwrap();
    }

    let cases = HANDLERS
        .iter()
        .map(|&(op, def)| (rt.mapper.index(op), rt.function_labels[&def]))
        .collect::<Vec<(u8, CodeLabel)>>();

    rt.calls(r8, cases);

    // ret
    rt.asm.ret().unwrap();
}

use iced_x86::code_asm::{AsmRegister64, CodeLabel};

use crate::{runtime::Runtime, vm::bytecode::VMPrecision};

type Handler = Box<dyn FnOnce(&mut Runtime)>;

pub fn dispatch(
    rt: &mut Runtime,
    precision: AsmRegister64,
    epilogue: &CodeLabel,
    mut int: Option<Handler>,
    mut float: Option<Handler>,
) {
    let mut cases = Vec::new();
    let mut emits = Vec::new();

    macro_rules! case {
        ($opt:expr, $tag:expr) => {
            if let Some(f) = $opt.take() {
                let label = rt.asm.create_label();
                cases.push((rt.mapper.index($tag) as u8, label));
                emits.push((label, f));
            }
        };
    }

    case!(int, VMPrecision::Integer);
    case!(float, VMPrecision::Float);

    rt.jumps(precision, cases);

    for (mut label, f) in emits {
        rt.asm.set_label(&mut label).unwrap();
        f(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }
}

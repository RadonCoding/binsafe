use iced_x86::code_asm::{AsmRegister64, CodeLabel};

use crate::{runtime::Runtime, vm::bytecode::VMWidth};

type Handler = Box<dyn FnOnce(&mut Runtime)>;

pub fn dispatch(
    rt: &mut Runtime,
    width: AsmRegister64,
    epilogue: &CodeLabel,
    mut lower64: Option<Handler>,
    mut lower32: Option<Handler>,
    mut lower16: Option<Handler>,
    mut higher8: Option<Handler>,
    mut lower8: Option<Handler>,
    mut slower64: Option<Handler>,
    mut slower32: Option<Handler>,
    mut slower16: Option<Handler>,
    mut slower8: Option<Handler>,
    mut lower128: Option<Handler>,
    mut lower256: Option<Handler>,
) {
    let both8 = lower8.is_some() && higher8.is_some();
    let merged8 = lower8.is_some() != higher8.is_some();

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

    if both8 {
        case!(lower8, VMWidth::Lower8);
        case!(higher8, VMWidth::Higher8);
    } else if merged8 {
        let label = rt.asm.create_label();
        cases.push((rt.mapper.index(VMWidth::Lower8) as u8, label));
        cases.push((rt.mapper.index(VMWidth::Higher8) as u8, label));
        emits.push((label, lower8.take().or_else(|| higher8.take()).unwrap()));
    }

    case!(lower16, VMWidth::Lower16);
    case!(lower32, VMWidth::Lower32);
    case!(lower64, VMWidth::Lower64);
    case!(slower64, VMWidth::SLower64);
    case!(slower32, VMWidth::SLower32);
    case!(slower16, VMWidth::SLower16);
    case!(slower8, VMWidth::SLower8);
    case!(lower128, VMWidth::Lower128);
    case!(lower256, VMWidth::Lower256);

    rt.jumps(width, cases);

    for (mut label, f) in emits {
        rt.asm.set_label(&mut label).unwrap();
        f(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }
}

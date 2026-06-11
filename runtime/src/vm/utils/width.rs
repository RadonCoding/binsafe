use iced_x86::code_asm::{AsmRegister8, CodeLabel};

use crate::{runtime::Runtime, vm::bytecode::VMWidth};

type Handler = Box<dyn FnOnce(&mut Runtime)>;

pub fn dispatch(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,

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
    macro_rules! case {
        ($opt:expr, $tag:expr) => {
            if let Some(f) = $opt.take() {
                let mut skip = rt.asm.create_label();

                // cmp ..., ...
                rt.asm.cmp(width, rt.mapper.index($tag) as i32).unwrap();
                // jne ...
                rt.asm.jne(skip).unwrap();

                f(rt);

                // jmp ...
                rt.asm.jmp(*epilogue).unwrap();

                rt.asm.set_label(&mut skip).unwrap();

                rt.asm.zero_bytes().unwrap();
            }
        };
    }

    if higher8.is_some() && lower8.is_some() {
        case!(lower8, VMWidth::Lower8);
        case!(higher8, VMWidth::Higher8);
    } else if let Some(f) = higher8.take().or_else(|| lower8.take()) {
        let mut handler = rt.asm.create_label();
        let mut skip = rt.asm.create_label();

        // cmp ..., ...
        rt.asm
            .cmp(width, rt.mapper.index(VMWidth::Lower8) as i32)
            .unwrap();
        // je ...
        rt.asm.je(handler).unwrap();
        // cmp ..., ...
        rt.asm
            .cmp(width, rt.mapper.index(VMWidth::Higher8) as i32)
            .unwrap();
        // jne ...
        rt.asm.jne(skip).unwrap();

        rt.asm.set_label(&mut handler).unwrap();

        f(rt);

        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();

        rt.asm.set_label(&mut skip).unwrap();

        rt.asm.zero_bytes().unwrap();
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
}

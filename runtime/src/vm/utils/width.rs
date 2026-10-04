use iced_x86::code_asm::{AsmRegister64, CodeLabel};

use crate::{
    runtime::{Handler, Runtime},
    vm::bytecode::VMWidth,
};

pub fn dispatch(
    rt: &mut Runtime,
    width: AsmRegister64,
    epilogue: &CodeLabel,
    mut lower64: Option<Handler>,
    mut lower32: Option<Handler>,
    mut higher16: Option<Handler>,
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

    let mut handlers = Vec::new();

    macro_rules! case {
        ($opt:expr, $tag:expr) => {
            if let Some(f) = $opt.take() {
                handlers.push((vec![rt.mapper.index($tag) as u8], f));
            }
        };
    }

    if both8 {
        case!(lower8, VMWidth::Lower8);
        case!(higher8, VMWidth::Higher8);
    } else if merged8 {
        handlers.push((
            vec![
                rt.mapper.index(VMWidth::Lower8) as u8,
                rt.mapper.index(VMWidth::Higher8) as u8,
            ],
            lower8.take().or_else(|| higher8.take()).unwrap(),
        ));
    }

    case!(lower16, VMWidth::Lower16);
    case!(higher16, VMWidth::Higher16);
    case!(lower32, VMWidth::Lower32);
    case!(lower64, VMWidth::Lower64);
    case!(slower64, VMWidth::SLower64);
    case!(slower32, VMWidth::SLower32);
    case!(slower16, VMWidth::SLower16);
    case!(slower8, VMWidth::SLower8);
    case!(lower128, VMWidth::Lower128);
    case!(lower256, VMWidth::Lower256);

    rt.switch(width, *epilogue, handlers);
}

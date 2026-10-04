use iced_x86::code_asm::{AsmRegister64, CodeLabel};

use crate::{
    runtime::{Handler, Runtime},
    vm::bytecode::VMPrecision,
};

pub fn dispatch(
    rt: &mut Runtime,
    precision: AsmRegister64,
    epilogue: &CodeLabel,
    mut int: Option<Handler>,
    mut float: Option<Handler>,
) {
    let mut handlers = Vec::new();

    macro_rules! case {
        ($opt:expr, $tag:expr) => {
            if let Some(f) = $opt.take() {
                handlers.push((vec![rt.mapper.index($tag) as u8], f));
            }
        };
    }

    case!(int, VMPrecision::Integer);
    case!(float, VMPrecision::Float);

    rt.switch(precision, *epilogue, handlers);
}

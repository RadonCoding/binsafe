pub mod functions;
pub mod mapper;
pub mod runtime;
pub mod vm;

macro_rules! define_offset {
    ($name:ident, $offset:expr, $size:expr) => {
        $offset += $size;
        let $name = $offset;
    };
}

pub(crate) use define_offset;

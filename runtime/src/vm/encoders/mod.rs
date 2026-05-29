use std::any::Any;
use std::fmt::{self, Debug};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMMem, VMReg, VMWidth};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Register(VMReg),
    Memory(VMMem, u8),
    Flags,
    Scratch,
}

pub trait Encode: Debug + Any {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8>;

    fn size(&mut self, mapper: &mut Mapper) -> usize {
        self.encode(mapper).len()
    }

    fn reads(&self) -> Vec<Effect> {
        vec![]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![]
    }
}

#[cfg(debug_assertions)]
impl fmt::Display for dyn Encode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format!("{self:?}");
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == ':' && chars.peek() == Some(&' ') {
                chars.next();
                while out.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                    out.pop();
                }
            } else {
                out.push(ch);
            }
        }

        let out = out.replace(" { ", "(").replace(" }", ")");

        let mut result = String::with_capacity(out.len());
        let mut chars = out.char_indices().peekable();

        while let Some((i, ch)) = chars.next() {
            if ch == '[' {
                let remaining = &out[i + 1..];

                if let Some(end) = remaining.find(']') {
                    let bytes: Option<Vec<u8>> = remaining[..end]
                        .split(',')
                        .map(|b| b.trim().parse::<u8>().ok())
                        .collect();

                    if let Some(bytes) = bytes {
                        match bytes.len() {
                            4 => {
                                result.push_str(&format!(
                                    "0x{:08X}",
                                    u32::from_le_bytes(bytes.try_into().unwrap())
                                ));
                                chars.nth(end);
                                continue;
                            }
                            8 => {
                                result.push_str(&format!(
                                    "0x{:016X}",
                                    u64::from_le_bytes(bytes.try_into().unwrap())
                                ));
                                chars.nth(end);
                                continue;
                            }
                            _ => {}
                        }
                    }
                }
            }
            result.push(ch);
        }

        write!(f, "{result}")
    }
}

pub fn encode_immediate(value: u64) -> (VMWidth, usize) {
    match value {
        0..=0xFF => (VMWidth::Lower8, 1),
        0..=0xFFFF => (VMWidth::Lower16, 2),
        0..=0xFFFFFFFF => (VMWidth::Lower32, 4),
        _ => (VMWidth::Lower64, 8),
    }
}

pub mod add;
pub mod discard;
pub mod jcc;
pub mod load_address;
pub mod load_immediate;
pub mod load_memory;
pub mod load_register;
pub mod ret;
pub mod skip;
pub mod store_memory;
pub mod store_register;
pub mod sub;

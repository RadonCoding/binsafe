use std::fmt::{self, Debug};

use crate::mapper::Mapper;

pub trait Encode: Debug {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8>;
}

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

pub fn compose_2(a: impl Encode + 'static, b: impl Encode + 'static) -> Vec<Box<dyn Encode>> {
    vec![Box::new(a), Box::new(b)]
}

pub fn compose_3(
    a: impl Encode + 'static,
    b: impl Encode + 'static,
    c: impl Encode + 'static,
) -> Vec<Box<dyn Encode>> {
    vec![Box::new(a), Box::new(b), Box::new(c)]
}

pub mod jcc;
pub mod lea;
pub mod load_addr;
pub mod load_imm;
pub mod load_mem;
pub mod load_reg;
pub mod mov;
pub mod nop;
pub mod store_mem;
pub mod store_reg;

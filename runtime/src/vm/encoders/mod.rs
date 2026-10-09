use std::any::{type_name, Any};
use std::fmt::{self, Debug};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCode, VMReg, VMVec};

pub mod adc;
pub mod add;
pub mod and;
pub mod back;
pub mod bit_scan_reverse;
pub mod bit_test;
pub mod bit_test_complement;
pub mod bit_test_reset;
pub mod bit_test_set;
pub mod block;
pub mod branch;
pub mod byte_swap;
pub mod compare_exchange;
pub mod compound;
pub mod cpuid;
pub mod discard;
pub mod div;
pub mod exchange;
pub mod exchange_add;
pub mod label;
pub mod load_address;
pub mod load_immediate;
pub mod load_memory;
pub mod load_register;
pub mod load_vector;
pub mod mul;
pub mod or;
pub mod packed_byte_equal;
pub mod packed_byte_mask;
pub mod pop;
pub mod push;
pub mod rol;
pub mod ror;
pub mod sar;
pub mod sbb;
pub mod shl;
pub mod shr;
pub mod store_extend;
pub mod store_memory;
pub mod store_merge;
pub mod store_register;
pub mod sub;
pub mod timestamp;
pub mod trailing_zeros;
pub mod vector_add;
pub mod vector_and;
pub mod vector_and_not;
pub mod vector_div;
pub mod vector_mul;
pub mod vector_or;
pub mod vector_sub;
pub mod vector_xor;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Effect {
    Register(VMReg),
    Vector(VMVec),
    Memory,
}

pub fn identity(operation: &Box<dyn Encode>) -> usize {
    operation.as_ref() as *const dyn Encode as *const () as usize
}

pub trait Depth {
    fn depth(&self) -> i32;
}

impl<T: Encode + ?Sized> Depth for T {
    fn depth(&self) -> i32 {
        self.produces() - self.consumes()
    }
}

pub trait Encode: Debug + Any {
    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn name(&self) -> &'static str {
        type_name::<Self>().rsplit("::").next().unwrap()
    }

    fn code(&self) -> Option<VMCode>;

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8>;

    fn size(&self, mapper: &mut Mapper) -> usize {
        self.code().map_or(0, |_| 1) + self.encode(mapper).len()
    }

    fn reads(&self) -> Vec<Effect> {
        vec![]
    }

    fn writes(&self) -> Vec<Effect> {
        vec![]
    }

    fn consumes(&self) -> i32 {
        0
    }

    fn produces(&self) -> i32 {
        0
    }

    fn is_source(&self) -> bool {
        false
    }

    fn is_destination(&self) -> bool {
        false
    }

    fn is_branch(&self) -> bool {
        false
    }

    fn children_ref(&self) -> Option<&[Box<dyn Encode>]> {
        None
    }

    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Encode>>> {
        None
    }

    fn seal(&mut self, _mapper: &mut Mapper, _transform: &mut dyn FnMut(&mut [u8], usize)) {}
}

impl fmt::Display for dyn Encode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = strip_fields(&format!("{self:?}"))
            .replace(" { ", "(")
            .replace(" }", ")");
        let s = hex_bytes(&s);
        let s = hex_decimals(&s);
        write!(f, "{s}")
    }
}

fn strip_fields(input: &str) -> String {
    let mut output = String::with_capacity(input.len());

    let mut characters = input.chars().peekable();

    while let Some(c) = characters.next() {
        if c == ':' && characters.peek() == Some(&' ') {
            characters.next();

            while output.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                output.pop();
            }
        } else {
            output.push(c);
        }
    }
    output
}

fn hex_bytes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());

    let mut characters = input.char_indices().peekable();

    while let Some((i, c)) = characters.next() {
        if c == '[' {
            if let Some(end) = input[i + 1..].find(']') {
                let bytes = input[i + 1..i + 1 + end]
                    .split(',')
                    .map(|b| b.trim().parse::<u8>().ok())
                    .collect::<Option<Vec<u8>>>();
                if let Some(bytes) = bytes {
                    let hex = match bytes.len() {
                        1 => Some(format!(
                            "0x{:02X}",
                            u8::from_le_bytes(bytes.try_into().unwrap())
                        )),
                        2 => Some(format!(
                            "0x{:04X}",
                            u16::from_le_bytes(bytes.try_into().unwrap())
                        )),
                        4 => Some(format!(
                            "0x{:08X}",
                            u32::from_le_bytes(bytes.try_into().unwrap())
                        )),
                        8 => Some(format!(
                            "0x{:016X}",
                            u64::from_le_bytes(bytes.try_into().unwrap())
                        )),
                        _ => None,
                    };
                    if let Some(hex) = hex {
                        output.push_str(&hex);
                        characters.nth(end);
                        continue;
                    }
                }
            }
        }
        output.push(c);
    }
    output
}

fn hex_decimals(input: &str) -> String {
    let mut output = String::with_capacity(input.len());

    let characters = input.chars().collect::<Vec<char>>();

    let mut i = 0;

    while i < characters.len() {
        let c = characters[i];

        if c == '0' && matches!(characters.get(i + 1), Some('x') | Some('X')) {
            output.extend(characters[i..i + 2].iter());
            i += 2;
            while matches!(characters.get(i), Some(c) if c.is_ascii_hexdigit()) {
                output.push(characters[i]);
                i += 1;
            }
            continue;
        }

        let previous =
            i > 0 && (characters[i - 1].is_ascii_alphanumeric() || characters[i - 1] == '_');

        let (start, negative) = match c {
            '-' if !previous && matches!(characters.get(i + 1), Some(c) if c.is_ascii_digit()) => {
                (i + 1, true)
            }
            c if c.is_ascii_digit() && !previous => (i, false),
            _ => {
                output.push(c);
                i += 1;
                continue;
            }
        };

        let mut end = start;

        while matches!(characters.get(end), Some(c) if c.is_ascii_digit()) {
            end += 1;
        }

        let digits = characters[start..end].iter().collect::<String>();

        match digits.parse::<i64>() {
            Ok(value) => {
                let value = if negative { -value } else { value };

                if value >= i8::MIN as i64 && value <= i8::MAX as i64 {
                    output.push_str(&format!("0x{:02X}", value as u8));
                } else if value >= i16::MIN as i64 && value <= i16::MAX as i64 {
                    output.push_str(&format!("0x{:04X}", value as u16));
                } else if value >= i32::MIN as i64 && value <= i32::MAX as i64 {
                    output.push_str(&format!("0x{:08X}", value as u32));
                } else {
                    output.push_str(&format!("0x{:016X}", value as u64));
                }
            }
            Err(_) => {
                if negative {
                    output.push('-');
                }
                output.push_str(&digits);
            }
        }
        i = end;
    }
    output
}
pub mod xor;

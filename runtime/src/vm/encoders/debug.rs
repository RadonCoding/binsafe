#![allow(unused)]

use crate::vm::encoders::Encode;
use std::fmt;

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

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
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
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
    out
}

fn hex_bytes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        if ch == '[' {
            if let Some(end) = input[i + 1..].find(']') {
                let bytes = input[i + 1..i + 1 + end]
                    .split(',')
                    .map(|b| b.trim().parse::<u8>().ok())
                    .collect::<Option<Vec<u8>>>();
                if let Some(bytes) = bytes {
                    let hex = match bytes.len() {
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
                        out.push_str(&hex);
                        chars.nth(end);
                        continue;
                    }
                }
            }
        }
        out.push(ch);
    }
    out
}

fn hex_decimals(input: &str) -> String {
    let chars = input.chars().collect::<Vec<char>>();
    let mut out = String::with_capacity(input.len());

    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch == '0' && matches!(chars.get(i + 1), Some('x') | Some('X')) {
            out.extend(chars[i..i + 2].iter());
            i += 2;
            while matches!(chars.get(i), Some(c) if c.is_ascii_hexdigit()) {
                out.push(chars[i]);
                i += 1;
            }
            continue;
        }
        let prev_alnum = i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
        let (start, negative) = match ch {
            '-' if !prev_alnum && matches!(chars.get(i + 1), Some(c) if c.is_ascii_digit()) => {
                (i + 1, true)
            }
            c if c.is_ascii_digit() && !prev_alnum => (i, false),
            _ => {
                out.push(ch);
                i += 1;
                continue;
            }
        };
        let mut end = start;
        while matches!(chars.get(end), Some(c) if c.is_ascii_digit()) {
            end += 1;
        }
        let digits = chars[start..end].iter().collect::<String>();
        match digits.parse::<i64>() {
            Ok(value) => {
                let value = if negative { -value } else { value };
                out.push_str(&format!("0x{:X}", value));
            }
            Err(_) => {
                if negative {
                    out.push('-');
                }
                out.push_str(&digits);
            }
        }
        i = end;
    }
    out
}

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        };
        write!(f, "{}", s)
    }
}

fn log(level: LogLevel, args: fmt::Arguments) {
    let now = SystemTime::now();
    let epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let unix = epoch.as_secs();
    let hours = (unix / 3600) % 24;
    let minutes = (unix / 60) % 60;
    let seconds = unix % 60;
    println!(
        "[{:02}:{:02}:{:02}] [{}] {}",
        hours, minutes, seconds, level, args
    );
}

pub fn info(fmt: impl fmt::Display) {
    log(LogLevel::Info, format_args!("{}", fmt));
}

pub fn warn(fmt: impl fmt::Display) {
    log(LogLevel::Warn, format_args!("{}", fmt));
}

pub fn error(fmt: impl fmt::Display) {
    log(LogLevel::Error, format_args!("{}", fmt));
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::info(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::warn(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::error(format_args!($($arg)*))
    };
}

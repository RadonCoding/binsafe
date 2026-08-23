#[macro_export]
macro_rules! binsafe_begin {
    () => {
        unsafe {
            ::std::arch::asm!(".byte 0xEB, 0x08, 0x42, 0x49, 0x4E, 0x53, 0x41, 0x46, 0x45, 0x01", options(nostack, preserves_flags));
        }
    };
}

#[macro_export]
macro_rules! binsafe_end {
    () => {
        unsafe {
            ::std::arch::asm!(".byte 0xEB, 0x08, 0x42, 0x49, 0x4E, 0x53, 0x41, 0x46, 0x45, 0x02", options(nostack, preserves_flags));
        }
    };
}

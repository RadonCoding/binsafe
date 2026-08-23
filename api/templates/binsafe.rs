#[macro_export]
macro_rules! binsafe_begin {
    () => {
        unsafe {
            ::std::arch::asm!(".byte {begin}", options(nostack, preserves_flags));
        }
    };
}

#[macro_export]
macro_rules! binsafe_end {
    () => {
        unsafe {
            ::std::arch::asm!(".byte {end}", options(nostack, preserves_flags));
        }
    };
}

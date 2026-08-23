pub const MARKER_SIZE: usize = 10;

pub const MARKER_BEGIN: [u8; MARKER_SIZE] = [
    0xEB,
    (MARKER_SIZE - 2) as u8,
    b'B',
    b'I',
    b'N',
    b'S',
    b'A',
    b'F',
    b'E',
    0x01,
];

pub const MARKER_END: [u8; MARKER_SIZE] = [
    0xEB,
    (MARKER_SIZE - 2) as u8,
    b'B',
    b'I',
    b'N',
    b'S',
    b'A',
    b'F',
    b'E',
    0x02,
];

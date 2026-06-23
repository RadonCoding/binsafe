use rand::Rng;
use runtime::VM_INTEGRITY_BYTE;

const HEADER_SIZE: usize = size_of::<u16>();
const TRAILER_SIZE: usize = size_of::<u8>() + size_of::<u8>();
const ENCRYPTED: u8 = 0;
const DECRYPTED: u8 = 1;

pub fn derive_key(bytes: &[u8]) -> u64 {
    let end = bytes.len() - TRAILER_SIZE;
    let start = end - size_of::<u64>();
    u64::from_le_bytes(bytes[start..end].try_into().unwrap())
}

pub fn encrypt_block(block: &mut Vec<u8>, key: u64, mul: u64, add: u64, att: u64) {
    let length = prepare_block(block);
    encrypt_payload(block, key, mul, add, att);
    finalize_encrypt(block, length);
}

pub fn decrypt_block(block: &mut Vec<u8>, key: u64, mul: u64, add: u64, att: u64) {
    let length = u16::from_le_bytes(block[..HEADER_SIZE].try_into().unwrap()) as usize;
    decrypt_payload(block, key, mul, add, att);
    unprepare_block(block, length);
}

fn align_payload(block: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    block.push(VM_INTEGRITY_BYTE);

    while block.len() % 8 != 0 {
        block.push(rng.gen::<u8>());
    }
}

fn encrypt_payload(block: &mut [u8], key: u64, mul: u64, add: u64, att: u64) {
    let mut key = key ^ att;

    for chunk in block.chunks_exact_mut(8) {
        let mut qword = u64::from_le_bytes(chunk.try_into().unwrap());
        qword ^= key;
        chunk.copy_from_slice(&qword.to_le_bytes());
        key ^= qword;
        key = key.wrapping_mul(mul).wrapping_add(add);
    }
}

pub fn decrypt_payload(block: &mut [u8], mut key: u64, mul: u64, add: u64, att: u64) {
    let length = u16::from_le_bytes(block[..HEADER_SIZE].try_into().unwrap()) as usize;
    let payload = &mut block[HEADER_SIZE..HEADER_SIZE + ((length + 1 + 7) & !7)];

    for chunk in payload.chunks_exact_mut(8) {
        let qword = u64::from_le_bytes(chunk.try_into().unwrap());
        let original = qword ^ key;
        chunk.copy_from_slice(&original.to_le_bytes());
        key ^= qword ^ att;
        key = key.wrapping_mul(mul).wrapping_add(add);
    }

    assert_eq!(payload[length], VM_INTEGRITY_BYTE);

    finalize_decrypt(block);
}

pub fn finalize_encrypt(block: &mut Vec<u8>, length: u16) {
    // word  - length
    block.splice(0..0, length.to_le_bytes());
    // byte  - state
    block.push(ENCRYPTED);
    // byte  - lock
    block.push(0);
}

fn finalize_decrypt(block: &mut [u8]) {
    // byte  - state
    block[block.len() - TRAILER_SIZE] = DECRYPTED;
}

fn prepare_block(block: &mut Vec<u8>) -> u16 {
    let length = TryInto::<u16>::try_into(block.len()).unwrap();
    align_payload(block);
    length
}

fn unprepare_block(block: &mut Vec<u8>, length: usize) {
    block.drain(..HEADER_SIZE);
    block.truncate(length);
}

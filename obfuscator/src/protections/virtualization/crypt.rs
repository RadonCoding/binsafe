use rand::Rng;
use runtime::{VM_CIPHER_ROUNDS, VM_INTEGRITY_QWORD};

pub const HEADER_SIZE: usize = size_of::<u16>();
pub const TRAILER_SIZE: usize = size_of::<u8>() + size_of::<u8>();

const ENCRYPTED: u8 = 0;
const DECRYPTED: u8 = 1;

fn keystream(key: u64, counter: u64) -> u64 {
    let mut a = key as u32;
    let mut b = (key >> 32) as u32;
    let mut x = (counter >> 32) as u32;
    let mut y = counter as u32;

    for round in 0..VM_CIPHER_ROUNDS {
        x = x.rotate_right(8).wrapping_add(y) ^ a;
        y = y.rotate_left(3) ^ x;
        b = a.wrapping_add(b.rotate_right(8)) ^ round;
        a = a.rotate_left(3) ^ b;
    }

    ((x as u64) << 32) | (y as u64)
}

pub struct Cipher {
    multiplier: u64,
    addend: u64,
}

impl Cipher {
    pub fn new(multiplier: u64, addend: u64) -> Self {
        Self { multiplier, addend }
    }

    pub fn encrypt_block(&self, block: &mut Vec<u8>, key: u64, secret: u64) {
        let length = prepare_block(block);
        finalize_encrypt(block, length);
        self.encrypt_payload(block, key, secret);
    }

    pub fn decrypt_block(&self, block: &mut Vec<u8>, key: u64, secret: u64) {
        let length = u16::from_le_bytes(block[..HEADER_SIZE].try_into().unwrap()) as usize;
        self.decrypt_payload(block, key, secret);
        unprepare_block(block, length);
    }

    pub fn encrypt_payload(&self, block: &mut [u8], key: u64, secret: u64) {
        let length = u16::from_le_bytes(block[..HEADER_SIZE].try_into().unwrap()) as usize;
        let payload = &mut block[HEADER_SIZE..HEADER_SIZE + ((length + 8 + 7) & !7)];

        let key = (key ^ secret)
            .wrapping_mul(self.multiplier)
            .wrapping_add(self.addend);

        for (counter, chunk) in payload.chunks_exact_mut(8).enumerate() {
            let qword = u64::from_le_bytes(chunk.try_into().unwrap());
            let cipher = qword ^ keystream(key, counter as u64);
            chunk.copy_from_slice(&cipher.to_le_bytes());
        }

        // byte  - state
        block[block.len() - TRAILER_SIZE] = ENCRYPTED;
    }

    pub fn decrypt_payload(&self, block: &mut [u8], key: u64, secret: u64) {
        let length = u16::from_le_bytes(block[..HEADER_SIZE].try_into().unwrap()) as usize;
        let payload = &mut block[HEADER_SIZE..HEADER_SIZE + ((length + 8 + 7) & !7)];

        let key = (key ^ secret)
            .wrapping_mul(self.multiplier)
            .wrapping_add(self.addend);

        for (counter, chunk) in payload.chunks_exact_mut(8).enumerate() {
            let cipher = u64::from_le_bytes(chunk.try_into().unwrap());
            let original = cipher ^ keystream(key, counter as u64);
            chunk.copy_from_slice(&original.to_le_bytes());
        }

        assert_eq!(
            u64::from_le_bytes(
                payload[length..length + size_of::<u64>()]
                    .try_into()
                    .unwrap()
            ),
            VM_INTEGRITY_QWORD
        );

        finalize_decrypt(block);
    }
}

pub fn derive_hash(bytes: &[u8], multiplier: u64, addend: u64) -> u64 {
    let start = HEADER_SIZE;
    let end = bytes.len() - TRAILER_SIZE;
    let payload = &bytes[start..end];

    let mut chunks = payload.chunks_exact(size_of::<u64>());
    let mut hash = 0u64;

    for chunk in &mut chunks {
        hash = (hash ^ u64::from_le_bytes(chunk.try_into().unwrap()))
            .wrapping_mul(multiplier)
            .wrapping_add(addend);
    }

    for &byte in chunks.remainder() {
        hash = (hash ^ byte as u64)
            .wrapping_mul(multiplier)
            .wrapping_add(addend);
    }

    hash
}

pub fn derive_key(bytes: &[u8]) -> u64 {
    let end = bytes.len() - TRAILER_SIZE;
    let start = end - size_of::<u64>();
    u64::from_le_bytes(bytes[start..end].try_into().unwrap())
}

fn align_payload(block: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    block.extend(VM_INTEGRITY_QWORD.to_le_bytes());

    while block.len() % 8 != 0 {
        block.push(rng.gen::<u8>());
    }
}

fn finalize_encrypt(block: &mut Vec<u8>, length: u16) {
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

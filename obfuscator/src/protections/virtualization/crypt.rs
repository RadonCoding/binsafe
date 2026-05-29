use rand::Rng;

pub fn encrypt(
    block: &mut Vec<u8>,
    key: u64,
    key_mul: u64,
    key_add: u64,
    key_att: u64,
    rng: &mut impl Rng,
) {
    let length = TryInto::<u16>::try_into(block.len()).unwrap();
    pad(block, rng);
    encrypt_chunks(block, key, key_mul, key_add, key_att);
    finalize(block, length);
}

pub fn decrypt(block: &mut Vec<u8>, key: u64, key_mul: u64, key_add: u64, key_att: u64) {
    let length =
        u16::from_le_bytes(block.drain(0..2).collect::<Vec<u8>>().try_into().unwrap()) as usize;
    block.pop();
    decrypt_chunks(block, key, key_mul, key_add, key_att);
    block.truncate(length);
}

pub fn pad(block: &mut Vec<u8>, rng: &mut impl Rng) {
    while block.len() % 8 != 0 {
        block.push(rng.gen::<u8>());
    }
}

pub fn encrypt_chunks(chunks: &mut [u8], key: u64, key_mul: u64, key_add: u64, key_att: u64) {
    let mut key = key ^ key_att;

    for chunk in chunks.chunks_exact_mut(8) {
        let mut qword = u64::from_le_bytes(chunk.try_into().unwrap());
        qword ^= key;
        chunk.copy_from_slice(&qword.to_le_bytes());
        key ^= qword;
        key = key.wrapping_mul(key_mul).wrapping_add(key_add);
    }
}

pub fn decrypt_chunks(data: &mut [u8], mut key: u64, key_mul: u64, key_add: u64, key_att: u64) {
    for chunk in data.chunks_exact_mut(8) {
        let qword = u64::from_le_bytes(chunk.try_into().unwrap());
        let original = qword ^ key;
        chunk.copy_from_slice(&original.to_le_bytes());
        key ^= qword ^ key_att;
        key = key.wrapping_mul(key_mul).wrapping_add(key_add);
    }
}

pub fn finalize(block: &mut Vec<u8>, length: u16) {
    // WORD - length of the VM-block [0..2]
    block.splice(0..0, length.to_le_bytes());
    // BYTE - lock state of the VM-block [..1]
    block.push(0);
}

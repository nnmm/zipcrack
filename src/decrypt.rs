use std::num::Wrapping;

use arrayvec::ArrayVec;

pub const RESULT_CAPACITY: usize = 256;

#[derive(Clone, Copy)]
pub struct EncryptionData {
    pub encryption_header: [u8; 12],
    pub last_mod_file_time: u16,
}

const fn crc32_byte(mut byte: u8) -> u32 {
    byte = byte.reverse_bits();
    let mut value = (byte as u32) << 24;
    let mut i = 0;
    while i < 8 {
        value = (value << 1) ^ ((value >> 31) * 0x04c11db7);
        i += 1;
    }
    value = value.reverse_bits();
    value
}

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < table.len() {
        table[i] = crc32_byte(i as u8);
        i += 1;
    }
    table
}

const CRC_32_TAB: &[u32; 256] = &crc32_table();

pub const fn crc32(crc: u32, byte: u8) -> u32 {
    let index = crc as u8 ^ byte;
    CRC_32_TAB[index as usize] ^ (crc >> 8)
}

#[inline(always)]
pub fn update_keys(keys: &mut [u32; 3], c: u8) {
    keys[0] = crc32(keys[0], c);
    keys[1] = (Wrapping(keys[1]) + Wrapping(keys[0] & 0x000000ff)).0;
    keys[1] = (Wrapping(keys[1]) * Wrapping(134775813) + Wrapping(1)).0;
    keys[2] = crc32(keys[2], (keys[1] >> 24) as u8);
}

#[inline(always)]
pub fn decrypt_byte(key2: u32) -> u8 {
    let temp = key2 as u16 | 2;
    let res = (Wrapping(temp) * Wrapping(temp ^ 1)).0 >> 8;
    res as u8
}

/// The "plain" version of the password check as described in APPNOTE.TXT
#[allow(unused)]
pub fn password_matches(mut ed: EncryptionData, password: &[u8]) -> bool {
    // 6.1.5 Initializing the encryption keys
    let mut keys = [305419896u32, 591751049u32, 878082192u32];
    for &c in password {
        update_keys(&mut keys, c);
    }

    // 6.1.6 Decrypting the encryption header
    for buf in &mut ed.encryption_header {
        let c: u8 = *buf ^ decrypt_byte(keys[2]);
        update_keys(&mut keys, c);
        *buf = c;
    }

    // The last bytes in buffer should be the timestamp
    ed.encryption_header[10..] == ed.last_mod_file_time.to_le_bytes()
}

pub fn encryption_data_matches(mut ed: EncryptionData, mut keys: [u32; 3]) -> bool {
    // 6.1.6 Decrypting the encryption header
    for buf in &mut ed.encryption_header {
        let c: u8 = *buf ^ decrypt_byte(keys[2]);
        update_keys(&mut keys, c);
        *buf = c;
    }

    // The last bytes in buffer should be the timestamp
    ed.encryption_header[10..] == ed.last_mod_file_time.to_le_bytes()
}

/// Represents a "block" of passwords where only the last letter is variable
/// Some computation can be done just once per password block, saving work
#[derive(Clone, Copy, Debug)]
pub struct PasswordBlock<'a> {
    /// All letters except the last one
    pub password_prefix: &'a [u8],
    /// Alphabet to sample the last letters from
    pub alphabet: &'a [u8],
    /// Keys initialized with the password prefix
    pub initialized_keys: [u32; 3],
}

#[inline(never)]
pub fn password_block_matches(
    password_block: PasswordBlock,
    ed: EncryptionData,
    matching_chars: &mut ArrayVec<u8, RESULT_CAPACITY>,
) {
    // Here the last letter of the password is unrolled:
    // This way, we don't repeat the block above for passwords that are identical apart from the last letter.
    for &last_char in password_block.alphabet {
        let mut keys_for_char = password_block.initialized_keys;
        let mut encryption_header_for_char = ed.encryption_header;
        update_keys(&mut keys_for_char, last_char);

        // 6.1.6 Decrypting the encryption header
        for buf in &mut encryption_header_for_char {
            let c: u8 = *buf ^ decrypt_byte(keys_for_char[2]);
            update_keys(&mut keys_for_char, c);
            *buf = c;
        }

        // The last bytes in buffer should be the timestamp
        if encryption_header_for_char[10..] == ed.last_mod_file_time.to_le_bytes() {
            matching_chars.push(last_char);
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    const BASE64_ALPHABET: &[u8; 64] =
        b"+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    #[test]
    fn test_three_letter_passwords() {
        let ed = EncryptionData {
            encryption_header: [147, 150, 41, 25, 165, 183, 31, 129, 76, 121, 70, 196],
            last_mod_file_time: 40784,
        };
        let mut password = b"---".to_vec();
        let mut found_passwords = vec![];
        for i in 0..64 {
            password[0] = BASE64_ALPHABET[i];
            for j in 0..64 {
                password[1] = BASE64_ALPHABET[j];
                for k in 0..64 {
                    password[2] = BASE64_ALPHABET[k];
                    if password_matches(ed, &password) {
                        found_passwords.push(password.clone());
                    }
                }
            }
        }
        let expected_passwords = vec![
            vec![51, 98, 119],
            vec![53, 90, 120],
            vec![73, 87, 89],
            vec![77, 51, 101],
            vec![80, 54, 49],
            vec![101, 86, 119],
            vec![115, 72, 68],
        ];
        assert_eq!(found_passwords, expected_passwords);
    }
}

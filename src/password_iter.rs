use crate::decrypt::*;
use crate::info::*;
use crate::opt::*;

use std::sync::atomic::Ordering;

pub type Password = [u8];
pub type InitializedKeys = [u32; 3];

/// Iterative password enumeration
pub fn for_each_password(opt: &Opt, mut callback: impl FnMut(&Password, InitializedKeys)) {
    let min_char = opt.alphabet.0[0];
    let max_char = opt.alphabet.0[opt.alphabet.0.len() - 1];

    // Use a LUT to efficiently "increment" a character to the next character in the alphabet
    let next_char = {
        let mut lut = vec![0; usize::from(max_char)];
        for slice in opt.alphabet.0.windows(2) {
            let cur = slice[0];
            let next = slice[1];
            lut[usize::from(cur)] = next;
        }
        lut
    };

    let mut password = if let Some(pw) = opt.start_password.clone() {
        pw.into_bytes()
    } else {
        vec![min_char; opt.min_length.into()]
    };

    // Redoing the initialization of keys for passwords that differ only in the last few characters
    // is redundant. Instead, cache the initialized keys up to character i and use that to compute
    // the keys after character i. This makes the key testing effort independent of key length.
    // initialized_keys[i] contains the keys after i characters.
    // Therefore, initialized_keys is 1 longer than password.
    let mut initialized_keys = vec![[305419896u32, 591751049u32, 878082192u32]];

    // Handle special case where min_length == 0
    if password.is_empty() {
        callback(&password, initialized_keys[0]);
        password.push(min_char);
        if opt.max_length == 0 {
            return;
        }
    }

    'main_loop: loop {
        while initialized_keys.len() <= password.len() {
            let i = initialized_keys.len();
            initialized_keys.push(initialized_keys[i - 1]);
            update_keys(&mut initialized_keys[i], password[i - 1]);
        }
        callback(&password, initialized_keys[password.len()]);
        let mut cursor = password.len() - 1;
        while password[cursor] == max_char {
            initialized_keys.pop();
            password[cursor] = min_char;
            if cursor == 0 {
                if password.len() == usize::from(opt.max_length) {
                    // We're done.
                    return;
                }
                password.push(min_char);
                continue 'main_loop;
            } else {
                cursor -= 1;
            }
        }
        initialized_keys.pop();
        password[cursor] = next_char[usize::from(password[cursor])];
    }
}

/// Iterative password enumeration with the last character unrolled
///
/// Note: This will not check the empty password
pub fn for_each_password_unrolled(opt: &Opt, mut callback: impl FnMut(PasswordBlock)) {
    let mut modified_opt = opt.clone();
    // TODO: Check that the start_password is respected here
    modified_opt.min_length = modified_opt.min_length.saturating_sub(1);
    modified_opt.max_length = modified_opt.max_length.saturating_sub(1);
    let chunked_alphabet: Vec<_> = opt
        .alphabet
        .0
        .chunks(8)
        .map(|slice| {
            // This will pad the last chunk to 8. Unwrap is safe since chunks() doesn't yield empty slices.
            let mut arr = [*slice.last().unwrap(); 8];
            arr[..slice.len()].clone_from_slice(slice);
            arr
        })
        .collect();

    let callback_for_single_password = move |pw: &[u8], initialized_keys: InitializedKeys| {
        let password_block = PasswordBlock {
            password_prefix: pw,
            alphabet: chunked_alphabet.as_slice(),
            initialized_keys,
        };
        callback(password_block);
    };
    for_each_password(&modified_opt, callback_for_single_password);
}

/// Given a password validation function, tests each password
pub fn test_each_password(
    opt: &Opt,
    info_data: &InfoData,
    mut predicate: impl FnMut(InitializedKeys) -> bool,
) {
    let callback_with_info = move |pw: &[u8], initialized_keys: InitializedKeys| {
        let count = info_data.counter.fetch_add(1, Ordering::Relaxed);

        // Once in a while, tell the info thread a recent password
        if count % 100_000 == 0 {
            let mut recent_password = info_data.recent_password.lock().unwrap();
            *recent_password = String::from_utf8_lossy(pw).into_owned();
        }
        if predicate(initialized_keys) {
            let s = String::from_utf8_lossy(pw);
            let mut found_passwords = info_data.found_passwords.lock().unwrap();
            found_passwords.push(s.into_owned());
        }
    };
    for_each_password(opt, callback_with_info);
}

/// Given a password block validation function, tests each password
pub fn test_each_password_unrolled(
    opt: &Opt,
    info_data: &InfoData,
    mut block_predicate: impl FnMut(PasswordBlock) -> Vec<Vec<u8>>,
) {
    let mut block_counter = 0;
    let password_block_size = u64::try_from(opt.alphabet.0.len()).unwrap();
    let callback_with_info = move |password_block: PasswordBlock| {
        info_data
            .counter
            .fetch_add(password_block_size, Ordering::Relaxed);
        block_counter += 1;

        // Once in a while, tell the info thread a recent password
        if block_counter == 100_000 {
            let mut recent_password = info_data.recent_password.lock().unwrap();
            let last_password_prefix = password_block.password_prefix.to_vec();
            *recent_password =
                String::from_utf8(last_password_prefix).expect("Password is not valid UTF-8");
            recent_password.push('-');
            block_counter = 0;
        }

        for pw in block_predicate(password_block) {
            let s = String::from_utf8(pw).expect("Password is not valid UTF-8");
            let mut found_passwords = info_data.found_passwords.lock().unwrap();
            found_passwords.push(s);
        }
    };
    for_each_password_unrolled(opt, callback_with_info);
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_opt() -> Opt {
        Opt {
            input: std::path::PathBuf::new(),
            show_zipfile_records: false,
            min_length: 1,
            max_length: 3,
            start_password: None,
            alphabet: Alphabet(b"abc".to_vec()),
            unroll: false,
        }
    }

    #[test]
    fn test_abc_passwords() {
        let opt = test_opt();
        let expected_passwords = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"aa".to_vec(),
            b"ab".to_vec(),
            b"ac".to_vec(),
            b"ba".to_vec(),
            b"bb".to_vec(),
            b"bc".to_vec(),
            b"ca".to_vec(),
            b"cb".to_vec(),
            b"cc".to_vec(),
            b"aaa".to_vec(),
            b"aab".to_vec(),
            b"aac".to_vec(),
            b"aba".to_vec(),
            b"abb".to_vec(),
            b"abc".to_vec(),
            b"aca".to_vec(),
            b"acb".to_vec(),
            b"acc".to_vec(),
            b"baa".to_vec(),
            b"bab".to_vec(),
            b"bac".to_vec(),
            b"bba".to_vec(),
            b"bbb".to_vec(),
            b"bbc".to_vec(),
            b"bca".to_vec(),
            b"bcb".to_vec(),
            b"bcc".to_vec(),
            b"caa".to_vec(),
            b"cab".to_vec(),
            b"cac".to_vec(),
            b"cba".to_vec(),
            b"cbb".to_vec(),
            b"cbc".to_vec(),
            b"cca".to_vec(),
            b"ccb".to_vec(),
            b"ccc".to_vec(),
        ];
        let mut passwords = vec![];
        for_each_password(&opt, |pw: &[u8], _: InitializedKeys| {
            passwords.push(pw.to_vec())
        });
        assert_eq!(passwords, expected_passwords);
        passwords = vec![];
        for_each_password_unrolled(&opt, |pb: PasswordBlock| {
            for &last_char in pb.alphabet {
                let mut password = pb.password_prefix.to_vec();
                password.push(last_char);
                passwords.push(password);
            }
        });
        assert_eq!(passwords, expected_passwords);
    }

    #[test]
    fn test_initialized_keys() {
        let mut opt = test_opt();
        opt.min_length = 0;
        for_each_password(&opt, |pw: &[u8], initialized_keys: [u32; 3]| {
            let mut keys = [305419896u32, 591751049u32, 878082192u32];
            for &c in pw {
                update_keys(&mut keys, c);
            }
            assert_eq!(initialized_keys, keys);
        });
    }
}

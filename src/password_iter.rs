use crate::decrypt::*;
use crate::info::*;
use crate::opt::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub type Password = [u8];
pub type InitializedKeys = [u32; 3];

/// Iterative password enumeration
pub fn for_each_password(opt: Opt, idx: u8, mut callback: impl FnMut(&Password, InitializedKeys)) {
    let alphabet = &opt.alphabet.0;

    let mut password = if let Some(pw) = opt.start_password.clone() {
        pw.into_bytes()
    } else {
        vec![alphabet[0]; opt.min_length.into()]
    };

    // Password represented as indices into the alphabet. It's easier to find the next password
    // using this representation.
    let mut password_idx: Vec<_> = password
        .iter()
        .map(|byte| {
            alphabet
                .iter()
                .position(|letter| letter == byte)
                .expect("Password not in alphabet")
        })
        .collect();

    // Redoing the initialization of keys for passwords that differ only in the last few characters
    // is redundant. Instead, cache the initialized keys up to character i and use that to compute
    // the keys after character i. This makes the key testing effort independent of key length.
    // initialized_keys[i] contains the keys after i characters.
    // Therefore, initialized_keys is 1 longer than password.
    let mut initialized_keys = vec![[305419896u32, 591751049u32, 878082192u32]];

    // TODO: Maybe this could be done more neatly with a struct that groups
    // password_idx, password, and initialized_keys
    while initialized_keys.len() <= password.len() {
        let i = initialized_keys.len();
        initialized_keys.push(initialized_keys[i - 1]);
        update_keys(&mut initialized_keys[i], password[i - 1]);
    }

    let add_offset = |password_idx: &mut Vec<usize>,
                      password: &mut Vec<u8>,
                      initialized_keys: &mut Vec<[u32; 3]>,
                      offset: u8|
     -> bool {
        let mut cursor = password.len();
        let mut carry = usize::from(offset);
        while carry != 0 {
            if cursor == 0 {
                if password.len() == usize::from(opt.max_length) {
                    // We're done.
                    return true;
                }
                password_idx.insert(0, 0);
                // The value will never be read, what matters is that a new element is prepended
                password.insert(0, 0);
                carry -= 1;
            } else {
                cursor -= 1;
                // The initialized keys at the cursor are invalidated.
                initialized_keys.pop();
            }
            let idx = password_idx[cursor] + carry;
            carry = idx / alphabet.len();
            password_idx[cursor] = idx % alphabet.len();
            password[cursor] = alphabet[password_idx[cursor]];
        }
        false
    };

    // To split work between threads, each thread will only generate passwords with step size
    // opt.num_threads and with offset idx from the origin,
    add_offset(&mut password_idx, &mut password, &mut initialized_keys, idx);

    loop {
        while initialized_keys.len() <= password.len() {
            let i = initialized_keys.len();
            initialized_keys.push(initialized_keys[i - 1]);
            update_keys(&mut initialized_keys[i], password[i - 1]);
        }
        callback(&password, initialized_keys[password.len()]);
        let finished = add_offset(
            &mut password_idx,
            &mut password,
            &mut initialized_keys,
            opt.num_threads,
        );
        if finished {
            break;
        }
    }
}

/// Iterative password enumeration with the last character unrolled
///
/// Note: This will not check the empty password
pub fn for_each_password_unrolled(mut opt: Opt, idx: u8, mut callback: impl FnMut(PasswordBlock)) {
    if let Some(pw) = &mut opt.start_password {
        pw.pop();
    }
    opt.min_length = opt.min_length.saturating_sub(1);
    opt.max_length = opt.max_length.saturating_sub(1);
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
    for_each_password(opt, idx, callback_for_single_password);
}

/// Given a password validation function, tests each password
pub fn test_each_password(
    opt: Opt,
    info_data: Arc<InfoData>,
    idx: u8,
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
    for_each_password(opt, idx, callback_with_info);
}

/// Given a password block validation function, tests each password
pub fn test_each_password_unrolled(
    opt: Opt,
    info_data: Arc<InfoData>,
    idx: u8,
    mut block_predicate: impl FnMut(PasswordBlock) -> Vec<Vec<u8>>,
) {
    let block_counter = AtomicU64::new(0);
    let password_block_size = u64::try_from(opt.alphabet.0.len()).unwrap();
    let callback_with_info = move |password_block: PasswordBlock| {
        info_data
            .counter
            .fetch_add(password_block_size, Ordering::Relaxed);
        let block_counter_cur = block_counter.fetch_add(1, Ordering::Relaxed);

        // Once in a while, tell the info thread a recent password
        if block_counter_cur == 100_000 {
            let mut recent_password = info_data.recent_password.lock().unwrap();
            let last_password_prefix = password_block.password_prefix.to_vec();
            *recent_password =
                String::from_utf8(last_password_prefix).expect("Password is not valid UTF-8");
            recent_password.push('-');
            block_counter.store(0, Ordering::Relaxed);
        }

        for pw in block_predicate(password_block) {
            let s = String::from_utf8(pw).expect("Password is not valid UTF-8");
            let mut found_passwords = info_data.found_passwords.lock().unwrap();
            found_passwords.push(s);
        }
    };
    for_each_password_unrolled(opt, idx, callback_with_info);
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_opt() -> Opt {
        Opt {
            alphabet: Alphabet(b"abc".to_vec()),
            input: std::path::PathBuf::new(),
            logfile: std::path::PathBuf::new(),
            max_length: 3,
            min_length: 1,
            num_threads: 1,
            show_zipfile_records: false,
            start_password: None,
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
        for_each_password(opt.clone(), 0, |pw: &[u8], _: InitializedKeys| {
            passwords.push(pw.to_vec())
        });
        assert_eq!(passwords, expected_passwords);

        passwords = vec![];
        for_each_password_unrolled(opt.clone(), 0, |pb: PasswordBlock| {
            for last_char_chunk in pb.alphabet {
                for &last_char in last_char_chunk {
                    let mut password = pb.password_prefix.to_vec();
                    password.push(last_char);
                    // Filter out duplicates from padding
                    if passwords.last() != Some(&password) {
                        passwords.push(password);
                    }
                }
            }
        });
        assert_eq!(passwords, expected_passwords);

        // Test sharded version
        passwords = vec![];
        let mut opt_multithreaded = opt.clone();
        opt_multithreaded.num_threads = 2;
        for_each_password(
            opt_multithreaded.clone(),
            0,
            |pw: &[u8], _: InitializedKeys| passwords.push(dbg!(pw.to_vec())),
        );
        for_each_password(
            opt_multithreaded.clone(),
            1,
            |pw: &[u8], _: InitializedKeys| passwords.push(pw.to_vec()),
        );
        // Sort by length first, then alphabetically
        passwords.sort_by(|pw1, pw2| pw1.len().cmp(&pw2.len()).then(pw1.cmp(pw2)));
        assert_eq!(passwords, expected_passwords);

        // Test very sharded version
        passwords = vec![];
        opt_multithreaded.num_threads = 12;
        for idx in 0..12 {
            for_each_password(
                opt_multithreaded.clone(),
                idx,
                |pw: &[u8], _: InitializedKeys| passwords.push(dbg!(pw.to_vec())),
            );
        }
        // Sort by length first, then alphabetically
        passwords.sort_by(|pw1, pw2| pw1.len().cmp(&pw2.len()).then(pw1.cmp(pw2)));
        assert_eq!(passwords, expected_passwords);
    }

    #[test]
    fn test_initialized_keys() {
        let mut opt = test_opt();
        opt.min_length = 0;
        for_each_password(opt, 0, |pw: &[u8], initialized_keys: [u32; 3]| {
            let mut keys = [305419896u32, 591751049u32, 878082192u32];
            for &c in pw {
                update_keys(&mut keys, c);
            }
            assert_eq!(initialized_keys, keys);
        });
    }
}

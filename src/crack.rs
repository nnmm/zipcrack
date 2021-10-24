use crate::decrypt::{
    encryption_data_matches, password_matches_unrolled, PasswordBlock,
    EncryptionData, RESULT_CAPACITY,
};
use crate::info::{run_with_info_thread, InfoData};
use crate::opt::Opt;
use crate::password_iter::{test_each_password, test_each_password_unrolled};
use crate::zipfile::Record;

use arrayvec::ArrayVec;

pub fn get_encryption_data(zipfile: &[Record]) -> Vec<EncryptionData> {
    zipfile
        .iter()
        .filter_map(|record| {
            let local_file = record.get_local_file()?;
            let encryption_header = local_file.encryption_header?.bytes;
            Some(EncryptionData {
                encryption_header,
                last_mod_file_time: local_file.local_file_header.last_mod_file_time,
            })
        })
        .collect()
}

pub fn crack(opt: Opt, zipfile: &[Record]) {
    let eds = get_encryption_data(zipfile);
    let callback = move |initialized_keys: [u32; 3]| -> bool {
        for &ed in &eds {
            if !encryption_data_matches(ed, initialized_keys) {
                return false;
            }
        }
        true
    };

    run_with_info_thread(&opt, move |opt: &Opt, info_data: &InfoData| {
        test_each_password(opt, info_data, callback);
    });
}

pub fn crack_unrolled(opt: Opt, zipfile: &[Record]) {
    let eds = get_encryption_data(zipfile);
    let mut matching_chars = ArrayVec::<u8, RESULT_CAPACITY>::new();
    let callback = move |password_block: PasswordBlock| -> Vec<Vec<u8>> {
        let mut iter = eds.iter();
        if let Some(ed) = iter.next() {
            password_matches_unrolled(password_block, *ed, &mut matching_chars);
        };
        if matching_chars.is_empty() {
            return Vec::new();
        };

        // Ok, the password passed the first file – check against the other files
        let mut matching_chars_other = ArrayVec::<u8, RESULT_CAPACITY>::new();
        for ed in iter {
            password_matches_unrolled(password_block, *ed, &mut matching_chars_other);
            // Intersection of two
            matching_chars.retain(|ch| matching_chars_other.contains(ch));
            matching_chars_other.clear();
            if matching_chars.is_empty() {
                return Vec::new();
            }
        }

        let new_passwords = matching_chars
            .iter()
            .copied()
            .map(|ch| {
                let mut new_password = password_block.password_prefix.to_vec();
                new_password.push(ch);
                new_password
            })
            .collect();
        matching_chars.clear();
        new_passwords
    };

    run_with_info_thread(&opt, move |opt: &Opt, info_data: &InfoData| {
        test_each_password_unrolled(opt, info_data, callback);
    });
}

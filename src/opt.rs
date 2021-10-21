use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Clone, StructOpt)]
#[structopt(
    name = "zipcrack",
    about = "Attempts to crack a ZIP archive's password with brute force. It is assumed that all files have the same password. There may be false positives if the number of files in the archive is very small."
)]
pub struct Opt {
    /// Input ZIP file. Should contain several files to eliminate false positives.
    #[structopt(parse(from_os_str))]
    pub input: PathBuf,

    /// Prints out the records inside the ZIP file
    #[structopt(long)]
    pub show_zipfile_records: bool,

    /// The minimum password length
    #[structopt(long, default_value = "1")]
    pub min_length: u8,

    /// The maximum password length
    #[structopt(long, default_value = "10")]
    pub max_length: u8,

    /// Do not start at the alphabetically lowest password, but from this string.
    #[structopt(long)]
    pub start_password: Option<String>,

    /// The alphabet to build passwords from. Can be "base64" or "custom:<letters>".
    #[structopt(short, long)]
    pub alphabet: Alphabet,

    /// Uses the unrolled version of the algorithm
    #[structopt(long)]
    pub unroll: bool,
}

#[derive(Clone)]
pub struct Alphabet(pub Vec<u8>);

impl std::str::FromStr for Alphabet {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_ascii() {
            return Err("Alphabet contains non-ASCII characters");
        }
        let alphabet = match s {
            "base64" => {
                b"+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".to_vec()
            }
            _ => {
                if let Some(custom) = s.strip_prefix("custom:") {
                    let mut chars = custom.as_bytes().to_vec();
                    if chars.is_empty() {
                        return Err("Custom alphabet cannot be empty");
                    }
                    chars.sort_unstable();
                    chars.dedup();
                    chars
                } else {
                    return Err("Invalid alphabet");
                }
            }
        };
        Ok(Self(alphabet))
    }
}

use nom::branch::alt;
use nom::bytes::complete::{tag, take};
use nom::combinator::map;
use nom::error::context;
use nom::multi::many0;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;
use nom::IResult;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

// Good introduction:
// https://games.greggman.com/game/zip-rant/

// To see info about an archive:
// unzip -Zv plaintext.zip

#[derive(Debug)]
pub struct LocalFileHeader {
    pub version_needed_to_extract: u16,
    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,
    pub last_mod_file_time: u16,
    pub last_mod_file_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name: OsString,
    pub extra_field: Vec<u8>,
}

impl LocalFileHeader {
    pub fn is_encrypted(&self) -> bool {
        self.general_purpose_bit_flag & 1 == 1
    }
}

pub fn parse_local_file_header(input: &[u8]) -> IResult<&[u8], LocalFileHeader> {
    let (input, _) = tag("PK\x03\x04")(input)?;
    let (input, fields) = tuple((
        le_u16, le_u16, le_u16, le_u16, le_u16, le_u32, le_u32, le_u32,
    ))(input)?;
    let (input, file_name_length) = le_u16(input)?;
    let (input, extra_field_length) = le_u16(input)?;
    let (input, file_name) = take(file_name_length)(input)?;
    let (input, extra_field) = take(extra_field_length)(input)?;
    Ok((
        input,
        LocalFileHeader {
            version_needed_to_extract: fields.0,
            general_purpose_bit_flag: fields.1,
            compression_method: fields.2,
            last_mod_file_time: fields.3,
            last_mod_file_date: fields.4,
            crc32: fields.5,
            compressed_size: fields.6,
            uncompressed_size: fields.7,
            file_name: OsStr::from_bytes(file_name).to_owned(),
            extra_field: extra_field.to_vec(),
        },
    ))
}

#[derive(Clone, Copy, Debug)]
pub struct EncryptionHeader {
    pub bytes: [u8; 12],
}

pub fn parse_encryption_header(input: &[u8]) -> IResult<&[u8], EncryptionHeader> {
    let (input, slice) = take(12usize)(input)?;
    Ok((
        input,
        EncryptionHeader {
            bytes: slice.try_into().unwrap(),
        },
    ))
}

#[derive(Debug)]
pub struct DataDescriptor {
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
}

pub fn parse_data_descriptor(input: &[u8]) -> IResult<&[u8], DataDescriptor> {
    let (input, _) = tag("PK\x07\x08")(input)?;
    let (input, fields) = tuple((le_u32, le_u32, le_u32))(input)?;
    Ok((
        input,
        DataDescriptor {
            crc32: fields.0,
            compressed_size: fields.1,
            uncompressed_size: fields.2,
        },
    ))
}

#[derive(Debug)]
pub struct LocalFile {
    pub local_file_header: LocalFileHeader,
    pub encryption_header: Option<EncryptionHeader>,
    pub file_data: Vec<u8>,
    pub data_descriptor: Option<DataDescriptor>,
}

pub fn parse_local_file(input: &[u8]) -> IResult<&[u8], LocalFile> {
    let (input, local_file_header) =
        context("Parsing local file header", parse_local_file_header)(input)?;
    let mut compressed_size = usize::try_from(local_file_header.compressed_size).unwrap();
    let (input, encryption_header) = if local_file_header.is_encrypted() {
        compressed_size -= 12;
        map(parse_encryption_header, Some)(input)?
    } else {
        (input, None)
    };
    let (input, file_data) = take(compressed_size)(input)?;
    let (input, data_descriptor) = if local_file_header.is_encrypted() {
        context("Parsing data descriptor", map(parse_data_descriptor, Some))(input)?
    } else {
        (input, None)
    };
    Ok((
        input,
        LocalFile {
            local_file_header,
            encryption_header,
            file_data: file_data.to_vec(),
            data_descriptor,
        },
    ))
}

#[derive(Debug)]
pub struct CentralDirectoryFileHeader {
    pub version_made_by: u16,
    pub version_needed_to_extract: u16,
    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,
    pub last_mod_file_time: u16,
    pub last_mod_file_date: u16,
    pub crc_32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub disk_number_start: u16,
    pub internal_file_attributes: u16,
    pub external_file_attributes: u32,
    pub relative_offset_of_local_header: u32,
    pub file_name: OsString,
    pub extra_field: Vec<u8>,
    pub file_comment: Vec<u8>,
}

pub fn parse_central_directory_file_header(
    input: &[u8],
) -> IResult<&[u8], CentralDirectoryFileHeader> {
    let (input, _) = tag("PK\x01\x02")(input)?;
    let (input, fields) = tuple((
        le_u16, le_u16, le_u16, le_u16, le_u16, le_u16, le_u32, le_u32, le_u32, le_u16, le_u16,
        le_u16, le_u16, le_u16, le_u32, le_u32,
    ))(input)?;
    let (input, file_name) = take(fields.9)(input)?;
    let (input, extra_field) = take(fields.10)(input)?;
    let (input, file_comment) = take(fields.11)(input)?;
    Ok((
        input,
        CentralDirectoryFileHeader {
            version_made_by: fields.0,
            version_needed_to_extract: fields.1,
            general_purpose_bit_flag: fields.2,
            compression_method: fields.3,
            last_mod_file_time: fields.4,
            last_mod_file_date: fields.5,
            crc_32: fields.6,
            compressed_size: fields.7,
            uncompressed_size: fields.8,
            disk_number_start: fields.12,
            internal_file_attributes: fields.13,
            external_file_attributes: fields.14,
            relative_offset_of_local_header: fields.15,
            file_name: OsStr::from_bytes(file_name).to_owned(),
            extra_field: extra_field.to_vec(),
            file_comment: file_comment.to_vec(),
        },
    ))
}

#[derive(Debug)]
pub struct DigitalSignature {
    signature_data: Vec<u8>,
}

pub fn parse_digital_signature(input: &[u8]) -> IResult<&[u8], DigitalSignature> {
    let (input, _) = tag("PK\x07\x08")(input)?;
    let (input, size) = le_u16(input)?;
    let (input, signature_data) = take(size)(input)?;
    Ok((
        input,
        DigitalSignature {
            signature_data: signature_data.to_vec(),
        },
    ))
}

#[derive(Debug)]
pub struct EndOfCentralDirectoryRecord {
    // number of this disk
    pub disk_num: u16,
    // number of the disk with the start of the central directory
    pub disk_num_start_cd: u16,
    // total number of entries in the central directory on this disk
    pub cd_num_entries_cur_disk: u16,
    // total number of entries in the central directory
    pub cd_num_entries: u16,
    // size of the central directory
    pub cd_size: u32,
    // offset of start of central directory with respect to the starting disk number
    pub cd_offset: u32,
    pub zip_file_comment: Vec<u8>,
}

pub fn parse_end_of_central_directory_record(
    input: &[u8],
) -> IResult<&[u8], EndOfCentralDirectoryRecord> {
    let (input, _) = tag("PK\x05\x06")(input)?;
    let (input, fields) = tuple((le_u16, le_u16, le_u16, le_u16, le_u32, le_u32, le_u16))(input)?;
    let (input, zip_file_comment) = take(fields.6)(input)?;
    Ok((
        input,
        EndOfCentralDirectoryRecord {
            disk_num: fields.0,
            disk_num_start_cd: fields.1,
            cd_num_entries_cur_disk: fields.2,
            cd_num_entries: fields.3,
            cd_size: fields.4,
            cd_offset: fields.5,
            zip_file_comment: zip_file_comment.to_vec(),
        },
    ))
}

#[derive(Debug)]
pub enum Record {
    LocalFile(LocalFile),
    CentralDirectory(CentralDirectoryFileHeader),
    DigitalSignature(DigitalSignature),
    EndOfCentralDirectory(EndOfCentralDirectoryRecord),
}

impl Record {
    // Accessor for the LocalFile variant
    pub fn get_local_file(&self) -> Option<&LocalFile> {
        if let Record::LocalFile(lf) = self {
            Some(lf)
        } else {
            None
        }
    }
}

pub fn parse(input: &[u8]) -> IResult<&[u8], Vec<Record>> {
    let parse_record = alt((
        map(parse_local_file, Record::LocalFile),
        map(
            parse_central_directory_file_header,
            Record::CentralDirectory,
        ),
        map(parse_digital_signature, Record::DigitalSignature),
        map(
            parse_end_of_central_directory_record,
            Record::EndOfCentralDirectory,
        ),
    ));
    let (input, records) = many0(parse_record)(input)?;
    Ok((input, records))
}

// TODO: This is ugly, make a Display impl instead
pub fn show_file(records: &[Record]) {
    for record in records {
        match record {
            Record::LocalFile(local_file) => {
                println!("Header: {:#?}", local_file.local_file_header);
                println!("Encryption header: {:#?}", local_file.encryption_header);
                println!("Data descriptor: {:#?}", local_file.data_descriptor);
            }
            Record::CentralDirectory(central_directory_file_header) => {
                println!("{:#?}", central_directory_file_header);
            }
            Record::DigitalSignature(digital_signature) => {
                println!("{:#?}", digital_signature);
            }
            Record::EndOfCentralDirectory(eocd) => {
                println!("{:#?}", eocd);
            }
        }
    }
    println!("==============================================");
}

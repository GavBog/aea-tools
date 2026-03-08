use anyhow::Result;
use apfs::ApfsVolume;
use asahi_remote_firmware::reader::AeaReader;
use async_zip::tokio::read::seek::ZipFileReader;
use base64::{Engine as _, engine::general_purpose};
use remote_file::HttpFile;
use tokio::{
    fs::OpenOptions,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
};

pub const LFH_SIGNATURE: u32 = 67324752;

#[tokio::main]
async fn main() -> Result<()> {
    // https://theapplewiki.com/wiki/Keys:CheerD_25D125_(MacBookAir10,1)
    let ipsw_key_b64 = "TukDup9yUwZHVHOcOOvnwECsZpwEoslV0+Ykwzle9MA=";
    let ipsw_key = general_purpose::STANDARD
        .decode(ipsw_key_b64)
        .expect("Failed to decode Base64 key");

    let client = reqwest::Client::new();
    let remote_ipsw =
        HttpFile::new(client, "https://updates.cdn-apple.com/2026WinterFCS/fullrestores/047-60229/6D5DBEA5-75A0-4BEF-ACC9-5ACF9B8DF6B7/UniversalMac_26.3_25D125_Restore.ipsw").await?;
    let local_ipsw = tokio::fs::File::open("UniversalMac_26.3_25D125_Restore.ipsw").await?;
    let buffered_reader = BufReader::new(local_ipsw);
    let zip_reader = ZipFileReader::with_tokio(buffered_reader).await?;

    let entries = zip_reader.file().entries();
    let file_to_find = "043-49020-148.dmg.aea";
    let entry = entries
        .iter()
        .find(|entry| entry.filename().as_str().unwrap_or_default() == file_to_find)
        .ok_or_else(|| anyhow::anyhow!("File not found in zip: {}", file_to_find))?;
    let offset = entry.header_offset();

    let mut buffered_reader = zip_reader.into_inner().into_inner();
    buffered_reader
        .seek(tokio::io::SeekFrom::Start(offset))
        .await?;

    let signature = {
        let mut buffer = [0u8; 4];
        buffered_reader.read_exact(&mut buffer).await?;
        u32::from_le_bytes(buffer)
    };

    match signature {
        LFH_SIGNATURE => (),
        actual => anyhow::bail!(
            "Unexpected header signature: {:x}, expected {:x}",
            actual,
            LFH_SIGNATURE
        ),
    };

    let header = LocalFileHeader::from_reader(&mut buffered_reader).await?;
    let trailing_size = (header.file_name_length as u64) + (header.extra_field_length as u64);
    buffered_reader
        .seek(tokio::io::SeekFrom::Current(trailing_size as i64))
        .await?;

    let mut aea_decrypter = AeaReader::new(&ipsw_key, &mut buffered_reader).await?;
    let cluster_count = aea_decrypter.cluster_count().await?;

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open("output.dmg")
        .await?;

    for cluster_index in 0..cluster_count {
        let segments = aea_decrypter
            .get_all_segments_from_cluster(cluster_index)
            .await?;
        file.write_all(&segments.concat()).await?;
    }

    Ok(())
}

pub struct LocalFileHeader {
    pub version: u16,
    pub flags: GeneralPurposeFlag,
    pub compression: u16,
    pub mod_time: u16,
    pub mod_date: u16,
    pub crc: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_length: u16,
    pub extra_field_length: u16,
}

impl LocalFileHeader {
    pub async fn from_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<LocalFileHeader> {
        let mut buffer: [u8; 26] = [0; 26];
        reader.read_exact(&mut buffer).await?;
        Ok(LocalFileHeader::from(buffer))
    }
}

impl From<[u8; 26]> for LocalFileHeader {
    fn from(value: [u8; 26]) -> LocalFileHeader {
        LocalFileHeader {
            version: u16::from_le_bytes(value[0..2].try_into().unwrap()),
            flags: GeneralPurposeFlag::from(u16::from_le_bytes(value[2..4].try_into().unwrap())),
            compression: u16::from_le_bytes(value[4..6].try_into().unwrap()),
            mod_time: u16::from_le_bytes(value[6..8].try_into().unwrap()),
            mod_date: u16::from_le_bytes(value[8..10].try_into().unwrap()),
            crc: u32::from_le_bytes(value[10..14].try_into().unwrap()),
            compressed_size: u32::from_le_bytes(value[14..18].try_into().unwrap()),
            uncompressed_size: u32::from_le_bytes(value[18..22].try_into().unwrap()),
            file_name_length: u16::from_le_bytes(value[22..24].try_into().unwrap()),
            extra_field_length: u16::from_le_bytes(value[24..26].try_into().unwrap()),
        }
    }
}

#[derive(Copy, Clone)]
pub struct GeneralPurposeFlag {
    pub encrypted: bool,
    pub data_descriptor: bool,
    pub filename_unicode: bool,
}

impl From<u16> for GeneralPurposeFlag {
    fn from(value: u16) -> GeneralPurposeFlag {
        let encrypted = !matches!(value & 0x1, 0);
        let data_descriptor = !matches!((value & 0x8) >> 3, 0);
        let filename_unicode = !matches!((value & 0x800) >> 11, 0);

        GeneralPurposeFlag {
            encrypted,
            data_descriptor,
            filename_unicode,
        }
    }
}

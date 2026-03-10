use std::io::{Seek, SeekFrom};

use anyhow::Result;
use apfs::ApfsVolume;
use asahi_remote_firmware::reader::AeaReader;
use base64::{Engine as _, engine::general_purpose};
use http_range_client::UreqHttpReader;
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use zip::ZipArchive;

pub const LFH_SIGNATURE: u32 = 67324752;

#[tokio::main]
async fn main() -> Result<()> {
    // https://theapplewiki.com/wiki/Keys:CheerD_25D125_(MacBookAir10,1)
    let ipsw_key_b64 = "TukDup9yUwZHVHOcOOvnwECsZpwEoslV0+Ykwzle9MA=";
    let ipsw_key = general_purpose::STANDARD
        .decode(ipsw_key_b64)
        .expect("Failed to decode Base64 key");
    let remote_ipsw = UreqHttpReader::new(
        "https://updates.cdn-apple.com/2026WinterFCS/fullrestores/047-60229/6D5DBEA5-75A0-4BEF-ACC9-5ACF9B8DF6B7/UniversalMac_26.3_25D125_Restore.ipsw",
    );
    // let local_ipsw = std::fs::File::open("UniversalMac_26.3_25D125_Restore.ipsw")?;
    let mut zip_reader = ZipArchive::new(remote_ipsw)?;

    let filename = "043-49020-148.dmg.aea";
    let offset = zip_reader
        .by_name(filename)?
        .data_start()
        .ok_or_else(|| anyhow::anyhow!("Failed to get data offset for entry '{}'", filename))?;

    let mut reader = zip_reader.into_inner();
    reader.seek(SeekFrom::Start(offset))?;

    let mut aea_decrypter = AeaReader::new(&ipsw_key, &mut reader)?;
    let cluster_count = aea_decrypter.cluster_count()?;

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open("output.dmg")
        .await?;

    for cluster_index in 0..cluster_count {
        let segments = aea_decrypter.get_all_segments_from_cluster(cluster_index)?;
        file.write_all(&segments.concat()).await?;
    }

    Ok(())
}

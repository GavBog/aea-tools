use std::io::{Seek, SeekFrom};

use anyhow::Result;
use apfs::ApfsVolume;
use asahi_remote_firmware::{reader::AeaReader, stream::AeaStream};
use base64::{Engine as _, engine::general_purpose};
use http_range_client::UreqHttpReader;
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

    let aea_decrypter = AeaReader::new(&ipsw_key, &mut reader)?;
    let aea_stream = AeaStream::new(aea_decrypter)?;

    let mut vol = ApfsVolume::open(aea_stream)?;
    let info = vol.volume_info();
    println!(
        "{}: {} files, {} dirs",
        info.name, info.num_files, info.num_directories
    );

    let directories = vol.list_directory("/")?;
    println!("Root directory entries:");
    for entry in directories {
        println!(" - {}", entry.name);
    }

    let path = "usr/share/firmware/wifi/C-4378__s-B3/kyushu.trx";
    let stat = vol.stat(path)?;
    println!("{}: size {} bytes", path, stat.size);

    // let mut file = File::create("output.dmg")?;
    // for i in 0..aea_decrypter.cluster_count()? {
    //     let segment_data = aea_decrypter.get_all_segments_from_cluster(i)?.concat();
    //     file.write_all(&segment_data)?;
    // }

    Ok(())
}

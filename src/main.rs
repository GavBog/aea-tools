use anyhow::Result;
use asahi_remote_firmware::{reader::AeaReader, stream::AeaStream};
use base64::{Engine as _, engine::general_purpose};
use exhume_apfs::APFS;
use http_range_client::UreqHttpReader;
use std::{
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
};
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

    let mut apfs = APFS::new(aea_stream).unwrap();

    if let Some(vol) = apfs.volumes.first().cloned() {
        let fstree = apfs.open_fstree_for_volume(&vol).unwrap();

        let mut stack = vec![
            (
                "usr/share/firmware/wifi".to_string(),
                PathBuf::from("extracted_wifi"),
            ),
            (
                "usr/share/firmware/bluetooth".to_string(),
                PathBuf::from("extracted_bluetooth"),
            ),
        ];

        while let Some((remote_path, local_path)) = stack.pop() {
            let dir_node = match fstree.resolve_path(&mut apfs, &remote_path) {
                Ok(node) => node,
                Err(_) => continue,
            };

            if let Ok(children) = fstree.dir_children(&mut apfs, dir_node.inode_id) {
                let _ = std::fs::create_dir_all(&local_path);

                for child in children {
                    let child_remote_path = format!("{}/{}", remote_path, child.name);
                    let child_local_path = local_path.join(&child.name);

                    match child.flags {
                        // Directory
                        4 => {
                            println!("Found dir: {}", child_remote_path);
                            stack.push((child_remote_path, child_local_path));
                        }
                        // File
                        8 => {
                            if let Ok(data) =
                                fstree.read_file_by_path(&mut apfs, &child_remote_path)
                            {
                                println!("Extracting {} ({} bytes)", child_remote_path, data.len());
                                if let Ok(mut f) = File::create(&child_local_path) {
                                    let _ = f.write_all(&data);
                                }
                            }
                        }
                        _ => {} // Ignore symlinks (10) and other types for now
                    }
                }
            }
        }
    };

    // let mut file = File::create("output.dmg")?;
    // for i in 0..aea_decrypter.cluster_count()? {
    //     let segment_data = aea_decrypter.get_all_segments_from_cluster(i)?.concat();
    //     file.write_all(&segment_data)?;
    // }

    Ok(())
}

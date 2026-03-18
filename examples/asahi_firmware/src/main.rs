use aea_tools::{reader::AeaReader, stream::AeaStream};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use exhume_apfs::APFS;
use http_range_client::UreqHttpReader;
use std::{
    env,
    fs::{self, File},
    io::{self, Seek, SeekFrom, Write},
    os,
    path::PathBuf,
};
use zip::ZipArchive;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let out_dir = args
        .get(1)
        .ok_or_else(|| anyhow!("Usage: asahi_firmware <output_directory>"))?;
    let base_path = PathBuf::from(out_dir);
    fs::create_dir_all(&base_path)?;

    // https://theapplewiki.com/wiki/Keys:CheerD_25D125_(MacBookAir10,1)
    let ipsw_key_b64 = "TukDup9yUwZHVHOcOOvnwECsZpwEoslV0+Ykwzle9MA=";
    let ipsw_key = general_purpose::STANDARD
        .decode(ipsw_key_b64)
        .expect("Failed to decode Base64 key");

    let remote_ipsw = UreqHttpReader::new(
        "https://updates.cdn-apple.com/2026WinterFCS/fullrestores/047-60229/6D5DBEA5-75A0-4BEF-ACC9-5ACF9B8DF6B7/UniversalMac_26.3_25D125_Restore.ipsw",
    );
    let mut zip_reader = ZipArchive::new(remote_ipsw)?;

    {
        let mut file = zip_reader.by_path("Firmware/J313_InputDevice.im4p")?;
        let local_path = base_path.join("fud_firmware/Firmware/J313_InputDevice.im4p");
        fs::create_dir_all(local_path.parent().unwrap())?;
        io::copy(&mut file, &mut File::create(local_path)?)?;

        let symlink_path = base_path.join("fud_firmware/j313/InputDevice.im4p");
        fs::create_dir_all(symlink_path.parent().unwrap())?;
        os::unix::fs::symlink("../Firmware/J313_InputDevice.im4p", &symlink_path)?;
        println!(
            "Created symlink: {:?} -> ../Firmware/J313_InputDevice.im4p",
            symlink_path
        );
    }

    let filename = "043-49020-148.dmg.aea";
    let offset = zip_reader
        .by_name(filename)?
        .data_start()
        .ok_or_else(|| anyhow!("Failed to get data offset for entry '{}'", filename))?;

    let mut reader = zip_reader.into_inner();
    reader.seek(SeekFrom::Start(offset))?;

    let aea_decrypter = AeaReader::new(&ipsw_key, &mut reader)?;
    let aea_stream = AeaStream::new(aea_decrypter)?;

    let mut apfs = APFS::new(aea_stream).map_err(|e| anyhow!("APFS Init Error: {:?}", e))?;

    if let Some(vol) = apfs.volumes.first().cloned() {
        let fstree = apfs
            .open_fstree_for_volume(&vol)
            .map_err(|e| anyhow!("FSTree Error: {:?}", e))?;

        let mut directories = vec![
            (
                "usr/share/firmware/wifi".to_string(),
                base_path.join("firmware/wifi"),
            ),
            (
                "usr/share/firmware/bluetooth".to_string(),
                base_path.join("firmware/bluetooth"),
            ),
        ];

        while let Some((remote_path, local_path)) = directories.pop() {
            let dir_node = match fstree.resolve_path(&mut apfs, &remote_path) {
                Ok(node) => node,
                Err(_) => continue,
            };

            if let Ok(children) = fstree.dir_children(&mut apfs, dir_node.inode_id) {
                let _ = fs::create_dir_all(&local_path);

                for child in children {
                    let child_remote_path = format!("{}/{}", remote_path, child.name);
                    let child_local_path = local_path.join(&child.name);

                    match child.flags {
                        // Directory
                        4 => {
                            println!("Found dir: {}", child_remote_path);
                            directories.push((child_remote_path, child_local_path));
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
                        _ => {}
                    }
                }
            }
        }

        if let Ok(data) = fstree.read_file_by_path(&mut apfs, "usr/libexec/appleh13camerad") {
            let _ = File::create(base_path.join("appleh13camerad"))
                .and_then(|mut f| f.write_all(&data));
        }
    };

    Ok(())
}

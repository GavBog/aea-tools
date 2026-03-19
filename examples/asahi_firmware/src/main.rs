use aea_tools::{reader::AeaReader, stream::AeaStream};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose};
use exhume_apfs::APFS;
use flate2::{Compression, write::GzEncoder};
use http_range_client::UreqHttpReader;
use std::{
    env,
    fs::{self, File},
    io::{self, BufWriter, Seek, SeekFrom},
    path::PathBuf,
};
use tar::Header;
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
    let ipsw_key = general_purpose::STANDARD.decode(ipsw_key_b64)?;

    let remote_ipsw = UreqHttpReader::new(
        "https://updates.cdn-apple.com/2026WinterFCS/fullrestores/047-60229/6D5DBEA5-75A0-4BEF-ACC9-5ACF9B8DF6B7/UniversalMac_26.3_25D125_Restore.ipsw",
    );
    let mut zip_reader = ZipArchive::new(remote_ipsw)?;

    let archive_file = File::create(base_path.join("all_firmware.tar.gz"))?;
    let enc = GzEncoder::new(BufWriter::new(archive_file), Compression::default());
    let mut archive = tar::Builder::new(enc);

    println!("Extracting Firmware/J313_InputDevice.im4p");
    let mut file_entry = zip_reader.by_path("Firmware/J313_InputDevice.im4p")?;
    let mut header = Header::new_gnu();
    header.set_size(file_entry.size());
    header.set_mode(0o644);
    archive.append_data(
        &mut header,
        "fud_firmware/Firmware/J313_InputDevice.im4p",
        &mut file_entry,
    )?;
    drop(file_entry);
    println!("Extracted Firmware/J313_InputDevice.im4p");

    let mut link_header = Header::new_gnu();
    link_header.set_entry_type(tar::EntryType::Symlink);
    archive.append_link(
        &mut link_header,
        "fud_firmware/j313/InputDevice.im4p",
        "../Firmware/J313_InputDevice.im4p",
    )?;
    println!(
        "Symlinked fud_firmware/j313/InputDevice.im4p to fud_firmware/Firmware/J313_InputDevice.im4p"
    );

    println!("Extracting kernelcache.release.mac13g (This may take a while)");
    let mut kcache = zip_reader.by_path("kernelcache.release.mac13g")?;
    let mut kcache_file = File::create(base_path.join("kernelcache.release.mac13g"))?;
    io::copy(&mut kcache, &mut kcache_file)?;
    drop(kcache);
    println!("Extracted kernelcache.release.mac13g");

    let filename = "043-49020-148.dmg.aea";
    let offset = zip_reader
        .by_name(filename)?
        .data_start()
        .ok_or_else(|| anyhow!("Failed to get data offset for {}", filename))?;
    let mut reader = zip_reader.into_inner();
    reader.seek(SeekFrom::Start(offset))?;

    let aea_decrypter = AeaReader::new(&ipsw_key, &mut reader)?;
    let aea_stream = AeaStream::new(aea_decrypter)?;
    let mut apfs = APFS::new(aea_stream).map_err(|e| anyhow!("APFS Error: {:?}", e))?;

    if let Some(vol) = apfs.volumes.first().cloned() {
        let fstree = apfs
            .open_fstree_for_volume(&vol)
            .map_err(|e| anyhow!("{:?}", e))?;
        let mut directories = vec![
            (
                "usr/share/firmware/wifi".to_string(),
                "firmware/wifi".to_string(),
            ),
            (
                "usr/share/firmware/bluetooth".to_string(),
                "firmware/bluetooth".to_string(),
            ),
        ];

        while let Some((remote_path, archive_inner_path)) = directories.pop() {
            if let Ok(dir_node) = fstree.resolve_path(&mut apfs, &remote_path)
                && let Ok(children) = fstree.dir_children(&mut apfs, dir_node.inode_id)
            {
                for child in children {
                    let child_remote = format!("{}/{}", remote_path, child.name);
                    let child_archive = format!("{}/{}", archive_inner_path, child.name);

                    match child.flags {
                        4 => directories.push((child_remote, child_archive)), // Directory
                        8 => {
                            // File
                            if let Ok(data) = fstree.read_file_by_path(&mut apfs, &child_remote) {
                                let mut h = Header::new_gnu();
                                h.set_size(data.len() as u64);
                                h.set_mode(0o644);
                                archive.append_data(&mut h, &child_archive, &data[..])?;
                                println!("Extracted {}", child_archive);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if let Ok(data) = fstree.read_file_by_path(&mut apfs, "usr/libexec/appleh13camerad") {
            let mut h = Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            archive.append_data(&mut h, "appleh13camerad", &data[..])?;
        }
    };

    archive.finish()?;
    println!("Success: all_firmware.tar.gz created.");

    Ok(())
}

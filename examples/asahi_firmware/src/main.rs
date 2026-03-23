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

    // https://theapplewiki.com/wiki/Keys:CheerDHW_25D2128_(MacBookAir10,1)
    let ipsw_key_b64 = "iL4eEnCN6zBWad03PvIqMnicyKaaAAEQhw95GYAHA5Q=";
    let ipsw_key = general_purpose::STANDARD.decode(ipsw_key_b64)?;

    let remote_ipsw = UreqHttpReader::new(
        "https://updates.cdn-apple.com/2026WinterFCS/fullrestores/047-88313/2E098049-1731-4415-A206-546D09301973/UniversalMac_26.3.1_25D2128_Restore.ipsw",
    );
    let mut zip_reader = ZipArchive::new(remote_ipsw)?;

    let archive_file = File::create(base_path.join("all_firmware.tar.gz"))?;
    let enc = GzEncoder::new(BufWriter::new(archive_file), Compression::default());
    let mut archive = tar::Builder::new(enc);

    println!("Creating base directory structures...");
    append_dir(&mut archive, "fud_firmware")?;
    append_dir(&mut archive, "fud_firmware/Firmware")?;
    append_dir(&mut archive, "fud_firmware/j313")?;

    append_dir(&mut archive, "firmware")?;
    append_dir(&mut archive, "firmware/wifi")?;
    append_dir(&mut archive, "firmware/bluetooth")?;

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

    let filename = "094-33869-053.dmg.aea";
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
                    if child.name.starts_with('.') {
                        continue;
                    }

                    if is_incompatible_wifi_item(&archive_inner_path, &child.name) {
                        println!(
                            "Dropping incompatible item '{}/{}'",
                            archive_inner_path, child.name
                        );
                        continue;
                    }

                    let child_remote = format!("{}/{}", remote_path, child.name);
                    let child_archive = format!("{}/{}", archive_inner_path, child.name);

                    match child.flags {
                        4 => {
                            // Directory
                            directories.push((child_remote, child_archive.clone()));
                            append_dir(&mut archive, &child_archive)?;
                        }
                        8 => {
                            // File
                            if let Ok(mut data) = fstree.read_file_by_path(&mut apfs, &child_remote)
                            {
                                if child_archive.starts_with("firmware/wifi/")
                                    && child_archive.ends_with(".txt")
                                    && let Ok(text) = std::str::from_utf8(&data)
                                {
                                    let cleaned: String = text
                                        .lines()
                                        .filter(|l| {
                                            l.contains('=')
                                                || l.trim().is_empty()
                                                || l.starts_with('#')
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                        + "\n";
                                    data = cleaned.into_bytes();
                                }
                                let mut h = Header::new_gnu();
                                h.set_size(data.len() as u64);
                                h.set_mode(0o644);
                                archive.append_data(&mut h, &child_archive, &data[..])?;
                                println!("Extracted: {}", child_archive);
                            }
                        }
                        10 => {
                            // Symlink
                            if let Some(id) = child.inode_id
                                && let Ok(Some(target)) = fstree.symlink_target(&mut apfs, id)
                            {
                                let mut h = Header::new_gnu();
                                h.set_entry_type(tar::EntryType::Symlink);
                                archive.append_link(&mut h, &child_archive, &target)?;
                                println!("Symlink: {} -> {}", child_archive, target);
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

// Firewall to stop asahi_firmware from panicking
fn is_incompatible_wifi_item(archive_inner_path: &str, name: &str) -> bool {
    if !archive_inner_path.starts_with("firmware/wifi") {
        return false;
    }

    let is_parsed = name.ends_with(".trx")
        || name.ends_with(".txt")
        || name.ends_with(".clmb")
        || name.ends_with(".txcb")
        || name.ends_with(".sig");

    if !is_parsed {
        return false;
    }

    let valid_dims = ["C", "s", "P", "M", "V", "m", "A"];

    let sim_name = if !name.ends_with(".txt") {
        format!("P-{}", name)
    } else {
        name.to_string()
    };

    let subpath = archive_inner_path
        .strip_prefix("firmware/wifi")
        .unwrap_or("")
        .trim_start_matches('/');

    let full_idpath = if subpath.is_empty() {
        sim_name
    } else {
        format!("{}/{}", subpath, sim_name)
    };

    let idpath = match full_idpath.rsplit_once('.') {
        Some((n, _)) => n,
        None => &full_idpath,
    }
    .replace('/', "_");

    let mut keys = Vec::new();

    for part in idpath.split('_') {
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('-') {
            if k == "P" && v.contains('-') {
                keys.push("P");
                keys.push("A");
            } else {
                keys.push(k);
            }
        } else {
            return true;
        }
    }

    for k in keys {
        if !valid_dims.contains(&k) {
            return true;
        }
    }

    false
}

fn append_dir<W: std::io::Write>(archive: &mut tar::Builder<W>, path: &str) -> Result<()> {
    let mut h = Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_mode(0o755);
    archive.append_data(
        &mut h,
        format!("{}/", path.trim_end_matches('/')),
        std::io::empty(),
    )?;
    Ok(())
}

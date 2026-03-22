use crate::{
    cluster_header::ClusterHeader,
    crypto::{
        aes_aead_decrypt, derive_cluster_header_encryption_key, derive_cluster_key,
        derive_main_key, derive_segment_key,
    },
    dictionary::AeaDictionary,
    prologue::AeaPrologue,
    root_header::RootHeader,
};
use anyhow::Result;
use lzfse_rust::LzfseRingDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{Read, Seek},
};

pub struct AeaReader<S>
where
    S: Read + Seek + Unpin,
{
    stream: S,
    start_pos: u64,
    dictionary: AeaDictionary,
    runtime_data: RuntimeData,
}

impl<S> AeaReader<S>
where
    S: Read + Seek + Unpin,
{
    pub fn new(external_key: &[u8], mut stream: S) -> Result<Self> {
        let start_pos = stream.stream_position()?;

        Ok(Self {
            stream,
            start_pos,
            dictionary: AeaDictionary::default(),
            runtime_data: RuntimeData::new(external_key),
        })
    }

    fn ensure_prologue_loaded(&mut self) -> Result<()> {
        if self.runtime_data.prologue.is_some() {
            return Ok(());
        }
        self.stream.seek(std::io::SeekFrom::Start(self.start_pos))?;
        let prologue = AeaPrologue::decode(&mut self.stream)?;
        self.dictionary.prologue_range = Some((self.start_pos, prologue.length() as u64));
        self.runtime_data.prologue = Some(prologue);
        Ok(())
    }

    fn prologue(&self) -> Result<&AeaPrologue> {
        self.runtime_data
            .prologue
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Prologue not loaded"))
    }

    fn prologue_mut(&mut self) -> Result<&mut AeaPrologue> {
        self.runtime_data
            .prologue
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Prologue not loaded"))
    }

    pub fn get_prologue(&mut self) -> Result<&AeaPrologue> {
        self.ensure_prologue_loaded()?;
        self.prologue()
    }

    pub fn get_main_key(&mut self) -> Result<[u8; 32]> {
        if let Some(amk) = self.runtime_data.amk {
            return Ok(amk);
        }

        self.ensure_prologue_loaded()?;
        let prologue = self.prologue()?;
        let amk = derive_main_key(
            &prologue.salt,
            &self.runtime_data.external_key,
            &prologue.profile_id,
        )?;

        self.runtime_data.amk = Some(amk);
        Ok(amk)
    }

    pub fn get_root_header(&mut self) -> Result<&RootHeader> {
        let amk = self.get_main_key()?;
        self.ensure_prologue_loaded()?;
        let prologue = self.prologue_mut()?;
        let root_header = prologue.get_decrypted_root_header(&amk)?;

        Ok(root_header)
    }

    fn ensure_cluster_header_loaded(&mut self, cluster_index: u32) -> Result<()> {
        if self
            .runtime_data
            .cluster_headers
            .contains_key(&cluster_index)
        {
            return Ok(());
        }

        let segments_per_cluster = self.get_root_header()?.segments_per_cluster;
        if let Some((offset, _length, chek, hmac)) =
            self.dictionary.cluster_map.get(&cluster_index).cloned()
        {
            self.stream.seek(std::io::SeekFrom::Start(offset))?;
            let cluster_header =
                ClusterHeader::decode(&mut self.stream, &chek, &hmac, segments_per_cluster)?;
            self.runtime_data
                .cluster_headers
                .insert(cluster_index, cluster_header);
            return Ok(());
        }

        let amk = self.get_main_key()?;
        let ck = derive_cluster_key(&amk, cluster_index)?;
        self.runtime_data.ck.insert(cluster_index, ck);
        let chek = derive_cluster_header_encryption_key(&ck);

        if cluster_index == 0 {
            self.ensure_prologue_loaded()?;
            let prologue_range = self
                .dictionary
                .prologue_range
                .ok_or_else(|| anyhow::anyhow!("Prologue range not found in dictionary"))?;

            let offset = prologue_range.0 + prologue_range.1;
            self.stream.seek(std::io::SeekFrom::Start(offset))?;

            let first_cluster_hmac = self.prologue()?.first_cluster_hmac;
            let cluster_header = ClusterHeader::decode(
                &mut self.stream,
                &chek,
                &first_cluster_hmac,
                segments_per_cluster,
            )?;

            self.dictionary.cluster_map.insert(
                cluster_index,
                (
                    offset,
                    cluster_header.encoded_len() as u64,
                    chek,
                    first_cluster_hmac,
                ),
            );
            self.runtime_data
                .cluster_headers
                .insert(cluster_index, cluster_header);

            return Ok(());
        }

        let previous_cluster_header = self.get_cluster_header(cluster_index - 1)?;
        let hmac = previous_cluster_header.next_cluster_hmac;

        let segment_info = &previous_cluster_header.segment_info;
        let segment_offset = segment_info
            .iter()
            .map(|info| info.compressed_size as u64)
            .sum::<u64>();
        let header_offset = self
            .dictionary
            .cluster_map
            .get(&(cluster_index - 1))
            .map(|(offset, length, _, _)| *offset + *length)
            .ok_or_else(|| anyhow::anyhow!("Previous cluster header not found in dictionary"))?;

        let offset = header_offset + segment_offset;
        self.stream.seek(std::io::SeekFrom::Start(offset))?;

        let cluster_header =
            ClusterHeader::decode(&mut self.stream, &chek, &hmac, segments_per_cluster)?;
        self.dictionary.cluster_map.insert(
            cluster_index,
            (offset, cluster_header.encoded_len() as u64, chek, hmac),
        );
        self.runtime_data
            .cluster_headers
            .insert(cluster_index, cluster_header);

        Ok(())
    }

    pub fn get_cluster_header(&mut self, cluster_index: u32) -> Result<&ClusterHeader> {
        self.ensure_cluster_header_loaded(cluster_index)?;
        self.runtime_data
            .cluster_headers
            .get(&cluster_index)
            .ok_or_else(|| anyhow::anyhow!("Cluster header not found"))
    }

    pub fn get_segment(&mut self, cluster_index: u32, segment_index: u32) -> Result<Vec<u8>> {
        if let Some((offset, length, key, hmac)) = self
            .dictionary
            .segment_map
            .get(&(cluster_index, segment_index))
            .cloned()
        {
            self.stream.seek(std::io::SeekFrom::Start(offset))?;
            let mut encrypted_segment_data = vec![0u8; length as usize];
            self.stream.read_exact(&mut encrypted_segment_data)?;
            let segment_data = aes_aead_decrypt(&key, &encrypted_segment_data, &[], &hmac)?;

            let decoder = &mut self.runtime_data.lzfse_decoder;
            let decompressed = if segment_data.starts_with(b"bvx2") {
                let mut out = Vec::new();
                decoder.decode_bytes(&segment_data, &mut out)?;
                out
            } else {
                segment_data
            };

            return Ok(decompressed);
        }

        let (segment_offset, segment_info, segment_hmac) = {
            let cluster_header = self.get_cluster_header(cluster_index)?;
            let offset = cluster_header
                .segment_info
                .iter()
                .take(segment_index as usize)
                .map(|info| info.compressed_size as u64)
                .sum::<u64>();
            let segment_info = cluster_header
                .segment_info
                .get(segment_index as usize)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Segment index {} out of bounds for cluster {}",
                        segment_index,
                        cluster_index
                    )
                })?
                .clone();
            let segment_hmac = *cluster_header
                .segment_hmacs
                .get(segment_index as usize)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Segment index {} out of bounds for cluster {}",
                        segment_index,
                        cluster_index
                    )
                })?;

            let segment_offset = self
                .dictionary
                .cluster_map
                .get(&cluster_index)
                .map(|(offset, length, _, _)| *offset + *length)
                .ok_or_else(|| anyhow::anyhow!("Cluster header not found in dictionary"))?
                + offset;

            (segment_offset, segment_info, segment_hmac)
        };

        let ck = self.runtime_data.ck.get(&cluster_index).ok_or_else(|| {
            anyhow::anyhow!("Cluster key not found for cluster {}", cluster_index)
        })?;
        let sk = derive_segment_key(ck, segment_index);

        self.dictionary.segment_map.insert(
            (cluster_index, segment_index),
            (
                segment_offset,
                segment_info.compressed_size as u64,
                sk,
                segment_hmac,
            ),
        );

        self.stream.seek(std::io::SeekFrom::Start(segment_offset))?;
        let mut encrypted_segment_data = vec![0u8; segment_info.compressed_size as usize];
        self.stream.read_exact(&mut encrypted_segment_data)?;
        let segment_data = aes_aead_decrypt(&sk, &encrypted_segment_data, &[], &segment_hmac)?;

        let decoder = &mut self.runtime_data.lzfse_decoder;
        let decompressed = if segment_data.starts_with(b"bvx2") {
            let mut out = Vec::new();
            decoder.decode_bytes(&segment_data, &mut out)?;
            out
        } else {
            segment_data
        };

        let expected_size = segment_info.decompressed_size as usize;
        let actual_size = decompressed.len();
        if expected_size != actual_size {
            return Err(anyhow::anyhow!(
                "Size mismatch: expected {}, got {}",
                expected_size,
                actual_size
            ));
        }
        if actual_size == 0 {
            return Ok(Vec::new());
        }
        let expected_checksum = segment_info.checksum;
        let actual_checksum = Sha256::digest(&decompressed);
        if expected_checksum != actual_checksum.as_slice() {
            return Err(anyhow::anyhow!(
                "Checksum mismatch: expected {:x?}, got {:x?}",
                expected_checksum,
                actual_checksum
            ));
        }

        Ok(decompressed)
    }

    pub fn cluster_count(&mut self) -> Result<u32> {
        let root_header = self.get_root_header()?;
        let container_size = u64::from_le_bytes(root_header.container_size);
        let segment_size = u32::from_le_bytes(root_header.segment_size) as u64;
        let segments_per_cluster = u32::from_le_bytes(root_header.segments_per_cluster) as u64;
        let cluster_size = segment_size * segments_per_cluster;
        let cluster_count = container_size.div_ceil(cluster_size) as u32;

        Ok(cluster_count)
    }

    fn ensure_all_cluster_headers_loaded(&mut self) -> Result<()> {
        let cluster_count = self.cluster_count()?;
        for cluster_index in 0..cluster_count {
            self.ensure_cluster_header_loaded(cluster_index)?;
        }

        Ok(())
    }

    pub fn get_all_cluster_headers(&mut self) -> Result<Vec<&ClusterHeader>> {
        self.ensure_all_cluster_headers_loaded()?;
        let cluster_headers = self
            .runtime_data
            .cluster_headers
            .values()
            .collect::<Vec<_>>();

        Ok(cluster_headers)
    }

    pub fn get_all_segments_from_cluster(&mut self, cluster_index: u32) -> Result<Vec<Vec<u8>>> {
        let cluster_header = self.get_cluster_header(cluster_index)?;
        let segment_count = cluster_header.segment_info.len() as u32;
        let mut segments = Vec::with_capacity(segment_count as usize);
        for segment_index in 0..segment_count {
            let segment = self.get_segment(cluster_index, segment_index)?;
            segments.push(segment);
        }

        Ok(segments)
    }

    pub fn get_decompressed_length(&mut self) -> Result<u64> {
        let raw_size = self.get_root_header()?.raw_size;
        let total_length = u64::from_le_bytes(raw_size);
        Ok(total_length)
    }
}

struct RuntimeData {
    pub external_key: Vec<u8>,
    pub prologue: Option<AeaPrologue>,
    pub amk: Option<[u8; 32]>,
    pub ck: HashMap<u32, [u8; 32]>,
    pub cluster_headers: HashMap<u32, ClusterHeader>,
    pub lzfse_decoder: LzfseRingDecoder,
}

impl RuntimeData {
    fn new(external_key: &[u8]) -> Self {
        Self {
            external_key: external_key.to_vec(),
            prologue: None,
            amk: None,
            ck: HashMap::new(),
            cluster_headers: HashMap::new(),
            lzfse_decoder: LzfseRingDecoder::default(),
        }
    }
}

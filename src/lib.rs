pub mod cluster_header;
pub mod crypto;
pub mod dictionary;
pub mod prologue;
pub mod root_header;
pub mod segment_info;

use crate::{
    cluster_header::ClusterHeader,
    crypto::{
        aes_aead_decrypt, derive_cluster_header_encryption_key, derive_cluster_key,
        derive_main_key, derive_padding_authentication_key, derive_segment_key, verify_padding,
    },
    prologue::AeaPrologue,
    root_header::RootHeader,
    segment_info::SegmentInfo,
};
use anyhow::Result;
use lzfse_rust::LzfseRingDecoder;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub struct AeaDecrypter<S>
where
    S: AsyncReadExt + Unpin,
{
    stream: S,
    start_pos: u64,
    pub amk: [u8; 32],
    pub prologue: AeaPrologue,
    pub root_header: RootHeader,
    current_cluster_key: Option<[u8; 32]>,
    next_cluster_index: u32,
    next_cluster_hmac: [u8; 32],
    cluster_count: u32,
}

impl<S> AeaDecrypter<S>
where
    S: AsyncReadExt + AsyncSeekExt + Unpin,
{
    pub async fn new(external_key: &[u8], mut stream: S) -> Result<Self> {
        let start_pos = stream.stream_position().await?;
        let prologue = AeaPrologue::decode(&mut stream).await?;
        let amk = derive_main_key(&prologue.salt, external_key, &prologue.profile_id)?;
        let root_header = prologue.decrypt_root_header(&amk).await?;

        println!("compression: {:?}", root_header.compression_algorithm);

        let container_size = u64::from_le_bytes(root_header.container_size);
        let segment_size = u32::from_le_bytes(root_header.segment_size) as u64;
        let segments_per_cluster = u32::from_le_bytes(root_header.segments_per_cluster) as u64;
        let cluster_size = segment_size * segments_per_cluster;
        let cluster_count = container_size.div_ceil(cluster_size) as u32;

        Ok(Self {
            stream,
            start_pos,
            amk,
            root_header,
            next_cluster_index: 0,
            current_cluster_key: None,
            next_cluster_hmac: prologue.first_cluster_hmac,
            prologue,
            cluster_count,
        })
    }

    pub fn is_finished(&self) -> bool {
        self.next_cluster_index >= self.cluster_count
    }

    pub async fn reset(&mut self) -> Result<()> {
        self.stream
            .seek(tokio::io::SeekFrom::Start(self.start_pos))
            .await?;
        self.next_cluster_index = 0;
        self.current_cluster_key = None;
        self.next_cluster_hmac = self.prologue.first_cluster_hmac;
        Ok(())
    }

    pub async fn get_cluster_header(&mut self) -> Result<ClusterHeader> {
        let ck = derive_cluster_key(&self.amk, self.next_cluster_index)?;
        let chek = derive_cluster_header_encryption_key(&ck);

        self.current_cluster_key = Some(ck);
        self.next_cluster_index += 1;

        let cluster_header = ClusterHeader::decode(
            &mut self.stream,
            &chek,
            &self.next_cluster_hmac,
            self.root_header.segments_per_cluster,
        )
        .await?;

        self.next_cluster_hmac = cluster_header.next_cluster_hmac;

        Ok(cluster_header)
    }

    pub async fn get_segments(&mut self, cluster_header: &ClusterHeader) -> Result<Vec<Vec<u8>>> {
        let total_compressed_size: usize = cluster_header
            .segment_info
            .iter()
            .map(|info| info.compressed_size as usize)
            .sum();

        let mut full_cluster_data = vec![0u8; total_compressed_size];
        self.stream.read_exact(&mut full_cluster_data).await?;
        let current_cluster_key = self.current_cluster_key.expect("Key missing");

        let cluster_index = self.next_cluster_index - 1;

        let segments = rayon::scope(move |_| {
            cluster_header
                .segment_info
                .par_iter()
                .enumerate()
                .map(|(i, info)| {
                    if info.compressed_size == 0 {
                        return Ok(vec![]);
                    }

                    let start = cluster_header.segment_info[..i]
                        .iter()
                        .map(|s| s.compressed_size as usize)
                        .sum();
                    println!(
                        "Decrypting segment {} from cluster {}: start={}, size={}",
                        i, cluster_index, start, info.compressed_size
                    );
                    let end = start + info.compressed_size as usize;

                    let segment_hmac = &cluster_header.segment_hmacs[i * 32..(i + 1) * 32];
                    let segment_key = derive_segment_key(&current_cluster_key, i as u32);
                    aes_aead_decrypt(
                        &segment_key,
                        &full_cluster_data[start..end],
                        &[],
                        segment_hmac,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(segments)
    }

    pub async fn decompress_segments(
        &self,
        segments: Vec<Vec<u8>>,
        segment_info: Vec<SegmentInfo>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut decoder = LzfseRingDecoder::default();
        let mut decompressed_segments = Vec::new();
        for (segment, info) in segments.into_iter().zip(segment_info.into_iter()) {
            let decompressed = if segment.starts_with(b"bvx2") {
                let mut out = Vec::new();
                decoder.decode_bytes(&segment, &mut out)?;
                out
            } else {
                segment
            };

            let expected_size = info.decompressed_size as usize;
            let actual_size = decompressed.len();
            if expected_size != actual_size {
                return Err(anyhow::anyhow!(
                    "Size mismatch: expected {}, got {}",
                    expected_size,
                    actual_size
                ));
            }
            if actual_size == 0 {
                decompressed_segments.push(Vec::new());
                continue;
            }
            let expected_checksum = info.checksum;
            let actual_checksum = Sha256::digest(&decompressed);
            if expected_checksum != actual_checksum.as_slice() {
                return Err(anyhow::anyhow!(
                    "Checksum mismatch: expected {:x?}, got {:x?}",
                    expected_checksum,
                    actual_checksum
                ));
            }
            decompressed_segments.push(decompressed);
        }
        Ok(decompressed_segments)
    }

    pub async fn get_all_cluster_headers(&mut self) -> Result<Vec<ClusterHeader>> {
        let mut headers = Vec::new();
        for i in 0..self.cluster_count {
            let header = self.get_cluster_header().await?;
            let compressed_size: usize = header
                .segment_info
                .iter()
                .map(|info| info.compressed_size as usize)
                .sum();
            headers.push(header);

            println!(
                "Cluster {}: compressed size = {}; offset = {}",
                i,
                compressed_size,
                self.stream.stream_position().await? - self.start_pos
            );

            self.stream
                .seek(tokio::io::SeekFrom::Current(compressed_size as i64))
                .await?;
        }
        Ok(headers)
    }

    pub async fn goto_position(&mut self, position: u64) -> Result<()> {
        self.stream
            .seek(tokio::io::SeekFrom::Start(self.start_pos + position))
            .await?;
        Ok(())
    }

    pub async fn get_current_position(&mut self) -> Result<u64> {
        let pos = self.stream.stream_position().await?;
        Ok(pos - self.start_pos)
    }

    pub async fn bytes_left(&mut self) -> Result<u64> {
        let current_pos = self.get_current_position().await?;
        let total_size = u64::from_le_bytes(self.root_header.container_size);
        Ok(total_size - current_pos)
    }
}

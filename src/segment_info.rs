use crate::crypto::aes_aead_decrypt;
use anyhow::Result;

#[derive(Clone)]
pub struct SegmentInfo {
    pub decompressed_size: u32,
    pub compressed_size: u32,
    pub checksum: [u8; 32],
}

impl SegmentInfo {
    pub fn decrypt_segment_info(
        next_cluster_hmac: &[u8; 32],
        segment_hmacs: &[u8],
        encrypted_segment_info: Vec<u8>,
        chek: &[u8; 80],
        expected_hmac: &[u8; 32],
    ) -> Result<Vec<SegmentInfo>> {
        let mut ad = Vec::new();
        ad.extend_from_slice(next_cluster_hmac);
        ad.extend_from_slice(segment_hmacs);

        let segment_info_bytes =
            aes_aead_decrypt(chek, &encrypted_segment_info, &ad, expected_hmac)?;
        let segment_info_chunks = segment_info_bytes.chunks(40);
        let segment_info: Vec<SegmentInfo> = segment_info_chunks
            .map(|chunk| SegmentInfo {
                decompressed_size: u32::from_le_bytes(chunk[0..4].try_into().unwrap()),
                compressed_size: u32::from_le_bytes(chunk[4..8].try_into().unwrap()),
                checksum: chunk[8..40].try_into().unwrap(),
            })
            .collect();
        Ok(segment_info)
    }
}

use crate::segment_info::SegmentInfo;
use anyhow::Result;
use tokio::io::AsyncReadExt;

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Cluster_header
pub struct ClusterHeader {
    // Encrypted: (checksum_length+8)*segments_per_cluster
    // Unencrypted: segment_size*segments_per_cluster
    pub segment_info: Vec<SegmentInfo>,
    pub next_cluster_hmac: [u8; 32],
    // 32*segments_per_cluster
    pub segment_hmacs: Vec<u8>,
}

impl ClusterHeader {
    pub async fn decode<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        chek: &[u8; 80],
        expected_hmac: &[u8; 32],
        segments_per_cluster: [u8; 4],
    ) -> Result<Self> {
        let encrypted_segment_info_size =
            (32 + 8) * u32::from_le_bytes(segments_per_cluster) as usize;
        let segment_hmacs_size = 32 * u32::from_le_bytes(segments_per_cluster) as usize;

        let mut encrypted_segment_info = vec![0u8; encrypted_segment_info_size];
        let mut next_cluster_hmac = [0u8; 32];
        let mut segment_hmacs = vec![0u8; segment_hmacs_size];
        reader.read_exact(&mut encrypted_segment_info).await?;
        reader.read_exact(&mut next_cluster_hmac).await?;
        reader.read_exact(&mut segment_hmacs).await?;

        let segment_info = SegmentInfo::decrypt_segment_info(
            &next_cluster_hmac,
            &segment_hmacs,
            encrypted_segment_info,
            chek,
            expected_hmac,
        )
        .await?;

        Ok(Self {
            segment_info,
            next_cluster_hmac,
            segment_hmacs,
        })
    }
}

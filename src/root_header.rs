use crate::{crypto::aes_aead_decrypt, prologue::AeaPrologue};
use anyhow::Result;
use sha2::Sha256;

pub enum RootHeaderEnum {
    Unencrypted(RootHeader),
    Encrypted([u8; 48]),
}

pub struct RootHeader {
    pub raw_size: [u8; 8],
    pub container_size: [u8; 8],
    pub segment_size: [u8; 4],
    pub segments_per_cluster: [u8; 4],
    pub compression_algorithm: [u8; 1],
    pub checksum_algorithm: [u8; 1],
    // 22 bytes of padding
}

impl RootHeader {
    // https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Decrypting_root_header
    pub async fn decrypt_root_header(
        prologue: &AeaPrologue,
        amk: &[u8; 32],
    ) -> Result<Option<RootHeader>> {
        let root_header_encrypted = match &prologue.root_header {
            RootHeaderEnum::Encrypted(data) => data,
            RootHeaderEnum::Unencrypted(_) => return Ok(None),
        };

        // Derive 80-byte RHEK
        let hk_rhek = hkdf::Hkdf::<Sha256>::new(None, amk);
        let mut rhek = [0u8; 80];
        hk_rhek
            .expand(b"AEA_RHEK", &mut rhek)
            .map_err(|_| anyhow::anyhow!("RHEK expand fail"))?;

        // Decrypt using AEAD logic
        let mut ad = Vec::new();
        ad.extend_from_slice(&prologue.first_cluster_hmac);
        ad.extend_from_slice(&prologue.auth_data);

        let decrypted_header =
            aes_aead_decrypt(&rhek, root_header_encrypted, &ad, &prologue.root_hmac)?;

        let root_header = RootHeader::from_decrypted_data(&decrypted_header);
        Ok(Some(root_header))
    }

    pub fn from_decrypted_data(data: &[u8]) -> Self {
        let mut raw_size = [0u8; 8];
        raw_size.copy_from_slice(&data[0..8]);

        let mut container_size = [0u8; 8];
        container_size.copy_from_slice(&data[8..16]);

        let mut segment_size = [0u8; 4];
        segment_size.copy_from_slice(&data[16..20]);

        let mut segments_per_cluster = [0u8; 4];
        segments_per_cluster.copy_from_slice(&data[20..24]);

        let compression_algorithm = data[24];
        let checksum_algorithm = data[25];

        Self {
            raw_size,
            container_size,
            segment_size,
            segments_per_cluster,
            compression_algorithm: [compression_algorithm],
            checksum_algorithm: [checksum_algorithm],
        }
    }
}

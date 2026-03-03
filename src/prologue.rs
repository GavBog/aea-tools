use anyhow::Result;
use tokio::io::AsyncReadExt;

use crate::root_header::RootHeader;

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Prologue
pub struct AeaPrologue {
    pub magic: [u8; 4],
    pub profile_id: [u8; 3],
    pub scrypt_hardness: [u8; 1],
    pub auth_data_len: [u8; 4],
    pub auth_data: Vec<u8>,
    // 128 bytes on profile 0, 160 bytes on profiles 2/4, missing on 1/3/5 (unsigned)
    pub prologue_signature: Vec<u8>,
    // 32 bytes on profile 0, 65 bytes on profiles 3/4 (ECDHE), missing on 1/2/5
    pub encryption_data: Vec<u8>,
    pub salt: [u8; 32],
    pub root_hmac: [u8; 32],
    pub encrypted_root_header: [u8; 48],
    pub first_cluster_hmac: [u8; 32],
}

impl AeaPrologue {
    pub async fn decode<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        let mut profile_id_bytes = [0u8; 3];
        let mut hardness = [0u8; 1];
        let mut ad_len_bytes = [0u8; 4];
        reader.read_exact(&mut magic).await?;
        reader.read_exact(&mut profile_id_bytes).await?;
        reader.read_exact(&mut hardness).await?;
        reader.read_exact(&mut ad_len_bytes).await?;

        if &magic != b"AEA1" {
            return Err(anyhow::anyhow!(
                "Invalid prologue magic. Expected '{:?}', got '{:?}'",
                b"AEA1",
                magic
            ));
        }

        let profile_id = u32::from_le_bytes([
            profile_id_bytes[0],
            profile_id_bytes[1],
            profile_id_bytes[2],
            0,
        ]);

        let ad_len = u32::from_le_bytes(ad_len_bytes);
        let mut auth_data = vec![0u8; ad_len as usize];
        reader.read_exact(&mut auth_data).await?;

        let sig_len = match profile_id {
            0 => 128,
            2 | 4 => 160,
            _ => 0, // 1, 3, 5 are unsigned
        };

        let mut prologue_signature = vec![0u8; sig_len];
        if sig_len > 0 {
            reader.read_exact(&mut prologue_signature).await?;
        }

        let enc_data_len = match profile_id {
            0 => 32,
            3 | 4 => 65,
            _ => 0, // 1, 2, 5 use external keys or hardware
        };

        let mut encryption_data = vec![0u8; enc_data_len];
        if enc_data_len > 0 {
            reader.read_exact(&mut encryption_data).await?;
        }

        let mut salt = [0u8; 32];
        let mut root_hmac = [0u8; 32];
        let mut root_header = [0u8; 48];
        let mut first_cluster_hmac = [0u8; 32];

        reader.read_exact(&mut salt).await?;
        reader.read_exact(&mut root_hmac).await?;
        reader.read_exact(&mut root_header).await?;
        reader.read_exact(&mut first_cluster_hmac).await?;

        Ok(Self {
            magic,
            profile_id: profile_id_bytes,
            scrypt_hardness: hardness,
            auth_data_len: ad_len_bytes,
            auth_data,
            prologue_signature,
            encryption_data,
            salt,
            root_hmac,
            encrypted_root_header: root_header,
            first_cluster_hmac,
        })
    }

    pub async fn decrypt_root_header(&self, amk: &[u8; 32]) -> Result<RootHeader> {
        RootHeader::decrypt_root_header(self, amk).await
    }
}

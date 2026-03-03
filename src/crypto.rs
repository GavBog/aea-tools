use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#HMAC_AD
fn hmac_ad(key: &[u8], data: &[u8], ad: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC key length error");
    mac.update(ad);
    mac.update(data);
    mac.update(&(ad.len() as u64).to_le_bytes());

    mac.finalize().into_bytes().into()
}

// For padding auth
// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Padding
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC key length error");
    mac.update(data);

    mac.finalize().into_bytes().into()
}

pub fn verify_padding(key: &[u8], ciphertext: &[u8], expected_hmac: &[u8]) -> Result<Vec<u8>> {
    let calculated_hmac = hmac_sha256(key, ciphertext);
    println!("Calculated padding HMAC: {:x?}", calculated_hmac);
    println!("Expected padding HMAC: {:x?}", expected_hmac);
    if calculated_hmac != expected_hmac {
        anyhow::bail!("Integrity check failed: HMAC mismatch");
    }

    Ok(ciphertext.to_vec())
}

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#AES_AEAD
pub fn aes_aead_decrypt(
    key_80b: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
    expected_hmac: &[u8],
) -> Result<Vec<u8>> {
    let hmac_key = &key_80b[0..32];
    let aes_key = &key_80b[32..64];
    let aes_iv = &key_80b[64..80];

    let calculated_hmac = hmac_ad(hmac_key, ciphertext, ad);
    if calculated_hmac != expected_hmac {
        anyhow::bail!("Integrity check failed: HMAC_AD mismatch");
    }

    let mut output = ciphertext.to_vec();
    let mut cipher = ctr::Ctr128BE::<aes::Aes256>::new(aes_key.into(), aes_iv.into());
    cipher.apply_keystream(&mut output);

    Ok(output)
}

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Main_key
pub fn derive_main_key(salt: &[u8], external_key: &[u8], profile_id: &[u8]) -> Result<[u8; 32]> {
    let mut amk_info = b"AEA_AMK".to_vec();
    amk_info.extend_from_slice(profile_id);
    amk_info.push(0);

    let hk_amk = hkdf::Hkdf::<Sha256>::new(Some(salt), external_key);
    let mut amk = [0u8; 32];
    hk_amk
        .expand(&amk_info, &mut amk)
        .map_err(|_| anyhow::anyhow!("AMK expand fail"))?;

    Ok(amk)
}

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Keys
pub fn derive_cluster_key(amk: &[u8; 32], cluster_index: u32) -> anyhow::Result<[u8; 32]> {
    let mut ck_info = b"AEA_CK".to_vec();
    ck_info.extend_from_slice(&cluster_index.to_le_bytes());
    let hk_ck = hkdf::Hkdf::<sha2::Sha256>::new(None, amk);
    let mut ck = [0u8; 32];
    hk_ck
        .expand(&ck_info, &mut ck)
        .map_err(|_| anyhow::anyhow!("CK expand fail"))?;

    Ok(ck)
}

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Keys
pub fn derive_cluster_header_encryption_key(ck: &[u8; 32]) -> [u8; 80] {
    let chek_info = b"AEA_CHEK".to_vec();
    let hk_chek = hkdf::Hkdf::<sha2::Sha256>::new(None, ck);
    let mut chek = [0u8; 80];
    hk_chek
        .expand(&chek_info, &mut chek)
        .expect("CHEK expand fail");

    chek
}

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Segments
pub fn derive_segment_key(ck: &[u8; 32], segment_index: u32) -> [u8; 80] {
    let mut sk_info = b"AEA_SK".to_vec();
    sk_info.extend_from_slice(&segment_index.to_le_bytes());

    let hk_sk = hkdf::Hkdf::<sha2::Sha256>::new(None, ck);
    let mut sk = [0u8; 80];
    hk_sk.expand(&sk_info, &mut sk).expect("SK expand fail");

    sk
}

// https://theapplewiki.com/wiki/Apple_Encrypted_Archive#Padding
pub fn derive_padding_authentication_key(amk: &[u8; 32]) -> [u8; 32] {
    let pak_info = b"AEA_PAK".to_vec();
    let hk_pak = hkdf::Hkdf::<sha2::Sha256>::new(None, amk);
    let mut pak = [0u8; 32];
    hk_pak.expand(&pak_info, &mut pak).expect("PAK expand fail");

    pak
}

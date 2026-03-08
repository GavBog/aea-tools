use std::collections::BTreeMap;

type Offset = u64;
type Length = u64;
type ClusterIndex = u32;
type SegmentIndex = u32;

type Key80 = [u8; 80];
type Hmac32 = [u8; 32];

#[derive(Default)]
pub struct AeaDictionary {
    pub rhek: Option<[u8; 80]>,
    pub root_header_hmac: Option<[u8; 32]>,

    pub prologue_range: Option<(Offset, Length)>,
    pub cluster_map: BTreeMap<ClusterIndex, (Offset, Length, Key80, Hmac32)>,
    pub segment_map: BTreeMap<(ClusterIndex, SegmentIndex), (Offset, Length, Key80, Hmac32)>,
    pub padding_start: Option<(Offset, Length, [u8; 32])>,
}

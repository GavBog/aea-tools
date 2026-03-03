use std::collections::HashMap;

struct AeaDictionary {
    // Index : start offset
    clusterMap: HashMap<u32, u64>,
    // Checksum : start offset, compressed size
    segmentMap: HashMap<[u8; 32], (u64, u32)>,
    paddingStart: u64,
}

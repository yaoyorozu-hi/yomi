use anyhow::Result;

/// zstd level for the archive store. Favors ratio; archival is not latency-bound.
pub const ZSTD_LEVEL: i32 = 19;

/// Compress `bytes` into a single zstd frame.
pub fn compress_frame(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::encode_all(bytes, ZSTD_LEVEL)?)
}

/// Decompress a `.zst` store that may hold multiple concatenated frames
/// (one per incremental capture). zstd reads concatenated frames transparently.
pub fn decompress_all(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::decode_all(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_single_frame() {
        let data = b"the quick brown fox\n";
        let c = compress_frame(data).unwrap();
        assert_eq!(decompress_all(&c).unwrap(), data);
    }

    #[test]
    fn concatenated_frames_decode_in_order() {
        let a = b"line one\nline two\n";
        let b = b"line three\nline four\n";
        let mut store = compress_frame(a).unwrap();
        store.extend_from_slice(&compress_frame(b).unwrap());
        let mut expected = a.to_vec();
        expected.extend_from_slice(b);
        assert_eq!(decompress_all(&store).unwrap(), expected);
    }
}

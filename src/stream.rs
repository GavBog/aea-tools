use crate::reader::AeaReader;
use anyhow::Result;
use lru::LruCache;
use std::{
    io::{Read, Seek, SeekFrom},
    num::NonZeroUsize,
    sync::Arc,
};

pub struct AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    reader: AeaReader<S>,
    virtual_position: u64,
    end_position: u64,
    segment_cache: LruCache<(u32, u32), Arc<[u8]>>,

    segment_index_map: Vec<(u32, u32, u64)>,
    current_scanned_offset: u64,
    next_unscanned_cluster_index: u32,
    total_cluster_count: u32,
}

impl<S> AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    pub fn new(mut reader: AeaReader<S>) -> Result<Self> {
        let end_position = reader
            .get_decompressed_length()
            .map_err(std::io::Error::other)?;

        let total_cluster_count = reader.cluster_count()?;
        let cache_cap = NonZeroUsize::new(128).unwrap();

        Ok(Self {
            reader,
            virtual_position: 0,
            end_position,
            segment_cache: LruCache::new(cache_cap),
            segment_index_map: Vec::new(),
            current_scanned_offset: 0,
            next_unscanned_cluster_index: 0,
            total_cluster_count,
        })
    }

    fn ensure_index_up_to(&mut self, required_offset: u64) -> Result<()> {
        while self.current_scanned_offset <= required_offset
            && self.next_unscanned_cluster_index < self.total_cluster_count
        {
            let header = self
                .reader
                .get_cluster_header(self.next_unscanned_cluster_index)?;

            for (segment_index, segment_info) in header.segment_info.iter().enumerate() {
                self.segment_index_map.push((
                    self.next_unscanned_cluster_index,
                    segment_index as u32,
                    self.current_scanned_offset,
                ));
                self.current_scanned_offset += segment_info.decompressed_size as u64;
            }

            self.next_unscanned_cluster_index += 1;
        }
        Ok(())
    }

    pub fn get_data_at_decompressed_range(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        if length == 0 || offset >= self.end_position {
            return Ok(Vec::new());
        }

        let range_end = (offset + length).min(self.end_position);
        self.ensure_index_up_to(range_end.saturating_sub(1))?;

        let start_index = self
            .segment_index_map
            .partition_point(|&(_, _, segment_offset)| segment_offset <= offset)
            .saturating_sub(1);

        let end_index = self
            .segment_index_map
            .partition_point(|&(_, _, segment_offset)| segment_offset < range_end)
            .saturating_sub(1);

        let mut result_data = Vec::with_capacity(length as usize);
        for map_index in start_index..=end_index {
            let (cluster_index, segment_index, segment_global_start) =
                self.segment_index_map[map_index];

            let segment_data =
                if let Some(cached) = self.segment_cache.get(&(cluster_index, segment_index)) {
                    Arc::clone(cached)
                } else {
                    let data: Vec<u8> = self.reader.get_segment(cluster_index, segment_index)?;
                    let shared_data: Arc<[u8]> = Arc::from(data);
                    self.segment_cache
                        .put((cluster_index, segment_index), Arc::clone(&shared_data));
                    shared_data
                };

            let local_start = if map_index == start_index {
                (offset - segment_global_start) as usize
            } else {
                0
            };

            let local_end = if map_index == end_index {
                (range_end - segment_global_start) as usize
            } else {
                segment_data.len()
            };

            result_data.extend_from_slice(&segment_data[local_start..local_end]);
        }

        Ok(result_data)
    }
}

impl<S> Read for AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.virtual_position >= self.end_position {
            return Ok(0);
        }

        let offset = self.virtual_position;
        let length = buffer.len() as u64;

        let data = self
            .get_data_at_decompressed_range(offset, length)
            .map_err(std::io::Error::other)?;

        let bytes_read = data.len();
        buffer[..bytes_read].copy_from_slice(&data);
        self.virtual_position += bytes_read as u64;

        Ok(bytes_read)
    }
}

impl<S> Seek for AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let new_position = match position {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(offset) => self.virtual_position as i64 + offset,
            SeekFrom::End(offset) => self.end_position as i64 + offset,
        };

        if new_position < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek to a negative position",
            ));
        }

        self.virtual_position = new_position as u64;
        Ok(self.virtual_position)
    }
}

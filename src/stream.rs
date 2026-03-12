use crate::reader::AeaReader;
use anyhow::Result;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

pub struct AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    reader: AeaReader<S>,
    virtual_position: u64,
    end_position: u64,
    segment_cache: HashMap<(u32, u32), Vec<u8>>,
}

impl<S> AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    pub fn new(mut reader: AeaReader<S>) -> std::io::Result<Self> {
        let end_position = reader
            .get_decompressed_length()
            .map_err(std::io::Error::other)?;
        Ok(Self {
            reader,
            virtual_position: 0,
            end_position,
            segment_cache: HashMap::new(),
        })
    }

    pub fn get_data_at_decompressed_range(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let mut start_segment_info = None;
        let mut end_segment_info = None;
        let range_end = offset + length;

        let mut current_offset = 0u64;
        'outer: for cluster_index in 0..self.reader.cluster_count()? {
            let header = self.reader.get_cluster_header(cluster_index)?;
            for (segment_index, info) in header.segment_info.iter().enumerate() {
                let segment_size = info.decompressed_size;
                current_offset += segment_size as u64;
                if start_segment_info.is_none() && current_offset > offset {
                    start_segment_info = Some((
                        cluster_index,
                        segment_index as u32,
                        current_offset - segment_size as u64,
                    ));
                }
                if current_offset >= range_end {
                    end_segment_info = Some((
                        cluster_index,
                        segment_index as u32,
                        current_offset - segment_size as u64,
                    ));
                    break 'outer;
                }
            }
        }

        let (start_cluster, start_segment, start_segment_start_pos) = start_segment_info
            .ok_or_else(|| anyhow::anyhow!("Start offset {} is out of bounds", offset))?;

        let (end_cluster, end_segment, end_segment_start_pos) = end_segment_info
            .ok_or_else(|| anyhow::anyhow!("End offset {} is out of bounds", range_end))?;

        let mut result_data = Vec::with_capacity(length as usize);
        for cluster_index in start_cluster..=end_cluster {
            let header = self.reader.get_cluster_header(cluster_index)?;

            let first_segment_in_this_cluster = if cluster_index == start_cluster {
                start_segment
            } else {
                0
            };
            let last_segment_in_this_cluster = if cluster_index == end_cluster {
                end_segment
            } else {
                (header.segment_info.len() - 1) as u32
            };

            for segment_index in first_segment_in_this_cluster..=last_segment_in_this_cluster {
                let segment_data =
                    if let Some(cached) = self.segment_cache.get(&(cluster_index, segment_index)) {
                        cached.clone()
                    } else {
                        self.reader.get_segment(cluster_index, segment_index)?
                    };

                self.segment_cache
                    .insert((cluster_index, segment_index), segment_data.clone());

                let local_start =
                    if cluster_index == start_cluster && segment_index == start_segment {
                        (offset - start_segment_start_pos) as usize
                    } else {
                        0
                    };

                let local_end = if cluster_index == end_cluster && segment_index == end_segment {
                    (range_end - end_segment_start_pos) as usize
                } else {
                    segment_data.len()
                };

                result_data.extend_from_slice(&segment_data[local_start..local_end]);
            }
        }

        Ok(result_data)
    }
}

impl<S> Read for AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let offset = self.virtual_position;
        let length = buf.len() as u64;

        let data = self
            .get_data_at_decompressed_range(offset, length)
            .map_err(std::io::Error::other)?;

        let bytes_read = data.len();
        buf[..bytes_read].copy_from_slice(&data);
        self.virtual_position += bytes_read as u64;

        Ok(bytes_read)
    }
}

impl<S> Seek for AeaStream<S>
where
    S: Read + Seek + Unpin,
{
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_position = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(offset) => self.virtual_position as i64 + offset,
            SeekFrom::End(offset) => {
                let end_position = self.end_position as i64;
                end_position + offset
            }
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

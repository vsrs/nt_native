use crate::Result;

pub trait Read {
    fn read(&self, buffer: &mut [u8]) -> Result<usize>;
}

pub trait ReadAt {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize>;
}

pub trait Flush {
    fn flush(&self) -> Result<()>;
}

pub trait Size {
    fn size(&self) -> Result<u64>;
}

pub trait Write: Flush {
    fn write(&self, data: &[u8]) -> Result<usize>;
}

pub trait WriteAt: Flush {
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize>;
}

pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

impl From<u64> for SeekFrom {
    fn from(value: u64) -> Self {
        SeekFrom::Start(value)
    }
}

pub trait Seek {
    fn seek(&self, to: SeekFrom) -> Result<u64>;
    fn stream_position(&self) -> Result<u64>;
    fn stream_len(&self) -> Result<u64>;
}

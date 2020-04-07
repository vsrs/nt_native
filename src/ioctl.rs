use crate::*;
use winapi::um::winioctl::{GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO};

pub fn length(handle: &Handle) -> Result<u64> {
    let mut data = unsafe { StructBuffer::<GET_LENGTH_INFORMATION>::new() };
    handle.ioctl_query(IOCTL_DISK_GET_LENGTH_INFO, &mut data)?;
    Ok(unsafe { *data.Length.QuadPart() as u64 })
}

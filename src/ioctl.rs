use winapi::um::winioctl::{GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO};
use crate::*;

pub fn length(handle: &Handle) -> Result<u64> {
    let data = handle.ioctl_query::<GET_LENGTH_INFORMATION>(IOCTL_DISK_GET_LENGTH_INFO)?;
    Ok( unsafe { *data.Length.QuadPart() as u64 } )
}

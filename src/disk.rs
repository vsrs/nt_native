use crate::*;
use winapi::um::winioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY};

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct Disk(Handle);

impl From<Handle> for Disk {
    fn from(handle: Handle) -> Self {
        Self(handle)
    }
}

impl Disk {
    fn index_to_name(index: u32) -> NtString {
        let name = crate::format!("\\??\\PhysicalDrive{}", index);
        NtString::from(name)
    }

    pub fn open_nth(index: u32) -> Result<Self> {
        let name = Self::index_to_name(index);
        Self::open(&name)
    }

    pub fn open(name: &NtString) -> Result<Self> {
        let (handle, _) = NewHandle::device(Access::GENERIC_READ | Access::GENERIC_WRITE).build(name)?;

        Ok(Self(handle))
    }

    pub fn open_nth_readonly(index: u32) -> Result<Self> {
        let name = Self::index_to_name(index);
        Self::open_readonly(&name)
    }

    // TODO: check if the call needs ADMIN rights
    pub fn open_readonly(name: &NtString) -> Result<Self> {
        let (handle, _) = NewHandle::device(Access::GENERIC_READ).build(name)?;

        Ok(Self(handle))
    }

    /// Usefull only to get device_name without admin rights.
    pub fn open_nth_info(index: u32) -> Result<Self> {
        let name = Self::index_to_name(index);
        Self::open_info(&name)
    }

    /// Usefull only to get device_name without admin rights.
    pub fn open_info(name: &NtString) -> Result<Self> {
        let (handle, _) = NewHandle::device(Access::SYNCHRONIZE).build(name)?;

        Ok(Self(handle))
    }

    /// Returns the disk device name: `\Device\Harddisk0\DR0`.
    ///
    /// To pass this name to a Win32 function add `\\?\GLOBALROOT\` prefix: `\\?\GLOBALROOT\Device\Harddisk0\DR0`
    pub fn device_name(&self) -> Result<NtString> {
        self.0.object_name()
    }

    pub fn capacity(&self) -> Result<u64> {
        ioctl::length(&self.0)
    }

    pub fn is_readonly(&self) -> Result<bool> {
        ioctl::is_readonly(&self.0)
    }

    pub fn is_offline(&self) -> Result<bool> {
        const DISK_ATTRIBUTE_OFFLINE: u64 = 0x01;
        let attr = self.attributes()?;
        Ok((attr & DISK_ATTRIBUTE_OFFLINE) == DISK_ATTRIBUTE_OFFLINE)
    }

    pub fn is_removable(&self) -> Result<bool> {
        ioctl::is_removable(&self.0)
    }

    pub fn is_trim_enabled(&self) -> Result<bool> {
        ioctl::is_trim_enabled(&self.0)
    }
    pub fn has_seek_penalty(&self) -> Result<bool> {
        ioctl::has_seek_penalty(&self.0)
    }

    pub fn device_number(&self) -> Result<u32> {
        ioctl::device_number(&self.0)
    }

    pub fn attributes(&self) -> Result<u64> {
        ioctl::attributes(&self.0)
    }

    pub fn geometry(&self) -> Result<DISK_GEOMETRY> {
        let mut data = unsafe { StructBuffer::<DISK_GEOMETRY>::new() };
        self.0.ioctl_query(IOCTL_DISK_GET_DRIVE_GEOMETRY, &mut data)?;

        Ok(data.take())
    }
}

impl Flush for Disk {
    fn flush(&self) -> Result<()> {
        self.0.flush()
    }
}

impl Size for Disk {
    fn size(&self) -> Result<u64> {
        Disk::capacity(self)
    }
}

impl ReadAt for Disk {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.0.read(buffer, Some(offset))
    }
}

impl WriteAt for Disk {
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        self.0.write(data, Some(offset))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test] // needs admin rights
    fn open() {
        if std::env::var("NT_NATIVE_TEST_ADMIN").is_ok() {
            let disk = Disk::open_nth(0).unwrap();
            let mut buffer = vec![0_u8; 512];
            let readed = disk.read_at(0, &mut buffer).unwrap();
            assert_eq!(readed, buffer.len());

            println!("First bytes (of {}):", disk.capacity().unwrap());
            for chunk in buffer.chunks(16).take(4) {
                println!("{:02x?}", chunk)
            }
        } else {
            print!("Non admin, skipped ... ");
        }
    }

    #[test]
    fn open_disk_info() {
        let disk = Disk::open_nth_info(0).unwrap();

        let name = disk.device_name().unwrap();
        println!("DeviceName: {}", name.to_string());
    }
}

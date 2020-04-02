use crate::*;

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct Volume(Handle);

impl From<Handle> for Volume {
    fn from(handle: Handle) -> Self {
        Self(handle)
    }
}

impl Volume {
    pub fn open(name: &NtString) -> Result<Self> {
        let (handle, _) = NewHandle::device().build(name)?;

        Ok(Self(handle))
    }

    pub fn open_readonly(name: &NtString) -> Result<Self> {
        let (handle, _) = NewHandle::ro_device().build(name)?;

        Ok(Self(handle))
    }

    /// Returns the volume device name: `\Device\HarddiskVolume3`.
    ///
    /// To pass this name to a Win32 function add `\\?\GLOBALROOT\` prefix: `\\?\GLOBALROOT\Device\HarddiskVolume3`
    pub fn device_name(&self) -> Result<NtString> {
        self.0.object_name()
    }

    /// Returns the guid volume name: `\??\Volume{736d36a8-0000-0000-0000-100000000000}`.
    ///
    /// To pass this name to a Win32 function change second char to `\` : `\\?\Volume{736d36a8-0000-0000-0000-100000000000}`
    pub fn guid_name(&self) -> Result<NtString> {
        let mm = MountManager::open_readonly()?;
        let device_name = self.device_name()?;
        let info = mm.volume_mount_point(&device_name)?;
        Ok(info.guid_name)
    }

    /// Returns the unique volume binary ID.
    pub fn id(&self) -> Result<Vec<u8>> {
        let mm = MountManager::open_readonly()?;
        let device_name = self.device_name()?;
        let info = mm.volume_mount_point(&device_name)?;
        Ok(info.id)
    }

    /// Returns all volume mount points (as DOS names: `c:`, `c:\mount\folder`, etc. )
    pub fn path_names(&self) -> Result<Vec<NtString>> {
        let mm = MountManager::open_readonly()?;
        let device_name = self.device_name()?;
        mm.path_names(&device_name)
    }
}

impl Flush for Volume {
    fn flush(&self) -> Result<()> {
        self.0.flush()
    }
}

impl ReadAt for Volume {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.0.read(buffer, Some(offset))
    }
}

impl WriteAt for Volume {
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        self.0.write(data, Some(offset))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn open_ro_c() {
        let volume = Volume::open_readonly(nt_str_ref!("\\\\.\\c:")).unwrap();
        let path_names = volume.path_names().unwrap();
        println!("Volume 'C:' path names: ");
        for p in path_names {
            println!("  --- {}", p.to_string());
        }
        let device_name = volume.device_name().unwrap();
        println!("   Device Name: {}", device_name.to_string());

        let guid_name = volume.guid_name().unwrap();
        println!("   Guid Name: {}", guid_name.to_string());
    }
}

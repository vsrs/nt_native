use crate::*;
use core::mem;
use ntapi::ntioapi::*;
use winapi::shared::minwindef::MAX_PATH;
use winapi::shared::ntdef::{LONG, PVOID, ULONG};

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
        let (handle, _) = NewHandle::device(Access::GENERIC_READ | Access::GENERIC_WRITE).build(name)?;

        Ok(Self(handle))
    }

    /// To get the volume information only, not to read data!
    pub fn open_readonly(name: &NtString) -> Result<Self> {
        let (handle, _) = NewHandle::device(Access::READ_ATTRIBUTES | Access::SYNCHRONIZE).build(name)?;

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

pub struct FsInformation {
    pub name: NtString,
}

// FILE_FS_***_INFORMATION helpers
impl Volume {
    unsafe fn query_info<T: Sized>(handle: &Handle, class: FS_INFORMATION_CLASS) -> Result<T> {
        let mut info: T = mem::zeroed();
        let mut iosb: IO_STATUS_BLOCK = mem::zeroed();

        let status = NtQueryVolumeInformationFile(
            handle.as_raw(),
            &mut iosb,
            &mut info as *mut T as PVOID,
            mem::size_of::<T>() as u32,
            class,
        );

        nt_result!(status, info)
    }

    pub fn fs_information(&self) -> Result<FsInformation> {
        #[repr(C)]
        struct FsInfoWithBuffer {
            attributes: ULONG,
            maximum_component_name_length: LONG,
            fs_name_length: ULONG,
            fs_name: [u16; MAX_PATH],
        }

        // have to reopen the file system of the volume
        let mut device_name = self.device_name()?;
        device_name.push('\\' as u16); // trailing slash opens the FS

        let (fs_handle, _) = NewHandle::device(Access::READ_ATTRIBUTES | Access::SYNCHRONIZE).build_nt(&device_name)?;
        let attr_info: FsInfoWithBuffer = unsafe { Self::query_info(&fs_handle, FileFsAttributeInformation)? };
        let name = NtString::from(&attr_info.fs_name[..attr_info.fs_name_length as usize / U16_SIZE]);

        let vol_info: FILE_FS_VOLUME_INFORMATION = unsafe { Self::query_info(&fs_handle, FileFsVolumeInformation)? };

        Ok(FsInformation { name })
    }
}

impl Flush for Volume {
    fn flush(&self) -> Result<()> {
        self.0.flush()
    }
}

impl ReadAt for Volume {
    /// buffer size should be aligned!
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.0.read(buffer, Some(offset))
    }
}

impl WriteAt for Volume {
    /// buffer size should be aligned!
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

    #[test]
    fn volume_fs_info() {
        let volume = Volume::open_readonly(nt_str_ref!("\\\\.\\c:")).unwrap();
        let fs_info = volume.fs_information().unwrap();

        println!("FS: {}", fs_info.name.to_string());
    }

    #[test] // needs admin rights
    fn volume_read() {
        if std::env::var("NT_NATIVE_TEST_ADMIN").is_ok() {
            let volume = Volume::open(nt_str_ref!("\\\\.\\c:")).unwrap();
            let mut buffer = vec![0_u8; 512];
            let readed = volume.read_at(0, &mut buffer).unwrap();
            assert_eq!(readed, buffer.len());

            println!("First bytes:");
            for chunk in buffer.chunks(16).take(4) {
                println!("{:02x?}", chunk)
            }
        } else {
            print!("Non admin, skipped ... ");
        }
    }
}

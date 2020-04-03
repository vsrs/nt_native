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

    /// Requires volume to be opened with Volume::open() and admin rights!
    pub fn length(&self) -> Result<u64> {
        crate::ioctl::length(&self.0)
    }
}

pub struct FsInformation {
    pub name: NtString,
}

pub struct VolumeInformation {
    pub label: NtString,
    pub serial_number: u32,
    pub supports_objects: bool,
}

pub struct SizeInformation {
    pub total: u64,
    pub caller_available: u64,
    pub actual_available: u64,
    pub sectors_per_cluster: u32,
    pub bytes_per_sector: u32,
}

// FILE_FS_***_INFORMATION helpers
impl Volume {
    pub unsafe fn query_info<T: Sized>(handle: &Handle, class: FS_INFORMATION_CLASS) -> Result<T> {
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

        let fs_handle = self.reopen_fs()?;
        let attr_info: FsInfoWithBuffer = unsafe { Self::query_info(&fs_handle, FileFsAttributeInformation)? };
        let name = NtString::from(&attr_info.fs_name[..attr_info.fs_name_length as usize / U16_SIZE]);

        Ok(FsInformation { name })
    }

    pub fn information(&self) -> Result<VolumeInformation> {
        #[repr(C)]
        struct VolumeInfoWithBuffer {
            creation_time : u64, // LARGE_INTEGER 
            serial_number: ULONG,
            label_length: ULONG,
            supports_objects: bool,
            label: [u16; MAX_PATH],
        }

        let fs_handle = self.reopen_fs()?;
        let vol_info: VolumeInfoWithBuffer = unsafe { Self::query_info(&fs_handle, FileFsVolumeInformation)? };
        let label = NtString::from(&vol_info.label[..vol_info.label_length as usize / U16_SIZE]);

        Ok(VolumeInformation{
            label,
            serial_number: vol_info.serial_number,
            supports_objects: vol_info.supports_objects
        })
    }

    pub fn fs_size_information(&self) -> Result<SizeInformation> {
        let fs_handle = self.reopen_fs()?;

        unsafe {
            let info : FILE_FS_FULL_SIZE_INFORMATION = Self::query_info(&fs_handle, FileFsFullSizeInformation)?;

            let cluster_size = (info.SectorsPerAllocationUnit * info.BytesPerSector) as u64;
            let total = (*info.TotalAllocationUnits.QuadPart() as u64) * cluster_size;
            let caller_available = (*info.CallerAvailableAllocationUnits.QuadPart() as u64) * cluster_size;
            let actual_available = (*info.ActualAvailableAllocationUnits.QuadPart() as u64) * cluster_size;

            Ok(SizeInformation{
                total,
                caller_available,
                actual_available,
                sectors_per_cluster: info.SectorsPerAllocationUnit,
                bytes_per_sector: info.BytesPerSector,
            })
        }
    }

    fn reopen_fs(&self) -> Result<Handle> {
        // have to reopen the file system of the volume
        let mut device_name = self.device_name()?;
        device_name.push('\\' as u16); // trailing slash opens the FS

        let (fs_handle, _) = NewHandle::device(Access::READ_ATTRIBUTES | Access::SYNCHRONIZE).build_nt(&device_name)?;

        Ok(fs_handle)
    }
}

impl Flush for Volume {
    /// Requires volume to be opened with Volume::open() and admin rights!
    fn flush(&self) -> Result<()> {
        self.0.flush()
    }
}

impl Size for Volume {
    /// Requires volume to be opened with Volume::open() and admin rights!
    fn size(&self) -> Result<u64> {
        self.length()
    }
}

impl ReadAt for Volume {
    /// buffer size should be aligned!
    /// Requires volume to be opened with Volume::open() and admin rights!
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.0.read(buffer, Some(offset))
    }
}

impl WriteAt for Volume {
    /// buffer size should be aligned!
    /// Requires volume to be opened with Volume::open() and admin rights!
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
    fn information() {
        let volume = Volume::open_readonly(nt_str_ref!("\\\\.\\c:")).unwrap();
        
        let fs_info = volume.fs_information().unwrap();
        println!("FS: {}", fs_info.name.to_string());

        let volume_info = volume.information().unwrap();
        println!("Volume: {} {:08x}, objects: {}", volume_info.label.to_string(), volume_info.serial_number, volume_info.supports_objects);

        let size_information = volume.fs_size_information().unwrap();
        println!("Size: {}", size_information.total);
    }

    #[test]
    fn length() {
        if std::env::var("NT_NATIVE_TEST_ADMIN").is_ok() {
            let volume = Volume::open(nt_str_ref!("\\\\.\\c:")).unwrap();
        
            let size = volume.length().unwrap();
            println!("Size: {}", size)
        } else {
            print!("Non admin, skipped ... ");
        }
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

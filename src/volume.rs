use crate::*;
use core::mem;
use ntapi::ntioapi::*;
use winapi::shared::minwindef::MAX_PATH;
use winapi::shared::ntdef::{PVOID, TRUE};

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
        let (handle, _) = NewHandle::device(Access::SYNCHRONIZE).build(name)?;

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
    pub unsafe fn query_info<T: AsByteSliceMut>(handle: &Handle, class: FS_INFORMATION_CLASS, buffer: &mut T) -> Result<()> {
        let mut iosb: IO_STATUS_BLOCK = mem::zeroed();
        let bytes_buffer = buffer.as_byte_slice_mut();
        let bytes_len = bytes_buffer.len();

        let status = NtQueryVolumeInformationFile(
            handle.as_raw(),
            &mut iosb,
            bytes_buffer.as_mut_ptr() as PVOID,
            bytes_len as u32,
            class,
        );

        nt_result!(status, ())
    }

    pub fn fs_information(&self) -> Result<FsInformation> {
        let fs_handle = self.reopen_fs()?;
        let info = unsafe {
            let mut info = StructBuffer::<FILE_FS_ATTRIBUTE_INFORMATION>::with_ext(MAX_PATH * U16_SIZE);
            Self::query_info(&fs_handle, FileFsAttributeInformation, &mut info)?;
            let name = NtString::from_raw_bytes(info.FileSystemName.as_ptr(), info.FileSystemNameLength);
            FsInformation { name }
        };

        Ok(info)
    }

    pub fn information(&self) -> Result<VolumeInformation> {
        let fs_handle = self.reopen_fs()?;
        let info = unsafe {
            let mut info = StructBuffer::<FILE_FS_VOLUME_INFORMATION>::with_ext(MAX_PATH * U16_SIZE);
            Self::query_info(&fs_handle, FileFsVolumeInformation, &mut info)?;
            let label = NtString::from_raw_bytes(info.VolumeLabel.as_ptr(), info.VolumeLabelLength);

            VolumeInformation {
                label,
                serial_number: info.VolumeSerialNumber,
                supports_objects: info.SupportsObjects == TRUE,
            }
        };

        Ok(info)
    }

    pub fn fs_size_information(&self) -> Result<SizeInformation> {
        let fs_handle = self.reopen_fs()?;

        unsafe {
            let mut info = StructBuffer::<FILE_FS_FULL_SIZE_INFORMATION>::new();
            Self::query_info(&fs_handle, FileFsFullSizeInformation, &mut info)?;

            let cluster_size = (info.SectorsPerAllocationUnit * info.BytesPerSector) as u64;
            let total = (*info.TotalAllocationUnits.QuadPart() as u64) * cluster_size;
            let caller_available = (*info.CallerAvailableAllocationUnits.QuadPart() as u64) * cluster_size;
            let actual_available = (*info.ActualAvailableAllocationUnits.QuadPart() as u64) * cluster_size;

            Ok(SizeInformation {
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

        let (fs_handle, _) = NewHandle::device(Access::SYNCHRONIZE).build_nt(&device_name)?;

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
        println!(
            "Volume: {} {:08x}, objects: {}",
            volume_info.label.to_string(),
            volume_info.serial_number,
            volume_info.supports_objects
        );

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

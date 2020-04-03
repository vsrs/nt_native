use crate::*;
use core::mem;
use ntapi::ntioapi::*;
use winapi::shared::minwindef::MAX_PATH;
use winapi::shared::ntdef::{PVOID, TRUE, ULONG};

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct File(Handle);

impl From<Handle> for File {
    fn from(handle: Handle) -> Self {
        Self(handle)
    }
}

// ctors
impl File {
    pub fn create_new(name: &NtString) -> Result<Self> {
        let handle = NewHandle::create_new(name)?;
        Ok(Self(handle))
    }

    pub fn create_preallocated(name: &NtString, size: u64) -> Result<Self> {
        let handle = NewHandle::create_new(name)?;
        let file = Self(handle);
        file.set_end_of_file(size)?;
        Ok(file)
    }

    pub fn open(name: &NtString) -> Result<Self> {
        let handle = NewHandle::open(name)?;
        Ok(Self(handle))
    }

    pub fn open_readonly(name: &NtString) -> Result<Self> {
        let handle = NewHandle::open_readonly(name)?;
        Ok(Self(handle))
    }

    pub fn open_or_create(name: &NtString) -> Result<(Self, bool)> {
        let (handle, already_exists) = NewHandle::open_or_create(name)?;
        Ok((Self(handle), already_exists))
    }

    pub fn owerwrite(name: &NtString) -> Result<Self> {
        let handle = NewHandle::owerwrite(name)?;
        Ok(Self(handle))
    }

    pub fn owerwrite_or_create(name: &NtString) -> Result<(Self, bool)> {
        let (handle, already_exists) = NewHandle::owerwrite_or_create(name)?;
        Ok((Self(handle), already_exists))
    }
}

// inner
impl File {
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }

    pub fn close(&mut self) -> Result<()> {
        self.0.close()
    }

    pub fn object_name(&self) -> Result<NtString> {
        self.0.object_name()
    }
}

// FILE_***_INFORMATION helpers
impl File {
    unsafe fn query_info<T: Sized>(&self, class: FILE_INFORMATION_CLASS) -> Result<T> {
        let mut info: T = mem::zeroed();
        let mut iosb: IO_STATUS_BLOCK = mem::zeroed();

        let status = NtQueryInformationFile(
            self.0.as_raw(),
            &mut iosb,
            &mut info as *mut T as PVOID,
            mem::size_of::<T>() as u32,
            class,
        );

        nt_result!(status, info)
    }

    unsafe fn set_info<T: Sized>(&self, class: FILE_INFORMATION_CLASS, info: &T) -> Result<()> {
        let mut iosb: IO_STATUS_BLOCK = mem::zeroed();

        let status = NtSetInformationFile(
            self.0.as_raw(),
            &mut iosb,
            info as *const T as PVOID,
            mem::size_of::<T>() as u32,
            class,
        );

        nt_result!(status, ())
    }

    pub fn pos(&self) -> Result<u64> {
        unsafe {
            let info = self.query_info::<FILE_POSITION_INFORMATION>(FilePositionInformation)?;
            Ok(*info.CurrentByteOffset.QuadPart() as u64)
        }
    }

    pub fn set_pos(&self, pos: u64) -> Result<u64> {
        unsafe {
            let mut info: FILE_POSITION_INFORMATION = mem::zeroed();
            *info.CurrentByteOffset.QuadPart_mut() = pos as i64;

            self.set_info(FilePositionInformation, &info)?;
        }

        Ok(pos as u64)
    }

    pub fn size(&self) -> Result<u64> {
        unsafe {
            let info = self.query_info::<FILE_STANDARD_INFORMATION>(FileStandardInformation)?;
            Ok(*info.EndOfFile.QuadPart() as u64)
        }
    }

    pub fn size_on_disk(&self) -> Result<u64> {
        unsafe {
            let info = self.query_info::<FILE_STANDARD_INFORMATION>(FileStandardInformation)?;
            Ok(*info.AllocationSize.QuadPart() as u64)
        }
    }

    pub fn access_mask(&self) -> Result<Access> {
        unsafe {
            let info = self.query_info::<FILE_ACCESS_INFORMATION>(FileAccessInformation)?;
            Ok(Access::from_bits_unchecked(info.AccessFlags))
        }
    }

    /// Returns the buffer alignment required by the underlying device.
    ///
    /// See [FILE_ALIGNMENT_INFORMATION](https://docs.microsoft.com/ru-ru/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_alignment_information)
    pub fn alignment(&self) -> Result<usize> {
        unsafe {
            let info = self.query_info::<FILE_ALIGNMENT_INFORMATION>(FileAlignmentInformation)?;
            Ok(info.AlignmentRequirement as usize)
        }
    }

    /// Returns the access mode of a file.  
    /// This flags are is only a subset of all possible Options flags!
    ///
    /// See [FILE_MODE_INFORMATION](https://docs.microsoft.com/ru-ru/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_mode_information)
    pub fn mode(&self) -> Result<Options> {
        unsafe {
            let info = self.query_info::<FILE_MODE_INFORMATION>(FileModeInformation)?;
            Ok(Options::from_bits_unchecked(info.Mode))
        }
    }

    /// Returns whether the file system that contains the file is a remote file system.
    ///
    /// See [FILE_IS_REMOTE_DEVICE_INFORMATION](https://docs.microsoft.com/ru-ru/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_is_remote_device_information)
    pub fn is_remote(&self) -> Result<bool> {
        unsafe {
            let info = self.query_info::<FILE_IS_REMOTE_DEVICE_INFORMATION>(FileIsRemoteDeviceInformation)?;
            Ok(info.IsRemote == TRUE)
        }
    }

    /// Returns the pathname of a file or directory without a drive letter(volume).
    /// The volume can be mounted as a mountpoint, so using drive letters in low-level code is a very bad idea.
    ///
    /// If the ObjectAttributes->RootDirectory handle was opened by file ID, `path_name()` returns the relative path.
    /// If only the relative path is returned, the file name string will not begin with a backslash.
    ///
    /// See [FILE_NAME_INFORMATION](https://docs.microsoft.com/ru-ru/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_name_information)
    pub fn path_name(&self) -> Result<NtString> {
        #[repr(C)]
        struct FileNameInfoWithBuffer {
            length_in_bytes: ULONG,
            name_buffer: [u16; MAX_PATH],
        }

        let res = unsafe { self.query_info::<FileNameInfoWithBuffer>(FileNameInformation)? };
        let name_bytes = &res.name_buffer[..(res.length_in_bytes as usize / mem::size_of::<u16>())];

        Ok(NtString::from(name_bytes))
    }

    pub fn set_end_of_file(&self, end_of_file: u64) -> Result<()> {
        unsafe {
            let mut info: FILE_END_OF_FILE_INFORMATION = mem::zeroed();
            *info.EndOfFile.QuadPart_mut() = end_of_file as i64;
            self.set_info(FileEndOfFileInformation, &info)
        }
    }
}

impl Read for File {
    fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        self.0.read(buffer, None)
    }
}

impl ReadAt for File {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.0.read(buffer, Some(offset))
    }
}

impl Flush for File {
    fn flush(&self) -> Result<()> {
        self.0.flush()
    }
}

impl Size for File {
    fn size(&self) -> Result<u64> {
        File::size(self)
    }
}

impl Write for File {
    fn write(&self, data: &[u8]) -> Result<usize> {
        self.0.write(data, None)
    }
}

impl WriteAt for File {
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        self.0.write(data, Some(offset))
    }
}

impl Seek for File {
    fn seek(&self, to: SeekFrom) -> Result<u64> {
        let (mut pos, offset) = match to {
            SeekFrom::Start(s) => (s as i64, 0),
            SeekFrom::End(e) => (self.size()? as i64, e),
            SeekFrom::Current(c) => (self.pos()? as i64, c),
        };

        pos += offset;

        self.set_pos(pos as u64)
    }
    fn stream_position(&self) -> Result<u64> {
        self.pos()
    }
    fn stream_len(&self) -> Result<u64> {
        self.size()
    }
}

#[cfg(feature = "std")]
mod std_impl {
    use super::*;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};

    impl FromRawHandle for File {
        unsafe fn from_raw_handle(handle: RawHandle) -> Self {
            Self::from(Handle::from_raw_handle(handle))
        }
    }

    impl AsRawHandle for File {
        fn as_raw_handle(&self) -> RawHandle {
            self.0.as_raw_handle()
        }
    }

    impl IntoRawHandle for File {
        fn into_raw_handle(self) -> RawHandle {
            self.0.into_raw_handle()
        }
    }

    impl io::Read for File {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            (self as &dyn crate::Read).read(buf).map_err(Into::into)
        }
    }

    impl io::Write for File {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (self as &dyn crate::Write).write(buf).map_err(Into::into)
        }

        fn flush(&mut self) -> io::Result<()> {
            (self as &dyn crate::Write).flush().map_err(Into::into)
        }
    }

    impl io::Seek for File {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            (self as &dyn crate::Seek).seek(pos.into()).map_err(Into::into)
        }

        // Tracking issue for Seek::{stream_len, stream_position} (feature `seek_convenience`)
        // https://github.com/rust-lang/rust/issues/59359
        //
        // fn stream_len(&mut self) -> io::Result<u64> {
        //     self.size().map_err(Into::into)
        // }

        // fn stream_position(&mut self) -> io::Result<u64> {
        //     self.pos().map_err(Into::into)
        // }
    }
}

#[cfg(feature = "std")]
pub use std_impl::*;

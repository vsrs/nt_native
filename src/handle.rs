use core::{mem, ptr};

use ntapi::ntioapi::*;
use ntapi::ntobapi::*;
use winapi::shared::ntdef::{
    InitializeObjectAttributes, FALSE, HANDLE, LARGE_INTEGER, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, PLARGE_INTEGER,
    PVOID, ULONG,
};
use winapi::shared::ntstatus::STATUS_PENDING;
use winapi::shared::minwindef::MAX_PATH;

use crate::{Access, NtString, NullSafeMutPtr, NullSafePtr, Result};

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

#[derive(Clone, Debug)]
pub struct Handle(HANDLE);

unsafe impl Sync for Handle {}
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        let _res = self.close();
    }
}

impl Handle {
    /// Takes ownership of the handle
    pub(crate) fn new(handle: HANDLE) -> Handle {
        Handle(handle)
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_null()
    }

    pub fn close(&mut self) -> Result<()> {
        if self.is_valid() {
            let status = unsafe { NtClose(self.0) };
            nt_result!(status, {
                self.0 = 0 as HANDLE;
            })
        } else {
            Ok(())
        }
    }

    pub fn write(&self, data: &[u8]) -> Result<usize> {
        self.write_impl(data, None)
    }

    pub fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        self.read_impl(buffer, None)
    }

    pub fn write_at(&self, pos: u64, data: &[u8]) -> Result<usize> {
        self.write_impl(data, Some(pos))
    }

    pub fn read_at(&self, pos: u64, buffer: &mut [u8]) -> Result<usize> {
        self.read_impl(buffer, Some(pos))
    }

    pub fn flush(&self) -> Result<()> {
        self.flush_impl()
    }

    pub fn seek(&self, pos: impl Into<SeekFrom>) -> Result<u64> {
        self.seek_impl(pos.into())
    }

    pub fn pos(&self) -> Result<u64> {
        unsafe {
            let info = self.query_info::<FILE_POSITION_INFORMATION>(FilePositionInformation)?;
            Ok(*info.CurrentByteOffset.QuadPart() as u64)
        }
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
            Ok( Access::from_bits_unchecked(info.AccessFlags) )
        }
    }

    pub fn alignment(&self) -> Result<usize> {
        unsafe {
            let info = self.query_info::<FILE_ALIGNMENT_INFORMATION>(FileAlignmentInformation)?;
            Ok( info.AlignmentRequirement as usize )
        }
    }

    /// Returns the pathname of a file or directory without a drive letter(volume).
    /// The volume can be mounted as a mountpoint, so using drive letters in low-level code is a very bad idea.
    ///
    /// If the ObjectAttributes->RootDirectory handle was opened by file ID, `path_name()` returns the relative path.
    /// If only the relative path is returned, the file name string will not begin with a backslash.
    /// 
    /// See also: object_name()
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

    /// Returns full object name.
    /// For files it would be something like `\Device\HarddiskVolumeN\RootDir\Dir\file.ext'
    pub fn object_name(&self) -> Result<NtString> {
        unsafe {
            let info_size = mem::size_of::<OBJECT_NAME_INFORMATION>();
            let buffer_size =  info_size + MAX_PATH * 2;
            let mut buffer = Vec::<u8>::with_capacity(buffer_size);
            buffer.set_len(buffer_size);
            let mut return_len : ULONG = 0;
            let status = NtQueryObject(self.0, ObjectNameInformation, buffer.as_mut_ptr() as PVOID, buffer_size as ULONG, &mut return_len);
            nt_result!(status, {
                let info = &*(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION);
                let name_slice = core::slice::from_raw_parts(info.Name.Buffer as *const u16, info.Name.Length as usize / mem::size_of::<u16>());
                NtString::from(name_slice)
            })
        }
    }

    /// ShareAccess::DELETE flag should be set.
    ///
    /// Warning: the file will be deleted immediately after the call!
    /// The system will not wait until the last HANDLE to the file is closed.
    pub fn remove_object(mut self) -> Result<()> {
        unsafe {
            let mut oa = mem::MaybeUninit::<OBJECT_ATTRIBUTES>::uninit();
            let mut name = NtString::new().as_unicode_string();
            InitializeObjectAttributes(
                oa.as_mut_ptr(),
                &mut name,       // name
                0,               // attributes
                self.0,          // root
                ptr::null_mut(), // sd
            );

            let status = NtDeleteFile(oa.as_mut_ptr());
            nt_result!(status).and_then(move |_| self.close())
        }
    }

    pub(crate) fn as_raw(&self) -> HANDLE {
        self.0
    }
}

// raw information
impl Handle {
    pub unsafe fn query_info<T: Sized>(&self, class: FILE_INFORMATION_CLASS) -> Result<T> {
        let mut info: T = mem::zeroed();
        let mut iosb: IO_STATUS_BLOCK = mem::zeroed();

        let status = NtQueryInformationFile(
            self.0,
            &mut iosb,
            &mut info as *mut T as PVOID,
            mem::size_of::<T>() as u32,
            class,
        );

        nt_result!(status, info)
    }

    pub unsafe fn set_info<T: Sized>(&self, class: FILE_INFORMATION_CLASS, info: &T) -> Result<()> {
        let mut iosb: IO_STATUS_BLOCK = mem::zeroed();

        let status = NtSetInformationFile(
            self.0,
            &mut iosb,
            info as *const T as PVOID,
            mem::size_of::<T>() as u32,
            class,
        );

        nt_result!(status, ())
    }
}

macro_rules! offset_from_pos {
    ($offset:ident, $pos:ident) => {{
        let mut $offset: LARGE_INTEGER = mem::zeroed();
        match $pos {
            Some(p) => {
                *$offset.QuadPart_mut() = p as i64;
                &mut $offset as PLARGE_INTEGER
            }
            None => ptr::null_mut(),
        }
    }};
}

// internals
impl Handle {
    #[inline]
    unsafe fn wait_for_pending(&self, mut status: NTSTATUS, iosb: &IO_STATUS_BLOCK) -> NTSTATUS {
        if STATUS_PENDING == status {
            status = NtWaitForSingleObject(self.0, FALSE, ptr::null_mut());
            if NT_SUCCESS(status) {
                status = iosb.u.Status;
            }
        }

        status
    }

    fn write_impl(&self, data: &[u8], pos: Option<u64>) -> Result<usize> {
        unsafe {
            let offset_ptr = offset_from_pos!(offset, pos);
            let mut iosb = mem::zeroed::<IO_STATUS_BLOCK>();
            let buffer_len = data.len() as ULONG;
            let buffer_ptr = data.safe_ptr() as PVOID;

            let mut status = NtWriteFile(
                self.0,          // FileHandle
                ptr::null_mut(), // completition event
                None,            // ApcRoutine
                ptr::null_mut(), // ApcContext
                &mut iosb,       // IoStatusBlock
                buffer_ptr,      // Buffer
                buffer_len,      // Length
                offset_ptr,      // ByteOffset
                ptr::null_mut(), // Key
            );

            status = self.wait_for_pending(status, &iosb);
            nt_result!(status, iosb.Information as usize)
        }
    }

    fn read_impl(&self, mut buffer: &mut [u8], pos: Option<u64>) -> Result<usize> {
        unsafe {
            let offset_ptr = offset_from_pos!(offset, pos);
            let mut iosb = mem::zeroed::<IO_STATUS_BLOCK>();
            let buffer_len = buffer.len() as ULONG;
            let buffer_ptr = buffer.safe_mut_ptr() as PVOID;

            let mut status = NtReadFile(
                self.0,          // FileHandle
                ptr::null_mut(), // completition event
                None,            // ApcRoutine
                ptr::null_mut(), // ApcContext
                &mut iosb,       // IoStatusBlock
                buffer_ptr,      // Buffer
                buffer_len,      // Length
                offset_ptr,      // ByteOffset
                ptr::null_mut(), // Key
            );

            status = self.wait_for_pending(status, &iosb);
            nt_result!(status, iosb.Information as usize)
        }
    }

    fn flush_impl(&self) -> Result<()> {
        unsafe {
            let mut iosb = mem::zeroed::<IO_STATUS_BLOCK>();
            let status = NtFlushBuffersFile(self.0, &mut iosb);
            nt_result!(status, ())
        }
    }

    fn seek_impl(&self, pos: SeekFrom) -> Result<u64> {
        let (mut pos, offset) = match pos {
            SeekFrom::Start(s) => (s as i64, 0),
            SeekFrom::End(e) => (self.size()? as i64, e),
            SeekFrom::Current(c) => (self.pos()? as i64, c),
        };
        
        pos += offset;
        unsafe {
            let mut info : FILE_POSITION_INFORMATION = mem::zeroed();
            *info.CurrentByteOffset.QuadPart_mut() = pos;

            self.set_info(FilePositionInformation, &info)?;
        }

        Ok(pos as u64)
    }
}

#[cfg(feature = "std")]
mod std_impl {
    use super::*;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};
    use std::io;

    impl FromRawHandle for Handle {
        unsafe fn from_raw_handle(handle: RawHandle) -> Self {
            Handle::new(handle as HANDLE)
        }
    }

    impl AsRawHandle for Handle {
        fn as_raw_handle(&self) -> RawHandle {
            self.0 as RawHandle
        }
    }

    impl IntoRawHandle for Handle {
        fn into_raw_handle(self) -> RawHandle {
            self.0 as RawHandle
        }
    }

    impl From<std::io::SeekFrom> for SeekFrom {
        fn from(value: std::io::SeekFrom) -> Self {
            match value {
                std::io::SeekFrom::Start(s) => SeekFrom::Start(s),
                std::io::SeekFrom::End(e) => SeekFrom::End(e),
                std::io::SeekFrom::Current(c) => SeekFrom::Current(c),
            }
        }
    }

    impl io::Read for Handle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_impl(buf, None).map_err(Into::into)
        }
    }

    impl io::Write for Handle {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_impl(buf, None).map_err(Into::into)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_impl().map_err(Into::into)
        }
    }

    impl io::Seek for Handle {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            self.seek_impl(pos.into()).map_err(Into::into)
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

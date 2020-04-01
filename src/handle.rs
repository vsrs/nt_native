use core::{mem, ptr};

use ntapi::ntioapi::*;
use ntapi::ntobapi::*;
use winapi::shared::minwindef::MAX_PATH;
use winapi::um::winioctl::FILE_DEVICE_FILE_SYSTEM;
use winapi::shared::ntdef::{
    InitializeObjectAttributes, FALSE, HANDLE, LARGE_INTEGER, NTSTATUS, NT_SUCCESS, OBJECT_ATTRIBUTES, PLARGE_INTEGER,
    PVOID, ULONG,
};
use winapi::shared::ntstatus::{STATUS_END_OF_FILE, STATUS_PENDING};

use crate::{*, unsafe_tools::*};

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct Handle(HANDLE);

unsafe impl Sync for Handle {}
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        let _res = self.close();
        debug_assert!(_res.is_ok())
    }
}

impl Handle {
    pub const fn invalid() -> Handle {
        Handle(0 as HANDLE)
    }

    /// Takes ownership of the raw OS handle
    pub const fn new(handle: HANDLE) -> Handle {
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

    /// Returns full object name.
    /// For files it would be something like `\Device\HarddiskVolume3\RootDir\Dir\file.ext`
    ///
    /// Warning: this call uses well-known, but **Undocumented** structure!
    pub fn object_name(&self) -> Result<NtString> {
        unsafe {
            let info_size = mem::size_of::<OBJECT_NAME_INFORMATION>();
            let buffer_size = info_size + MAX_PATH * 2;
            let mut buffer = Vec::<u8>::with_capacity(buffer_size);
            buffer.set_len(buffer_size);
            let mut return_len: ULONG = 0;
            let status = NtQueryObject(
                self.0,
                ObjectNameInformation,
                buffer.as_mut_ptr() as PVOID,
                buffer_size as ULONG,
                &mut return_len,
            );
            nt_result!(status, {
                #[allow(clippy::cast_ptr_alignment)]
                let info = &*(buffer.as_ptr() as *const OBJECT_NAME_INFORMATION);
                NtString::from(&info.Name)
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
            let mut name = NtString::new().to_unicode_string();
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

// unsafe functions
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

    pub unsafe fn ioctl<I: Sized, O: Sized>(&self, code: u32, input: &I) -> Result<O> {
        let mut output = mem::zeroed::<O>();
        let (status, _size) = self.ioctl_raw(code, as_byte_slice(input), as_byte_slice_mut(&mut output));
        nt_result!(status, {
            debug_assert!(_size == core::mem::size_of::<O>());
            output
        })
    }

    pub unsafe fn ioctl_status(&self, code: u32) -> NTSTATUS {
        let (status, _) = self.ioctl_raw(code, &[], &mut []);
        status
    }
    
    pub unsafe fn ioctl_query<T: Sized>(&self, code: u32) -> Result<T> {
        let mut output = mem::zeroed::<T>();
        let (status, _size) = self.ioctl_raw(code, &[], as_byte_slice_mut(&mut output));
        nt_result!(status, {
            debug_assert!(_size == core::mem::size_of::<T>());
            output
        })
    }

    pub unsafe fn ioctl_same_buffer<T: Sized>(&self, code: u32, buffer: &mut T) -> Result<()> {
        let len = mem::size_of::<T>() as u32;
        let input = (buffer as *const T) as PVOID;
        let output = (buffer as *mut T) as PVOID;
        
        let (status, _size) = self.ioctl_impl(code, input, len, output, len);
        nt_result!(status, {
            debug_assert!(_size == mem::size_of::<T>());
        })
    }    

    pub unsafe fn ioctl_raw(&self, code: u32, in_buffer: &[u8], mut out_buffer: &mut [u8]) -> (NTSTATUS, usize) {
        self.ioctl_impl(code, in_buffer.safe_ptr() as PVOID, in_buffer.len() as ULONG, out_buffer.safe_mut_ptr() as PVOID, out_buffer.len() as ULONG)
    }
    
    unsafe fn ioctl_impl(&self, code: u32, in_ptr: PVOID, in_len: ULONG, out_ptr: PVOID, out_len: ULONG) -> (NTSTATUS, usize) {
        let fs_io_ctl = (code >> 16) == FILE_DEVICE_FILE_SYSTEM;
        let mut iosb = mem::zeroed::<IO_STATUS_BLOCK>();
    
        let mut status = if fs_io_ctl {
            NtFsControlFile(
                self.0,
                ptr::null_mut(), // Event
                None,            // ApcRoutine
                ptr::null_mut(), // ApcContext
                &mut iosb,       // IoStatusBlock
                code,            // FsControlCode
                in_ptr,          // InputBuffer
                in_len,          // InputBufferLength
                out_ptr,         // OutputBuffer
                out_len,         // OutputBufferLength
            )
        } else {
            NtDeviceIoControlFile(
                self.0,
                ptr::null_mut(), // Event
                None,            // ApcRoutine
                ptr::null_mut(), // ApcContext
                &mut iosb,       // IoStatusBlock
                code,            // IoControlCode
                in_ptr,          // InputBuffer
                in_len,          // InputBufferLength
                out_ptr,         // OutputBuffer
                out_len,         // OutputBufferLength
            )
        };
    
        status = self.wait_for_pending(status, &iosb);
        (status, iosb.Information as usize)
    }
}

// NT io operations
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

    pub fn write(&self, data: &[u8], pos: Option<u64>) -> Result<usize> {
        unsafe {
            let mut offset: LARGE_INTEGER = mem::zeroed();
            let offset_ptr = match pos {
                Some(p) => {
                    *offset.QuadPart_mut() = p as i64;
                    &mut offset as PLARGE_INTEGER
                }
                None => ptr::null_mut(),
            };

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

    pub fn read(&self, mut buffer: &mut [u8], pos: Option<u64>) -> Result<usize> {
        unsafe {
            let mut offset: LARGE_INTEGER = mem::zeroed();
            let offset_ptr = match pos {
                Some(p) => {
                    *offset.QuadPart_mut() = p as i64;
                    &mut offset as PLARGE_INTEGER
                }
                None => ptr::null_mut(),
            };

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
            match status {
                STATUS_END_OF_FILE => Ok(0),
                s => nt_result!(s, iosb.Information as usize),
            }
        }
    }

    pub fn flush(&self) -> Result<()> {
        unsafe {
            let mut iosb = mem::zeroed::<IO_STATUS_BLOCK>();
            let status = NtFlushBuffersFile(self.0, &mut iosb);
            nt_result!(status, ())
        }
    }

    pub fn seek(&self, pos: u64) -> Result<u64> {
        unsafe {
            let mut info: FILE_POSITION_INFORMATION = mem::zeroed();
            *info.CurrentByteOffset.QuadPart_mut() = pos as i64;

            self.set_info(FilePositionInformation, &info)?;
        }

        Ok(pos as u64)
    }

}

#[cfg(feature = "std")]
mod std_impl {
    use super::*;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};

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
            Handle::read(self, buf, None).map_err(Into::into)
        }
    }

    impl io::Write for Handle {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Handle::write(self, buf, None).map_err(Into::into)
        }

        fn flush(&mut self) -> io::Result<()> {
            Handle::flush(self).map_err(Into::into)
        }
    }
}

#[cfg(feature = "std")]
pub use std_impl::*;

use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_OBJECT_NAME_COLLISION};


#[derive(Eq, PartialEq)]
pub struct Error(NTSTATUS);

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

pub const OBJECT_NOT_FOUND : Error = Error(STATUS_OBJECT_NAME_NOT_FOUND);
pub const PATH_NOT_FOUND : Error = Error(STATUS_OBJECT_PATH_NOT_FOUND);
pub const ALREADY_EXISTS : Error = Error(STATUS_OBJECT_NAME_COLLISION);

impl From<NTSTATUS> for crate::Error {
    fn from(status: NTSTATUS) -> Self {
        Error(status)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (self as &dyn core::fmt::Debug).fmt(f)
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "NTSTATUS: 0x{:X}", &self.0)
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match nt_status_to_string(self.0 as u32) {
            Some(s) => write!(f, "NTSTATUS 0x{:X}, {}", &self.0, s),
            None => write!(f, "NTSTATUS 0x{:X}", &self.0)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        Self::new(std::io::ErrorKind::Other, e)
    }
}

#[cfg(feature = "std")]
pub fn nt_status_to_string(code: u32) -> Option<std::string::String> {
    use core::ptr;
    use winapi::shared::ntdef::{CHAR, LPSTR, PVOID};
    use winapi::shared::minwindef::HLOCAL;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::winbase::{
        FormatMessageA, LocalFree, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    unsafe {
        let mut buffer: LPSTR = ptr::null_mut();
        let nt_dll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const i8);
        let len = FormatMessageA(
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            nt_dll as PVOID,
            code,
            0,
            (&mut buffer as *mut LPSTR) as LPSTR,
            0,
            ptr::null_mut(),
        );

        if len == 0 {
            return None;
        }

        let mut len = len as isize;
        if len > 2 && *buffer.offset(len - 2) == ('\r' as CHAR) && *buffer.offset(len - 1) == ('\n' as CHAR) {
            len -= 2;
        }

        if len > 1 && *buffer.offset(len - 1) == ('.' as CHAR) {
            len -= 1;
        }

        let chars = std::slice::from_raw_parts(buffer as *const u8, len as usize);
        let result = std::string::String::from_utf8_lossy(chars).into_owned();

        LocalFree(buffer as HLOCAL);

        Some(result.replace("\r\n", " "))
    }
}
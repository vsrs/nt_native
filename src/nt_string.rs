use crate::*;
use ntapi::ntrtl::{RtlDosPathNameToNtPathName_U_WithStatus, RtlFreeUnicodeString};
use winapi::shared::ntdef::{PWSTR, UNICODE_STRING};
use winapi::shared::ntstatus::STATUS_SUCCESS;

#[macro_export]
macro_rules! nt_str {
    ($str:tt) => {
        NtString::from(wstr!($str).as_ref())
    };
}
#[macro_export]
macro_rules! nt_str_ref {
    ($str:tt) => {
        &$crate::nt_str!($str)
    };
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct NtString(Vec<u16>);

impl core::ops::Deref for NtString {
    type Target = Vec<u16>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for NtString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NtString {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub unsafe fn from_raw_bytes(ptr: *const u16, len: u32) -> Self {
        let name_bytes: &[u16] = core::slice::from_raw_parts(ptr, len as usize / U16_SIZE);
        Self::from(name_bytes)
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> crate::String {
        crate::String::from_utf16_lossy(&self.0)
    }
}

impl Default for NtString {
    fn default() -> Self {
        Self::new()
    }
}

impl AsByteSlice for NtString {
    unsafe fn as_byte_slice(&self) -> &[u8] {
        self.0.as_byte_slice()
    }
}

pub trait ToUnicodeString {
    /// # Safety
    ///
    /// UNICODE_STRING::Buffer is managed by Self instance.
    unsafe fn to_unicode_string(&self) -> UNICODE_STRING;
}

impl ToUnicodeString for &[u16] {
    unsafe fn to_unicode_string(&self) -> UNICODE_STRING {
        let len = self.len() as u16 * 2;
        UNICODE_STRING {
            Buffer: self.safe_ptr() as *mut _,
            Length: len,
            MaximumLength: len,
        }
    }
}

impl ToUnicodeString for NtString {
    unsafe fn to_unicode_string(&self) -> UNICODE_STRING {
        self.0.as_slice().to_unicode_string()
    }
}

impl From<Vec<u16>> for NtString {
    fn from(data: Vec<u16>) -> Self {
        Self(data)
    }
}

impl From<&[u16]> for NtString {
    fn from(data: &[u16]) -> Self {
        Self::from(data.to_vec())
    }
}

impl From<&str> for NtString {
    fn from(data: &str) -> Self {
        let data: Vec<u16> = data.encode_utf16().collect();
        Self::from(data)
    }
}

impl From<String> for NtString {
    fn from(data: String) -> Self {
        Self::from(data.as_str())
    }
}

impl From<&String> for NtString {
    fn from(data: &String) -> Self {
        Self::from(data.as_str())
    }
}

impl From<&UNICODE_STRING> for NtString {
    fn from(data: &UNICODE_STRING) -> Self {
        let utf16_slice = unsafe { core::slice::from_raw_parts(data.Buffer, data.Length as usize / core::mem::size_of::<u16>()) };
        Self::from(utf16_slice)
    }
}

/// Converts DOS names to NT native format  
///
///  `name` A constant string containing the DOS name of the target file or directory. Should be null-terminated!
///
/// The second element of the resulting tuple indicates whether the name a directory or not.
///
/// # Examples
/// ```rust
/// # #[macro_use] extern crate nt_native;
/// # use nt_native::*;
/// let nt_name = dos_name_to_nt(&nt_str!("c:\\some\\path\\file.ext")).unwrap();
/// assert_eq!(nt_name.0, nt_str!("\\??\\c:\\some\\path\\file.ext"));
/// ```
pub fn dos_name_to_nt(dos_name: &NtString) -> Result<(NtString, bool)> {
    let mut file_part: PWSTR = core::ptr::null_mut();
    let mut data = unsafe {
        let mut raw = core::mem::MaybeUninit::<UNICODE_STRING>::uninit();
        let mut temp: Vec<u16>;
        let dos_name = match dos_name.last() {
            Some(0) => &dos_name.0,
            _ => {
                // not null-terminated
                temp = dos_name.0.clone();
                temp.push(0);
                &temp
            }
        };

        let status =
            RtlDosPathNameToNtPathName_U_WithStatus(dos_name.as_ptr() as PWSTR, raw.as_mut_ptr(), &mut file_part, core::ptr::null_mut());
        if status != STATUS_SUCCESS {
            return Err(crate::Error::from(status));
        }
        raw.assume_init()
    };
    let nt_name = NtString::from(&data);
    unsafe {
        RtlFreeUnicodeString(&mut data);
    }

    Ok((nt_name, file_part.is_null()))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn build_prefix() -> String {
        use std::env;
        let path = &env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned());
        format!("\\??\\{}\\", path)
    }

    #[test]
    fn dos_name_to_nt_file() {
        let prefix = build_prefix();
        let res1 = dos_name_to_nt(nt_str_ref!("dir.name\\file.name")).unwrap();

        assert_eq!(format!("{}dir.name\\file.name", prefix), res1.0.to_string());
        assert_eq!(false, res1.1);

        let res2 = dos_name_to_nt(nt_str_ref!("\\??\\c:\\temp")).unwrap();
        assert_eq!("\\??\\c:\\temp", res2.0.to_string());
        assert_eq!(false, res2.1);
    }

    #[test]
    fn dos_name_to_nt_dir() {
        let prefix = build_prefix();
        let res1 = dos_name_to_nt(nt_str_ref!("dir.name\\")).unwrap();

        assert_eq!(format!("{}dir.name\\", prefix), res1.0.to_string());
        assert_eq!(true, res1.1);

        let res2 = dos_name_to_nt(nt_str_ref!("\\??\\x:\\some_folder\\")).unwrap();
        assert_eq!("\\??\\x:\\some_folder\\", res2.0.to_string());
        assert_eq!(true, res2.1);
    }

    #[test]
    fn dos_name_to_nt_slash() {
        let prefix = build_prefix();
        let res1 = dos_name_to_nt(nt_str_ref!("some/path/with/dir.name/file.name")).unwrap();

        assert_eq!(format!("{}some\\path\\with\\dir.name\\file.name", prefix), res1.0.to_string());
        assert_eq!(false, res1.1);
    }

    #[test]
    fn dos_name_to_nt_slash_not_changed_for_absolute() {
        let res1 = dos_name_to_nt(nt_str_ref!("\\??\\x:/some/path/dir.name/file.name")).unwrap();
        assert_eq!("\\??\\x:/some/path/dir.name/file.name", res1.0.to_string());
        assert_eq!(false, res1.1);

        let res2 = dos_name_to_nt(nt_str_ref!("\\??\\x:/some/path/dir.name/")).unwrap();
        assert_eq!("\\??\\x:/some/path/dir.name/", res2.0.to_string());
        assert_eq!(false, res2.1); // but it is folder
    }

    #[test]
    fn dos_name_empty() {
        let err = dos_name_to_nt(nt_str_ref!("")).unwrap_err();
        assert_eq!(err.ntstatus(), winapi::shared::ntstatus::STATUS_OBJECT_NAME_INVALID);
    }

    #[test]
    fn physical_drive_name() {
        let (name, is_dir) = dos_name_to_nt(nt_str_ref!("\\\\.\\PhysicalDrive0")).unwrap();
        assert_eq!(&name.to_string(), "\\??\\PhysicalDrive0");
        assert_eq!(is_dir, false);
    }
}

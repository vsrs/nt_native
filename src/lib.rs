#![cfg_attr(not(feature = "std"), no_std)]
#![cfg(windows)]

#[cfg(not(any(feature = "user", feature = "kernel")))]
compile_error!("Either feature 'user' or 'kernel' must be enabled: Link to `ntdll` or 'ntoskrnl' respectively");

#[cfg(all(feature = "std", feature = "kernel"))]
compile_error!("'std' support is anawailable for 'kernel'");

#[cfg(all(feature = "user", feature = "kernel"))]
compile_error!("Only one feature 'user' or 'kernel' must be enabled: Link to `ntdll` or 'ntoskrnl' respectively");

#[macro_use]
extern crate bitflags;

#[macro_use]
#[allow(unused_imports)]
extern crate wstr;

#[doc(hidden)]
pub use wstr::{wstr, wstr_impl}; // Just the macros needed.

#[cfg(not(feature = "std"))]
extern crate alloc as std;
pub(crate) use std::collections::BTreeMap;
pub(crate) use std::string::String;
pub(crate) use std::vec::Vec;

pub(crate) use core::option::Option;

#[macro_export]
macro_rules! nt_result {
    ($status:ident, $value:expr ) => {
        if winapi::shared::ntdef::NT_SUCCESS($status) {
            Ok($value)
        } else {
            Err(crate::Error::from($status))
        }
    };

    ($status:ident) => {
        if winapi::shared::ntdef::NT_SUCCESS($status) {
            Ok(())
        } else {
            Err(crate::Error::from($status))
        }
    };
}

#[macro_use]
mod nt_string;
pub use nt_string::*;

pub mod error;
pub use error::Error;

mod traits;
pub use traits::*;

mod new_handle;
pub use new_handle::*;

mod handle;
pub use handle::*;

mod file;
pub use file::*;

mod mount_manager;
pub use mount_manager::*;

mod volume;
pub use volume::*;

pub type Result<T> = core::result::Result<T, Error>;

// TODO: Maybe move to a separate crate? The same code would be useful in similar linux\macos implementations.
pub(crate) use unsafe_tools::*;
mod unsafe_tools {
    use crate::*;
    pub trait NullSafePtr<T: Sized> {
        fn safe_ptr(&self) -> *const T;
    }

    pub trait NullSafeMutPtr<T: Sized> {
        fn safe_mut_ptr(&mut self) -> *mut T;
    }

    impl<T: Sized> NullSafePtr<T> for &[T] {
        fn safe_ptr(&self) -> *const T {
            if self.is_empty() {
                core::ptr::null()
            } else {
                self.as_ptr()
            }
        }
    }

    impl<T: Sized> NullSafeMutPtr<T> for &mut [T] {
        fn safe_mut_ptr(&mut self) -> *mut T {
            if self.is_empty() {
                core::ptr::null_mut()
            } else {
                self.as_mut_ptr()
            }
        }
    }

    impl<T: Sized> NullSafePtr<T> for Vec<T> {
        fn safe_ptr(&self) -> *const T {
            self.as_slice().safe_ptr()
        }
    }

    impl NullSafePtr<u8> for str {
        fn safe_ptr(&self) -> *const u8 {
            self.as_bytes().safe_ptr()
        }
    }

    pub unsafe fn as_byte_slice<T: Sized>(p: &T) -> &[u8] {
        core::slice::from_raw_parts((p as *const T) as *const u8, core::mem::size_of::<T>())
    }

    pub unsafe fn as_byte_slice_mut<T: Sized>(p: &mut T) -> &mut [u8] {
        core::slice::from_raw_parts_mut((p as *mut T) as *mut u8, core::mem::size_of::<T>())
    }

    #[allow(dead_code)]
    pub unsafe fn alloc_buffer(size: usize) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(size);
        buffer.set_len(size);
        buffer
    }
}

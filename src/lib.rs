#![cfg_attr(not(feature = "std"), no_std)]
#![cfg(windows)]

#[cfg(not(any(feature = "user", feature = "kernel")))]
compile_error!("Either feature 'user' or 'kernel' must be enabled: Link to `ntdll` or 'ntoskrnl' respectively");

#[cfg(all(feature = "std", feature = "kernel"))]
compile_error!("'std' support is unawailable for 'kernel'");

#[cfg(all(feature = "user", feature = "kernel"))]
compile_error!("Only one feature 'user' or 'kernel' must be enabled: Link to `ntdll` or 'ntoskrnl' respectively");

#[macro_use]
extern crate bitflags;

#[macro_use]
#[allow(unused_imports)]
extern crate wstr;

#[doc(hidden)]
pub use wstr::{wstr, wstr_impl}; // Just the macros needed.

pub(crate) use rdisk_shared::{xstd::*, *};

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

mod disk;
pub use disk::*;

mod ioctl;

pub type Result<T> = core::result::Result<T, Error>;

pub(crate) const U16_SIZE: usize = core::mem::size_of::<u16>();

#[inline]
#[allow(non_snake_case)]
pub(crate) const fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

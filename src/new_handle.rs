use core::mem;

use ntapi::ntioapi::{
    NtCreateFile, FILE_COMPLETE_IF_OPLOCKED, FILE_CREATE, FILE_CREATE_TREE_CONNECTION, FILE_DELETE_ON_CLOSE,
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_NO_EA_KNOWLEDGE, FILE_NO_INTERMEDIATE_BUFFERING, FILE_OPEN,
    FILE_OPENED, FILE_OPEN_BY_FILE_ID, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
    FILE_OPEN_REQUIRING_OPLOCK, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_OVERWRITTEN, FILE_RANDOM_ACCESS,
    FILE_RESERVE_OPFILTER, FILE_SEQUENTIAL_ONLY, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_ALERT,
    FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH, IO_STATUS_BLOCK,
};
use ntapi::ntobapi::OBJ_INHERIT;
use winapi::shared::ntdef::{
    InitializeObjectAttributes, HANDLE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, OBJ_EXCLUSIVE,
    OBJ_FORCE_ACCESS_CHECK, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, OBJ_KERNEL_HANDLE, OBJ_OPENIF, OBJ_OPENLINK,
    OBJ_PERMANENT, OBJ_VALID_ATTRIBUTES, PLARGE_INTEGER, PVOID,
};
use winapi::um::winnt::{
    FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_EA, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
    FILE_ATTRIBUTE_NO_SCRUB_DATA, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_PINNED, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_UNPINNED,
    FILE_ATTRIBUTE_VIRTUAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, PSECURITY_DESCRIPTOR, READ_CONTROL, SECURITY_DESCRIPTOR, SYNCHRONIZE, WRITE_DAC,
    WRITE_OWNER,
};

use crate::{Handle, NtString, NullSafePtr, Result};

bitflags! {
    /// Wrapper around [File Access Rights Constants](https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants)
    pub struct Access: u32 {
        const DELETE = winapi::um::winnt::DELETE;

        const READ_DATA       = FILE_READ_DATA;
        const READ_ATTRIBUTES = FILE_READ_ATTRIBUTES;
        const READ_EA         = FILE_READ_EA;
        const READ_CONTROL    = READ_CONTROL;

        const WRITE_DATA       = FILE_WRITE_DATA;
        const WRITE_ATTRIBUTES = FILE_WRITE_ATTRIBUTES;
        const WRITE_EA         = FILE_WRITE_EA;
        const WRITE_DAC        = WRITE_DAC;
        const WRITE_OWNER      = WRITE_OWNER;
        const APPEND_DATA      = FILE_APPEND_DATA;
        const SYNCHRONIZE      = SYNCHRONIZE;

        // Directory specials
        const LIST_DIR = FILE_LIST_DIRECTORY;
        const ADD_FILE = FILE_ADD_FILE;
        const ADD_DIR  = FILE_ADD_SUBDIRECTORY;

        // GENERIC
        const GENERIC_READ  = FILE_GENERIC_READ;
        const GENERIC_WRITE = FILE_GENERIC_WRITE;
    }
}

impl Default for Access {
    fn default() -> Access {
        Access::GENERIC_READ | Access::GENERIC_WRITE
    }
}

bitflags! {
    pub struct Attribute: u32 {
        const INHERIT                         = OBJ_INHERIT;
        const PERMANENT                       = OBJ_PERMANENT;
        const EXCLUSIVE                       = OBJ_EXCLUSIVE;
        const CASE_INSENSITIVE                = OBJ_CASE_INSENSITIVE;
        const OPENIF                          = OBJ_OPENIF;
        const OPENLINK                        = OBJ_OPENLINK;
        const KERNEL_HANDLE                   = OBJ_KERNEL_HANDLE;
        const FORCE_ACCESS_CHECK              = OBJ_FORCE_ACCESS_CHECK;
        const IGNORE_IMPERSONATED_DEVICEMAP   = OBJ_IGNORE_IMPERSONATED_DEVICEMAP;
        const DONT_REPARSE                    = OBJ_DONT_REPARSE;
        const VALID_ATTRIBUTES                = OBJ_VALID_ATTRIBUTES;
    }
}

impl Default for Attribute {
    fn default() -> Attribute {
        Attribute::CASE_INSENSITIVE
    }
}

bitflags! {
    /// Wrapper around [File Attribute Constants](https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants)
    pub struct FileAttribute: u32 {
        const READONLY              = FILE_ATTRIBUTE_READONLY;
        const HIDDEN                = FILE_ATTRIBUTE_HIDDEN;
        const SYSTEM                = FILE_ATTRIBUTE_SYSTEM;
        const DIRECTORY             = FILE_ATTRIBUTE_DIRECTORY;
        const ARCHIVE               = FILE_ATTRIBUTE_ARCHIVE;
        const DEVICE                = FILE_ATTRIBUTE_DEVICE;
        const NORMAL                = FILE_ATTRIBUTE_NORMAL;
        const TEMPORARY             = FILE_ATTRIBUTE_TEMPORARY;
        const SPARSE_FILE           = FILE_ATTRIBUTE_SPARSE_FILE;
        const REPARSE_POINT         = FILE_ATTRIBUTE_REPARSE_POINT;
        const COMPRESSED            = FILE_ATTRIBUTE_COMPRESSED;
        const OFFLINE               = FILE_ATTRIBUTE_OFFLINE;
        const NOT_CONTENT_INDEXED   = FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        const ENCRYPTED             = FILE_ATTRIBUTE_ENCRYPTED;
        const INTEGRITY_STREAM      = FILE_ATTRIBUTE_INTEGRITY_STREAM;
        const VIRTUAL               = FILE_ATTRIBUTE_VIRTUAL;
        const NO_SCRUB_DATA         = FILE_ATTRIBUTE_NO_SCRUB_DATA;
        const EA                    = FILE_ATTRIBUTE_EA;
        const PINNED                = FILE_ATTRIBUTE_PINNED;
        const UNPINNED              = FILE_ATTRIBUTE_UNPINNED;
        const RECALL_ON_OPEN        = FILE_ATTRIBUTE_RECALL_ON_OPEN;
        const RECALL_ON_DATA_ACCESS = FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    }
}

impl Default for FileAttribute {
    fn default() -> FileAttribute {
        FileAttribute::NORMAL
    }
}

bitflags! {
    pub struct ShareAccess: u32 {
        const READ   = FILE_SHARE_READ;
        const WRITE  = FILE_SHARE_WRITE;
        const DELETE = FILE_SHARE_DELETE;
    }
}

impl Default for ShareAccess {
    fn default() -> ShareAccess {
        ShareAccess::READ | ShareAccess::WRITE
    }
}

pub struct SecurityDescriptor(SECURITY_DESCRIPTOR);

pub enum CreateDisposition {
    /// If the file already exists, replace it with the given file.
    /// If it does not, create the given file.
    Supersede,

    /// If the file already exists, fail the request and do not create or open the given file.
    /// If it does not, create the given file.
    Create,

    /// If the file already exists, open it instead of creating a new file.
    /// If it does not, fail the request and do not create a new file.
    Open,

    /// If the file already exists, open it.
    /// If it does not, create the given file.
    OpenOrCreate,

    /// If the file already exists, open it and overwrite it.
    /// If it does not, fail the request.
    Overwrite,

    /// If the file already exists, open it and overwrite it.
    /// If it does not, create the given file.
    OverwriteOrCreate,
}

impl CreateDisposition {
    pub fn to_u32(&self) -> u32 {
        match self {
            CreateDisposition::Supersede => FILE_SUPERSEDE,
            CreateDisposition::Create => FILE_CREATE,
            CreateDisposition::Open => FILE_OPEN,
            CreateDisposition::OpenOrCreate => FILE_OPEN_IF,
            CreateDisposition::Overwrite => FILE_OVERWRITE,
            CreateDisposition::OverwriteOrCreate => FILE_OVERWRITE_IF,
        }
    }
}

bitflags! {
    pub struct Options: u32 {
        const DIRECTORY              = FILE_DIRECTORY_FILE;
        const NON_DIRECTORY          = FILE_NON_DIRECTORY_FILE;
        const WRITE_THROUGH          = FILE_WRITE_THROUGH;
        const SEQUENTIAL_ONLY        = FILE_SEQUENTIAL_ONLY;
        const RANDOM_ACCESS          = FILE_RANDOM_ACCESS;
        const NO_BUFFERING           = FILE_NO_INTERMEDIATE_BUFFERING;
        const SYNC_ALERT             = FILE_SYNCHRONOUS_IO_ALERT;
        const SYNC_NONALERT          = FILE_SYNCHRONOUS_IO_NONALERT;
        const CREATE_TREE_CONNECTION = FILE_CREATE_TREE_CONNECTION;
        const NO_EA_KNOWLEDGE        = FILE_NO_EA_KNOWLEDGE;
        const OPEN_REPARSE_POINT     = FILE_OPEN_REPARSE_POINT;
        const DELETE_ON_CLOSE        = FILE_DELETE_ON_CLOSE;
        const OPEN_BY_FILE_ID        = FILE_OPEN_BY_FILE_ID;
        const OPEN_FOR_BACKUP        = FILE_OPEN_FOR_BACKUP_INTENT;
        const RESERVE_OPFILTER       = FILE_RESERVE_OPFILTER;
        const OPEN_REQUIRING_OPLOCK  = FILE_OPEN_REQUIRING_OPLOCK;
        const COMPLETE_IF_OPLOCKED   = FILE_COMPLETE_IF_OPLOCKED;
    }
}

impl Default for Options {
    fn default() -> Options {
        // FILE_SYNCHRONOUS_IO_NONALERT is almost always mandatory!
        // see https://github.com/reactos/reactos/blob/893a3c9d030fd8b078cbd747eeefd3f6ce57e560/dll/win32/kernel32/client/file/create.c#L128
        Options::SYNC_NONALERT
    }
}

pub struct NewHandle {
    pub access: Access,
    pub attributes: Attribute,
    pub security_descriptor: Option<SecurityDescriptor>,
    pub root: Option<Handle>,
    pub allocation_size: u64,
    pub file_attributes: FileAttribute,
    pub share_access: ShareAccess,
    pub create_disposition: CreateDisposition,
    pub options: Options,
    pub ea: std::vec::Vec<u8>,
}

impl Default for NewHandle {
    fn default() -> Self {
        Self {
            access: Access::default(),
            attributes: Attribute::default(),
            security_descriptor: None,
            root: None,
            allocation_size: 0,
            file_attributes: FileAttribute::default(),
            share_access: ShareAccess::default(),
            create_disposition: CreateDisposition::OpenOrCreate,
            options: Options::default(),
            ea: std::vec::Vec::new(),
        }
    }
}

// public API
impl NewHandle {
    pub fn with_cd(create_disposition: CreateDisposition) -> Self {
        Self {
            create_disposition,
            ..Self::default()
        }
    }

    pub fn create_new(name: &NtString) -> Result<Handle> {
        let (handle, _) = Self::with_cd(CreateDisposition::Create).build(name)?;
        Ok(handle)
    }

    pub fn open(name: &NtString) -> Result<Handle> {
        let (handle, _) = Self::with_cd(CreateDisposition::Open).build(name)?;
        Ok(handle)
    }

    pub fn open_readonly(name: &NtString) -> Result<Handle> {
        let (handle, _) = Self::with_cd(CreateDisposition::Open).build(name)?;

        Ok(handle)
    }

    pub fn open_or_create(name: &NtString) -> Result<(Handle, bool)> {
        Self::with_cd(CreateDisposition::OpenOrCreate).build(name)
    }

    pub fn owerwrite(name: &NtString) -> Result<Handle> {
        let (handle, _) = Self::with_cd(CreateDisposition::Overwrite).build(name)?;
        Ok(handle)
    }

    pub fn owerwrite_or_create(name: &NtString) -> Result<(Handle, bool)> {
        Self::with_cd(CreateDisposition::OverwriteOrCreate).build(name)
    }

    pub fn build(self, dos_name: &NtString) -> Result<(Handle, bool)> {
        let (nt_name, this) = self.auto_options(dos_name)?;

        this.build_nt(&nt_name)
    }

    pub fn build_nt(mut self, nt_name: &NtString) -> Result<(Handle, bool)> {
        if self.options.contains(Options::DELETE_ON_CLOSE) {
            self.access |= Access::DELETE;
        }

        let root: HANDLE = match &self.root {
            None => core::ptr::null_mut(),
            Some(r) => r.as_raw(),
        };

        let security_descriptor: PSECURITY_DESCRIPTOR = match &self.security_descriptor {
            None => core::ptr::null_mut(),
            Some(sd) => &sd.0 as *const _ as PSECURITY_DESCRIPTOR,
        };

        unsafe {
            let mut oa = mem::zeroed();
            let mut unicode_str = nt_name.as_unicode_string();
            InitializeObjectAttributes(
                &mut oa,
                &mut unicode_str,
                self.attributes.bits,
                root,
                security_descriptor,
            );

            let mut raw: HANDLE = mem::zeroed();
            let mut iosb: IO_STATUS_BLOCK = mem::zeroed();
            let status = NtCreateFile(
                &mut raw,
                self.access.bits,
                &mut oa,
                &mut iosb,
                self.allocation_size_ptr(),
                self.file_attributes.bits,
                self.share_access.bits,
                self.create_disposition.to_u32(),
                self.options.bits,
                self.ea.safe_ptr() as PVOID,
                self.ea.len() as u32,
            );

            nt_result!(status, {
                let already_exists = match self.create_disposition {
                    CreateDisposition::OpenOrCreate => iosb.Information == (FILE_OPENED as usize),
                    CreateDisposition::OverwriteOrCreate => iosb.Information == (FILE_OVERWRITTEN as usize),
                    _ => false,
                };

                (Handle::new(raw), already_exists)
            })
        }
    }
}

// internals
impl NewHandle {
    pub(crate) fn auto_options(mut self, dos_name: &NtString) -> Result<(NtString, Self)> {
        let (nt_name, is_dir) = super::dos_name_to_nt(dos_name)?;
        if !self.options.contains(Options::DIRECTORY) && !self.options.contains(Options::NON_DIRECTORY) {
            // autodetect only if not set manually
            if is_dir {
                self.options.remove(Options::NON_DIRECTORY);
                self.options |= Options::DIRECTORY;
            } else {
                self.options.remove(Options::DIRECTORY);
                self.options |= Options::NON_DIRECTORY;
            }
        }

        Ok((nt_name, self))
    }

    unsafe fn allocation_size_ptr(&self) -> PLARGE_INTEGER {
        match self.allocation_size {
            0 => core::ptr::null_mut(),
            _ => &self.allocation_size as *const _ as PLARGE_INTEGER,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_smoke() {
        let read = Access::GENERIC_READ;
        assert!(read.contains(Access::READ_CONTROL));
        assert!(read.contains(Access::READ_DATA));
        assert!(read.contains(Access::READ_ATTRIBUTES));
        assert!(read.contains(Access::READ_EA));
        assert!(read.contains(Access::SYNCHRONIZE));

        let access = Access::READ_CONTROL
            | Access::WRITE_DATA
            | Access::WRITE_ATTRIBUTES
            | Access::WRITE_EA
            | Access::APPEND_DATA
            | Access::SYNCHRONIZE;
        assert_eq!(access, Access::GENERIC_WRITE);

        let def = Access::default();
        assert!(def.contains(Access::WRITE_DATA));
        assert!(def.contains(Access::WRITE_ATTRIBUTES));
        assert!(def.contains(Access::READ_ATTRIBUTES));
        assert!(def.contains(Access::READ_DATA));
    }

    #[test]
    fn auto_options() {
        let (_, builder) = NewHandle::default()
            .auto_options(&nt_str!("dir.name/file.name"))
            .unwrap();
        assert!(builder.options.contains(Options::NON_DIRECTORY)); // autodetected by name

        let (_, builder) = NewHandle::default().auto_options(&nt_str!("dir.name/")).unwrap();
        assert!(builder.options.contains(Options::DIRECTORY)); // autodetected by name

        let (_, builder) = NewHandle {
            options: Options::NON_DIRECTORY,
            ..Default::default()
        }
        .auto_options(&nt_str!("dir.name/"))
        .unwrap();
        assert!(builder.options.contains(Options::NON_DIRECTORY)); // name ignored!

        let (_, builder) = NewHandle {
            options: Options::DIRECTORY,
            ..Default::default()
        }
        .auto_options(&nt_str!("dir.name/file.name"))
        .unwrap();
        assert!(builder.options.contains(Options::DIRECTORY)); // name ignored!
    }
}

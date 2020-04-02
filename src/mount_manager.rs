use crate::*;
use core::mem;
use winapi::shared::ntdef::USHORT;
use winapi::shared::ntstatus::{STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct MountManager(Handle);

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct MountPoint {
    pub id: Vec<u8>,
    pub device_name: NtString,
    pub dos_name: NtString,
    pub guid_name: NtString,
}

pub fn is_dos_volume_name(name: &[u16]) -> bool {
    name.len() == 14
        && name[0] == ('\\' as u16)
        && name[1] == ('D' as u16)
        && name[2] == ('o' as u16)
        && name[3] == ('s' as u16)
        && name[4] == ('D' as u16)
        && name[5] == ('e' as u16)
        && name[6] == ('v' as u16)
        && name[7] == ('i' as u16)
        && name[8] == ('c' as u16)
        && name[9] == ('e' as u16)
        && name[10] == ('s' as u16)
        && name[11] == ('\\' as u16)
        && name[12] >= ('A' as u16)
        && name[12] <= ('Z' as u16)
        && name[13] == (':' as u16)
}

pub fn is_guid_volume_name(name: &[u16]) -> bool {
    (name.len() == 48 || name.len() == 49 && name[24] == ('\\' as u16))
        && name[0] == ('\\' as u16)
        && (name[1] == ('?' as u16) || name[1] == ('\\' as u16))
        && name[2] == ('?' as u16)
        && name[3] == ('\\' as u16)
        && name[4] == ('V' as u16)
        && name[5] == ('o' as u16)
        && name[6] == ('l' as u16)
        && name[7] == ('u' as u16)
        && name[8] == ('m' as u16)
        && name[9] == ('e' as u16)
        && name[10] == ('{' as u16)
        && name[19] == ('-' as u16)
        && name[24] == ('-' as u16)
        && name[29] == ('-' as u16)
        && name[34] == ('-' as u16)
        && name[47] == ('}' as u16)
}

impl MountPoint {
    fn new(id: &[u8]) -> Self {
        Self {
            id: id.to_vec(),
            device_name: NtString::default(),
            dos_name: NtString::default(),
            guid_name: NtString::default(),
        }
    }

    fn add_device_name(&mut self, name: &[u16]) {
        if self.device_name.is_empty() {
            self.device_name = NtString::from(name);
        }
    }

    fn add_link_name(&mut self, name: &[u16]) {
        if self.dos_name.is_empty() && is_dos_volume_name(&name) {
            self.dos_name = NtString::from(name);
        } else if self.guid_name.is_empty() {
            debug_assert!(is_guid_volume_name(name));
            self.guid_name = NtString::from(name)
        }
    }
}

#[allow(bad_style)]
#[allow(dead_code)]
#[cfg_attr(rustfmt, rustfmt_skip)]
mod mountmgr {
    use winapi::shared::minwindef::{DWORD, ULONG, USHORT};
    use winapi::shared::ntdef::WCHAR;
    use winapi::um::winioctl::{FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_WRITE_ACCESS, METHOD_BUFFERED};
    use winapi::STRUCT;

    pub static DEVICE_NAME: &[u16] = wstr!("\\??\\MountPointManager");

    pub const MOUNTMGRCONTROLTYPE: DWORD = 0x0000_006D; // 'm'
    pub const MOUNTDEVCONTROLTYPE: DWORD = 0x0000_004D; // 'M'

    #[inline]
    // winapi::um::winioctl::CTL_CODE is not const!
    pub(crate) const fn CTL_CODE(DeviceType: DWORD, Function: DWORD, Method: DWORD, Access: DWORD) -> DWORD {
        (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    }

    pub const IOCTL_MOUNTMGR_CREATE_POINT: DWORD                = CTL_CODE(MOUNTMGRCONTROLTYPE, 0, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_DELETE_POINTS: DWORD               = CTL_CODE(MOUNTMGRCONTROLTYPE, 1, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_QUERY_POINTS: DWORD                = CTL_CODE(MOUNTMGRCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_MOUNTMGR_DELETE_POINTS_DBONLY: DWORD        = CTL_CODE(MOUNTMGRCONTROLTYPE, 3, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER: DWORD           = CTL_CODE(MOUNTMGRCONTROLTYPE, 4, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_AUTO_DL_ASSIGNMENTS: DWORD         = CTL_CODE(MOUNTMGRCONTROLTYPE, 5, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_CREATED: DWORD  = CTL_CODE(MOUNTMGRCONTROLTYPE, 6, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_VOLUME_MOUNT_POINT_DELETED: DWORD  = CTL_CODE(MOUNTMGRCONTROLTYPE, 7, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_CHANGE_NOTIFY: DWORD               = CTL_CODE(MOUNTMGRCONTROLTYPE, 8, METHOD_BUFFERED, FILE_READ_ACCESS);
    pub const IOCTL_MOUNTMGR_KEEP_LINKS_WHEN_OFFLINE: DWORD     = CTL_CODE(MOUNTMGRCONTROLTYPE, 9, METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);
    pub const IOCTL_MOUNTMGR_CHECK_UNPROCESSED_VOLUMES: DWORD   = CTL_CODE(MOUNTMGRCONTROLTYPE,10, METHOD_BUFFERED, FILE_READ_ACCESS);
    pub const IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION: DWORD = CTL_CODE(MOUNTMGRCONTROLTYPE,11, METHOD_BUFFERED, FILE_READ_ACCESS);

    // NTDDI_WINXP
    pub const IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH: DWORD  = CTL_CODE(MOUNTMGRCONTROLTYPE,12, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS: DWORD = CTL_CODE(MOUNTMGRCONTROLTYPE,13, METHOD_BUFFERED, FILE_ANY_ACCESS);

    // NTDDI_WS03
    pub const IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT: DWORD = CTL_CODE(MOUNTMGRCONTROLTYPE, 15, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_MOUNTMGR_SET_AUTO_MOUNT: DWORD   = CTL_CODE(MOUNTMGRCONTROLTYPE,16,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS);

    STRUCT! { struct MOUNTMGR_MOUNT_POINT {
        SymbolicLinkNameOffset: ULONG,
        SymbolicLinkNameLength: USHORT,
        UniqueIdOffset: ULONG,
        UniqueIdLength: USHORT,
        DeviceNameOffset: ULONG,
        DeviceNameLength: USHORT,
    }}

    STRUCT! { struct MOUNTMGR_MOUNT_POINTS {
        Size: ULONG,
        NumberOfMountPoints: ULONG,
        MountPoints: [MOUNTMGR_MOUNT_POINT; 1],
    }}

    STRUCT!{ struct MOUNTMGR_TARGET_NAME {
        DeviceNameLength: USHORT,
        DeviceName: [WCHAR; 1],
    }}

    STRUCT!{ struct MOUNTMGR_VOLUME_PATHS {
        MultiSzLength: ULONG,
        MultiSz: [WCHAR; 1],
    }}
}

impl MountManager {
    pub fn open() -> Result<Self> {
        let (handle, _) = NewHandle {
            access: Access::GENERIC_READ | Access::GENERIC_WRITE,
            share_access: ShareAccess::READ | ShareAccess::WRITE,
            create_disposition: CreateDisposition::Open,
            file_attributes: FileAttribute::NORMAL,
            ..NewHandle::default()
        }
        .build_nt(&mountmgr::DEVICE_NAME)?;

        Ok(Self(handle))
    }

    pub fn open_readonly() -> Result<Self> {
        let (handle, _) = NewHandle {
            access: Access::READ_ATTRIBUTES | Access::SYNCHRONIZE,
            share_access: ShareAccess::READ | ShareAccess::WRITE,
            create_disposition: CreateDisposition::Open,
            file_attributes: FileAttribute::NORMAL,
            ..NewHandle::default()
        }
        .build_nt(&mountmgr::DEVICE_NAME)?;

        Ok(Self(handle))
    }

    pub fn path_names(&self, device_name: &NtString) -> Result<Vec<NtString>> {
        const TN_SIZE: usize = mem::size_of::<mountmgr::MOUNTMGR_TARGET_NAME>();
        const U16_SIZE: usize = mem::size_of::<u16>();

        let name_bytes_size = device_name.len() * U16_SIZE;
        let input_size = TN_SIZE - U16_SIZE + name_bytes_size;
        unsafe {
            let mut input_buffer = alloc_buffer(input_size);
            #[allow(clippy::cast_ptr_alignment)]
            let spec = &mut *(input_buffer.as_mut_ptr() as *mut mountmgr::MOUNTMGR_TARGET_NAME);
            spec.DeviceNameLength = name_bytes_size as USHORT;
            let destination: &mut [u8] =
                core::slice::from_raw_parts_mut(spec.DeviceName.as_mut_ptr() as *mut _, name_bytes_size);
            let name_bytes: &[u8] = core::slice::from_raw_parts(device_name.as_ptr() as *mut _, name_bytes_size);
            destination.copy_from_slice(name_bytes);

            let out_buffer = self.ioctl(mountmgr::IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS, &input_buffer)?;
            #[allow(clippy::cast_ptr_alignment)]
            let raw_paths = &*(out_buffer.as_ptr() as *const mountmgr::MOUNTMGR_VOLUME_PATHS);
            let paths_slice: &[u16] =
                core::slice::from_raw_parts(raw_paths.MultiSz.as_ptr(), raw_paths.MultiSzLength as usize / U16_SIZE);
            let mut result = Vec::new();
            for path in paths_slice.split(|ch| ch == &0).filter(|p| !p.is_empty()) {
                result.push(NtString::from(path));
            }

            Ok(result)
        }
    }

    pub fn volumes(&self) -> Result<Vec<MountPoint>> {
        unsafe {
            let zeroed: mountmgr::MOUNTMGR_MOUNT_POINT = mem::zeroed();
            let out_buffer = self.ioctl(mountmgr::IOCTL_MOUNTMGR_QUERY_POINTS, as_byte_slice(&zeroed))?;
            let mut point_map: BTreeMap<Vec<u8>, MountPoint> = BTreeMap::new();
            self.process_points_output(&out_buffer, |link_name, id_bytes, device_name| {
                let entry = point_map
                    .entry(id_bytes.to_vec())
                    .or_insert_with(|| MountPoint::new(id_bytes));
                entry.add_link_name(link_name);
                entry.add_device_name(device_name);
            });

            Ok(point_map.values().cloned().collect())
        }
    }

    unsafe fn ioctl(&self, code: u32, input: &[u8]) -> Result<Vec<u8>> {
        let mut out_buffer = alloc_buffer(512);
        loop {
            let (status, _) = self.0.ioctl_raw(code, input, &mut out_buffer);
            match status {
                STATUS_SUCCESS => break,
                STATUS_BUFFER_OVERFLOW => out_buffer.resize(out_buffer.len() * 2, 0),
                error_status => return Err(Error::from(error_status)),
            }
        }

        Ok(out_buffer)
    }

    unsafe fn process_points_output<F>(&self, out_buffer: &[u8], mut f: F)
    where
        F: FnMut(&[u16], &[u8], &[u16]),
    {
        #[allow(clippy::cast_ptr_alignment)]
        let raw_points = &*(out_buffer.as_ptr() as *const mountmgr::MOUNTMGR_MOUNT_POINTS);
        for index in 0..raw_points.NumberOfMountPoints {
            let point = &*(&raw_points.MountPoints[0] as *const mountmgr::MOUNTMGR_MOUNT_POINT).offset(index as isize);

            let start = point.SymbolicLinkNameOffset as usize;
            let end = point.SymbolicLinkNameOffset as usize + point.SymbolicLinkNameLength as usize;
            let link_bytes = &out_buffer[start..end];
            #[allow(clippy::cast_ptr_alignment)]
            let link_name: &[u16] = core::slice::from_raw_parts(link_bytes.as_ptr() as *const _, link_bytes.len() / 2);

            let start = point.UniqueIdOffset as usize;
            let end = point.UniqueIdOffset as usize + point.UniqueIdLength as usize;
            let id_bytes: &[u8] = &out_buffer[start..end];

            let start = point.DeviceNameOffset as usize;
            let end = point.DeviceNameOffset as usize + point.DeviceNameLength as usize;
            let device_bytes = &out_buffer[start..end];
            #[allow(clippy::cast_ptr_alignment)]
            let device_name: &[u16] =
                core::slice::from_raw_parts(device_bytes.as_ptr() as *const _, device_bytes.len() / 2);

            f(link_name, id_bytes, device_name);
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn create_ro_mount_manager() {
        let mm = MountManager::open_readonly().unwrap();
        let all = mm.volumes().unwrap();
        for mp in &all {
            println!();

            println!("Dos name: {}", mp.dos_name.to_string());
            println!("GUID name: {}", mp.guid_name.to_string());
            println!("Device name: {}", mp.device_name.to_string());

            let paths = mm.path_names(&mp.device_name).unwrap();
            for p in &paths {
                println!("  --- {}", p.to_string());
            }

            if paths.is_empty() {
                println!("  --- NO MOUNT POINTS");
            }
        }
    }
}

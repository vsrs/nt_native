use crate::*;
use core::mem;
use winapi::shared::ntdef::{ULONG, USHORT};
use winapi::shared::ntstatus::{STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};
use windy::WString;
use windy_macros::wstring;

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct MountManager {
    handle: Handle,
    device_name: WString,
}

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
        if self.dos_name.is_empty() && is_dos_volume_name(name) {
            self.dos_name = NtString::from(name);
        } else if self.guid_name.is_empty() {
            debug_assert!(is_guid_volume_name(name));
            self.guid_name = NtString::from(name)
        }
    }

    pub fn open_volume(&self) -> Result<Volume> {
        Volume::open(&self.device_name)
    }

    pub fn open_readonly_volume(&self) -> Result<Volume> {
        Volume::open_info(&self.device_name)
    }
}

#[allow(bad_style)]
#[allow(dead_code)]
#[rustfmt::skip]
mod mountmgr {
    use crate::CTL_CODE;
    use winapi::shared::minwindef::{DWORD, ULONG, USHORT};
    use winapi::shared::ntdef::WCHAR;
    use winapi::um::winioctl::{FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_WRITE_ACCESS, METHOD_BUFFERED};
    use winapi::STRUCT;

    pub const MOUNTMGRCONTROLTYPE: DWORD = 0x0000_006D; // 'm'
    pub const MOUNTDEVCONTROLTYPE: DWORD = 0x0000_004D; // 'M'

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

const MP_SIZE: usize = mem::size_of::<mountmgr::MOUNTMGR_MOUNT_POINT>();

impl MountManager {
    pub fn open() -> Result<Self> {
        let device_name = wstring!("\\??\\MountPointManager");
        let (handle, _) = NewHandle::device(Access::GENERIC_READ | Access::GENERIC_WRITE).build_nt(&device_name.as_bytes())?;

        Ok(Self { handle, device_name })
    }

    pub fn open_readonly() -> Result<Self> {
        let device_name = wstring!("\\??\\MountPointManager");
        let (handle, _) = NewHandle::device(Access::SYNCHRONIZE).build_nt(&device_name.as_bytes())?;

        Ok(Self { handle, device_name })
    }

    pub fn path_names(&self, device_name: &NtString) -> Result<Vec<NtString>> {
        unsafe {
            let name_bytes: &[u8] = device_name.as_byte_slice();
            let name_bytes_size = name_bytes.len();
            let ext_size = name_bytes_size - U16_SIZE; // one WCHAR is in the MOUNTMGR_TARGET_NAME

            let mut spec = StructBuffer::<mountmgr::MOUNTMGR_TARGET_NAME>::with_ext(ext_size);
            spec.DeviceNameLength = name_bytes_size as USHORT;
            let destination: &mut [u8] = core::slice::from_raw_parts_mut(spec.DeviceName.as_mut_ptr() as *mut _, name_bytes_size);
            destination.copy_from_slice(name_bytes);

            let out_buffer = self.ioctl(mountmgr::IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS, spec.as_byte_slice())?;
            let output = StructBuffer::<mountmgr::MOUNTMGR_VOLUME_PATHS>::with_buffer(out_buffer);
            let paths_slice: &[u16] = core::slice::from_raw_parts(output.MultiSz.as_ptr(), output.MultiSzLength as usize / U16_SIZE);
            let mut result = Vec::new();
            for path in paths_slice.split(|ch| ch == &0).filter(|p| !p.is_empty()) {
                result.push(NtString::from(path));
            }

            Ok(result)
        }
    }

    pub fn volumes(&self) -> Result<Vec<MountPoint>> {
        unsafe {
            let zeroed = StructBuffer::<mountmgr::MOUNTMGR_MOUNT_POINT>::zeroed();

            let out_buffer = self.ioctl(mountmgr::IOCTL_MOUNTMGR_QUERY_POINTS, zeroed.as_byte_slice())?;
            let mut point_map: BTreeMap<Vec<u8>, MountPoint> = BTreeMap::new();
            self.process_points_output(&out_buffer, |link_name, id_bytes, device_name| {
                let entry = point_map.entry(id_bytes.to_vec()).or_insert_with(|| MountPoint::new(id_bytes));
                entry.add_link_name(link_name);
                entry.add_device_name(device_name);
            });

            Ok(point_map.values().cloned().collect())
        }
    }

    pub fn volume_mount_point(&self, device_name: &NtString) -> Result<MountPoint> {
        unsafe {
            let name_bytes: &[u8] = device_name.as_byte_slice();
            let name_bytes_size = name_bytes.len();
            let mut point = StructBuffer::<mountmgr::MOUNTMGR_MOUNT_POINT>::with_ext(name_bytes_size);
            point.SymbolicLinkNameOffset = 0;
            point.SymbolicLinkNameLength = 0;
            point.DeviceNameLength = name_bytes_size as USHORT;
            point.DeviceNameOffset = MP_SIZE as ULONG;
            point.UniqueIdLength = 0;
            point.UniqueIdOffset = 0;
            let ext_buffer = point.ext_buffer_mut();
            ext_buffer[..name_bytes_size].copy_from_slice(name_bytes);

            let out_buffer = self.ioctl(mountmgr::IOCTL_MOUNTMGR_QUERY_POINTS, point.as_byte_slice())?;
            let mut mount_point: Option<MountPoint> = None;
            self.process_points_output(&out_buffer, |link_name, id_bytes, device_name| {
                if mount_point.is_none() {
                    mount_point = Some(MountPoint::new(id_bytes));
                }
                if let Some(mp) = &mut mount_point {
                    mp.add_link_name(link_name);
                    mp.add_device_name(device_name);
                }
            });

            Ok(mount_point.unwrap())
        }
    }

    unsafe fn ioctl(&self, code: u32, input: &[u8]) -> Result<Vec<u8>> {
        let mut out_buffer = alloc_buffer(512);
        loop {
            let (status, _) = self.handle.ioctl_raw(code, input, &mut out_buffer);
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
            let device_name: &[u16] = core::slice::from_raw_parts(device_bytes.as_ptr() as *const _, device_bytes.len() / 2);

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

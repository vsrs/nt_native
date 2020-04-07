use crate::*;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::shared::ntstatus::STATUS_MEDIA_WRITE_PROTECTED;
use winapi::um::winioctl::{
    StorageDeviceSeekPenaltyProperty, StorageDeviceTrimProperty, DEVICE_TRIM_DESCRIPTOR, GET_LENGTH_INFORMATION,
    IOCTL_DISK_GET_DISK_ATTRIBUTES, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_IS_WRITABLE, IOCTL_STORAGE_GET_DEVICE_NUMBER,
    IOCTL_STORAGE_GET_HOTPLUG_INFO, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_NUMBER, STORAGE_PROPERTY_QUERY,
};

#[allow(bad_style)]
mod winioctl_ex {
    use winapi::shared::minwindef::{DWORD, ULONG};
    use winapi::shared::ntdef::{BOOLEAN, ULONGLONG};
    use winapi::STRUCT;

    STRUCT! { struct STORAGE_HOTPLUG_INFO{
        Size: ULONG,              // version
        MediaRemovable: BOOLEAN, // ie. zip, jaz, cdrom, mo, etc. vs hdd
        MediaHotplug: BOOLEAN,   // ie. does the device succeed a lock even though its not lockable media?
        DeviceHotplug: BOOLEAN,  // ie. 1394, USB, etc.
        WriteCacheEnableOverride: BOOLEAN, // This field should not be relied upon because it is no longer used
    }}

    STRUCT! { struct DEVICE_SEEK_PENALTY_DESCRIPTOR {
        Version: DWORD,
        Size: DWORD,
        IncursSeekPenalty: BOOLEAN,
    }}

    STRUCT! { struct GET_DISK_ATTRIBUTES {
        Version: ULONG,
        Reserved1: ULONG,
        Attributes: ULONGLONG,
    }}
}

pub fn length(handle: &Handle) -> Result<u64> {
    let mut data = unsafe { StructBuffer::<GET_LENGTH_INFORMATION>::new() };
    handle.ioctl_query(IOCTL_DISK_GET_LENGTH_INFO, &mut data)?;
    Ok(unsafe { *data.Length.QuadPart() as u64 })
}

pub fn is_readonly(handle: &Handle) -> Result<bool> {
    // attributes() with DISK_ATTRIBUTE_READ_ONLY does not work for virtual disks attached as read only

    match handle.ioctl_status(IOCTL_DISK_IS_WRITABLE) {
        STATUS_MEDIA_WRITE_PROTECTED => Ok(true),
        status if NT_SUCCESS(status) => Ok(false), // Not STATUS_SUCCESS because ioctl may return STATUS_ABANDONED -> STATUS_ABANDONED_WAIT_63
        status => Err(Error::from(status)),
    }
}

pub fn is_removable(handle: &Handle) -> Result<bool> {
    // A hotplug device refers to a device whose RemovalPolicy value displayed in the Device Manager is ExpectSurpriseRemoval.
    // The IOCTL_STORAGE_SET_HOTPLUG_INFO operation only sets the value of the DeviceHotplug member of this structure.
    // If the value of that member is set, the removal policy of the specified device is set to ExpectSurpriseRemoval and all levels of caching are disabled.
    // If the value of that member is not set, the removal policy of the specified device is set to ExpectOrderlyRemoval, and caching may be selectively enabled.

    let mut data = unsafe { StructBuffer::<winioctl_ex::STORAGE_HOTPLUG_INFO>::new() };
    handle.ioctl_query(IOCTL_STORAGE_GET_HOTPLUG_INFO, &mut data)?;

    Ok(data.DeviceHotplug != 0)
}

pub fn device_number(handle: &Handle) -> Result<u32> {
    let mut data = unsafe { StructBuffer::<STORAGE_DEVICE_NUMBER>::new() };
    handle.ioctl_query(IOCTL_STORAGE_GET_DEVICE_NUMBER, &mut data)?;

    Ok(data.DeviceNumber)
}

pub fn is_trim_enabled(handle: &Handle) -> Result<bool> {
    let mut input = StructBuffer::<STORAGE_PROPERTY_QUERY>::zeroed();
    input.PropertyId = StorageDeviceTrimProperty;

    let mut descriptor = unsafe { StructBuffer::<DEVICE_TRIM_DESCRIPTOR>::new() };
    handle.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, &input, &mut descriptor)?;

    Ok(descriptor.TrimEnabled != 0)
}

pub fn has_seek_penalty(handle: &Handle) -> Result<bool> {
    let mut input = StructBuffer::<STORAGE_PROPERTY_QUERY>::zeroed();
    input.PropertyId = StorageDeviceSeekPenaltyProperty;
    let mut descriptor = unsafe { StructBuffer::<winioctl_ex::DEVICE_SEEK_PENALTY_DESCRIPTOR>::new() };
    handle.ioctl(IOCTL_STORAGE_QUERY_PROPERTY, &input, &mut descriptor)?;

    Ok(descriptor.IncursSeekPenalty != 0)
}

pub fn attributes(handle: &Handle) -> Result<u64> {
    let mut data = unsafe { StructBuffer::<winioctl_ex::GET_DISK_ATTRIBUTES>::new() };
    handle.ioctl_query(IOCTL_DISK_GET_DISK_ATTRIBUTES, &mut data)?;

    Ok(data.Attributes)
}

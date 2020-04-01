use crate::*;

#[derive(Clone)]
#[cfg_attr(any(feature = "std", test), derive(Debug))]
pub struct Volume(Handle);

impl From<Handle> for Volume {
    fn from(handle: Handle) -> Self {
        Self(handle)
    }
}

impl Volume {
    pub fn open(name: &NtString) -> Result<Volume> {
        todo!()
    }

    pub fn enumerate() -> Volumes {
        todo!()
    }
}

pub struct Volumes{}

impl core::iter::Iterator for Volumes {
    type Item = Volume;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn enumerate_volumes() {
    }
}
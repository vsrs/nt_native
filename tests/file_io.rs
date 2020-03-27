use nt_native::*;
use std::io::prelude::*;

#[cfg(all(test, feature = "std"))]
mod std_tests {
    use super::*;

    fn test_dir() -> Option<String> {
        std::env::var("NT_NATIVE_TEST_DIR")
            .ok()
            .and_then(|dir| match std::fs::create_dir_all(&dir) {
                Ok(_) => Some(dir),
                Err(_) => None,
            })
    }

    #[test]
    fn builder_file() {
        if let Some(dir) = test_dir() {
            let new_file_name = format!("{}\\new_file.data", dir);
            // preliminary cleanup
            let _ = std::fs::remove_file(&new_file_name);

            let nt_path: NtString = NtString::from(&new_file_name);

            // file does not exist, open should fail
            assert_eq!(NewHandle::open(&nt_path).unwrap_err(), error::OBJECT_NOT_FOUND);
            assert_eq!(NewHandle::open_readonly(&nt_path).unwrap_err(), error::OBJECT_NOT_FOUND);
            assert_eq!(NewHandle::owerwrite(&nt_path).unwrap_err(), error::OBJECT_NOT_FOUND);

            let handle = NewHandle::create_new(&nt_path).unwrap();
            assert_eq!(handle.size().unwrap(), 0);

            let written = handle.write(b"12345678").unwrap();
            assert_eq!(written, 8);

            let mut buffer = vec![0_u8; 3];
            let readed = handle.read_at(1, &mut buffer).unwrap();
            assert_eq!(readed, 3);
            assert_eq!(buffer, b"234");
            assert_eq!(handle.size().unwrap(), 8);
            drop(handle);

            // now the file exists, the same call should fail
            let err = NewHandle::create_new(&nt_path).unwrap_err();
            assert_eq!(err, error::ALREADY_EXISTS);
            // and open should succeed
            drop(NewHandle::open(&nt_path).unwrap());

            // as well as open_readonly
            let handle = NewHandle::open_readonly(&nt_path).unwrap();
            let pos = handle.seek(SeekFrom::Start(5)).unwrap();
            assert_eq!(pos, 5);
            assert_eq!(pos, handle.pos().unwrap());

            let pos = handle.seek(SeekFrom::Current(2)).unwrap();
            assert_eq!(pos, 7);
            let pos = handle.seek(SeekFrom::Current(-4)).unwrap();
            assert_eq!(pos, 3);
            let pos = handle.seek(SeekFrom::End(-3)).unwrap();
            assert_eq!(pos, 5);
            let readed = handle.read(&mut buffer).unwrap();
            assert_eq!(readed, 3);
            assert_eq!(buffer, b"678");
            drop(handle);

            let handle = NewHandle::owerwrite(&nt_path).unwrap();
            drop(handle);

            let (handle, already_exists) = NewHandle::open_or_create(&nt_path).unwrap();
            assert_eq!(already_exists, true);
            drop(handle);

            let _ = std::fs::remove_file(&new_file_name);
            let (handle, already_exists) = NewHandle::open_or_create(&nt_path).unwrap();
            drop(handle);
            assert_eq!(already_exists, false);

            let (handle, already_exists) = NewHandle::owerwrite_or_create(&nt_path).unwrap();
            drop(handle);
            assert_eq!(already_exists, true);

            let _ = std::fs::remove_file(&new_file_name);
            let (handle, already_exists) = NewHandle {
                share_access: ShareAccess::default() | ShareAccess::DELETE,
                ..NewHandle::with_cd(CreateDisposition::OverwriteOrCreate)
            }
            .build(&nt_path)
            .unwrap();
            assert_eq!(already_exists, false);
            
            let n = handle.path_name().unwrap();
            println!("File path name: {}", n.to_string());

            let n = handle.object_name().unwrap();
            println!("Object name: {}", n.to_string());

            handle.remove_object().unwrap();
        }
    }

    #[test]
    fn std_traits() {
        if let Some(dir) = test_dir() {
            let file_name = format!("{}\\std_file.data", dir);
            let nt_path: NtString = NtString::from(&file_name);
            let (mut handle, _) = NewHandle::open_or_create(&nt_path).unwrap();
            std_test(&mut handle).unwrap();

            fn std_test<R: Read + Write + Seek>(file: &mut R) -> std::io::Result<()> {
                file.write_all(b"qwerty")?;
                let pos = file.seek(std::io::SeekFrom::Current(-5))?;
                assert_eq!(pos, 1);

                let mut buf = vec![0_u8; 5];
                file.read_exact(&mut buf)?;
                assert_eq!(buf, b"werty");

                Ok(())
            }
        }
    }
}

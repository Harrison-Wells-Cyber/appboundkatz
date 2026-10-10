use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// Everything the tool prints is mirrored to appbound.log next to the exe's
/// working directory, so run output survives a closing console window.
static LOG_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

/// One timestamped log per run, so a failing run's diagnostics survive the
/// next successful one that would otherwise overwrite appbound.log.
fn log_path() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let micros = 11_644_473_600_000_000 + now.as_secs() * 1_000_000;
    let digits: String = crate::report::format_chromium_time(micros as i64)
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    format!("appbound_{digits}.log")
}

fn log_file() -> Option<&'static Mutex<File>> {
    LOG_FILE
        .get_or_init(|| File::create(log_path()).ok().map(Mutex::new))
        .as_ref()
}

pub fn out(args: core::fmt::Arguments<'_>) {
    write_line(&mut std::io::stdout().lock(), args);
}

pub fn err(args: core::fmt::Arguments<'_>) {
    write_line(&mut std::io::stderr().lock(), args);
}

fn write_line(stream: &mut dyn Write, args: core::fmt::Arguments<'_>) {
    let mut line = args.to_string();
    line.push('\n');
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.flush();
    if let Some(file) = log_file() {
        if let Ok(mut f) = file.lock() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}

#[macro_export]
macro_rules! log_out {
    ($($arg:tt)*) => { $crate::log::out(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! log_err {
    ($($arg:tt)*) => { $crate::log::err(format_args!($($arg)*)) };
}

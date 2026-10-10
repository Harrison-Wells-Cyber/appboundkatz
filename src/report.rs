use std::fs::File;
use std::io::Write;

use csv::WriterBuilder;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::db::{CookieRow, LoginRow};

pub fn write_reports(logins: &[LoginRow], cookies: &[CookieRow]) -> Result<(), String> {
    let passwords_csv = build_passwords_csv(logins)?;
    let cookies_csv = build_cookies_csv(cookies)?;

    std::fs::write("passwords.csv", &passwords_csv).map_err(|e| e.to_string())?;
    std::fs::write("cookies.csv", &cookies_csv).map_err(|e| e.to_string())?;

    let file = File::create("browser_data.zip").map_err(|e| e.to_string())?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    zip.start_file("passwords.csv", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(&passwords_csv).map_err(|e| e.to_string())?;
    zip.start_file("cookies.csv", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(&cookies_csv).map_err(|e| e.to_string())?;
    zip.finish().map_err(|e| e.to_string())?;

    Ok(())
}

fn build_passwords_csv(logins: &[LoginRow]) -> Result<Vec<u8>, String> {
    let mut writer = WriterBuilder::new().from_writer(Vec::new());
    writer
        .write_record([
            "browser",
            "origin_url",
            "username",
            "password",
            "created",
            "last_used",
            "modified",
        ])
        .map_err(|e| e.to_string())?;
    for login in logins {
        writer
            .write_record([
                login.browser,
                &login.origin_url,
                &login.username,
                &login.password,
                &format_chromium_time(login.created),
                &format_chromium_time(login.last_used),
                &format_chromium_time(login.modified),
            ])
            .map_err(|e| e.to_string())?;
    }
    writer.into_inner().map_err(|e| e.to_string())
}

fn build_cookies_csv(cookies: &[CookieRow]) -> Result<Vec<u8>, String> {
    let mut writer = WriterBuilder::new().from_writer(Vec::new());
    writer
        .write_record([
            "browser",
            "url",
            "domain",
            "name",
            "path",
            "value",
            "secure",
            "httponly",
            "created",
            "expires",
            "last_accessed",
            "last_updated",
        ])
        .map_err(|e| e.to_string())?;
    for cookie in cookies {
        writer
            .write_record([
                cookie.browser,
                &full_cookie_url(cookie),
                &cookie.host,
                &cookie.name,
                &cookie.path,
                &cookie.value,
                &cookie.secure.to_string(),
                &cookie.httponly.to_string(),
                &format_chromium_time(cookie.created),
                &format_chromium_time(cookie.expires),
                &format_chromium_time(cookie.last_access),
                &format_chromium_time(cookie.last_update),
            ])
            .map_err(|e| e.to_string())?;
    }
    writer.into_inner().map_err(|e| e.to_string())
}

/// Cookies are stored per (domain, path), not per URL; reconstruct a usable
/// URL from the stored fields.
fn full_cookie_url(cookie: &CookieRow) -> String {
    let scheme = if cookie.secure { "https" } else { "http" };
    let host = cookie.host.trim_start_matches('.');
    format!("{scheme}://{host}{}", cookie.path)
}

/// Chrome/Edge store timestamps as microseconds since 1601-01-01 (0 = "never").
pub(crate) fn format_chromium_time(micros: i64) -> String {
    if micros == 0 {
        return "never".to_string();
    }
    let secs = micros.div_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Convert days since 1601-01-01 into a civil date (Howard Hinnant's
/// civil_from_days algorithm, rebased for the 1601 epoch).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 584_694; // 719468 (1970-based) minus 134774 (1601 -> 1970)
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_epoch_days() {
        assert_eq!(civil_from_days(0), (1601, 1, 1));
        assert_eq!(format_chromium_time(0), "never");
        assert_eq!(format_chromium_time(11_644_473_600_000_000), "1970-01-01 00:00:00");
        assert_eq!(format_chromium_time(13_348_540_800_000_000), "2024-01-01 00:00:00");
    }
}

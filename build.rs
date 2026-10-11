//! Embeds a Windows VERSIONINFO resource in the binary for the windows-gnu
//! target (see appbound.rc), via the mingw windres tool.
fn main() {
    if !std::env::var("TARGET")
        .unwrap_or_default()
        .contains("windows")
    {
        return;
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out = std::env::var("OUT_DIR").unwrap();
    let windres = ["x86_64-w64-mingw32-windres", "windres"]
        .iter()
        .find(|tool| {
            std::process::Command::new(tool)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        });
    let Some(windres) = windres else {
        println!("cargo:warning=windres not found; building without version resource");
        return;
    };

    let rc = format!("{manifest}/appbound.rc");
    let res = format!("{out}/resource.res");
    let ok = std::process::Command::new(*windres)
        .arg(&rc)
        .arg("-O")
        .arg("coff")
        .arg("-o")
        .arg(&res)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        panic!("windres failed to compile {rc}");
    }

    println!("cargo:rerun-if-changed=appbound.rc");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-arg-bins={res}");
}

# appboundkatz

A reliable, simple Rust port of [ElevationKatz](https://github.com/mkaliere/ChromeKatz)
(by Meckazin / ChromeKatz) that demonstrates how Chrome's and Edge's
**App-Bound Encryption (ABE)** can be defeated without ever touching the
SYSTEM elevation service, COM interfaces, or any elevated privilege.

The tool runs as a **standard, unelevated user** and only ever interacts with
processes started by that same user.

## What it does

For each of Chrome and Edge, on every run, with no options or modes:

1. **Terminates any running instances** of that browser (same user only), so a
   fresh, deterministic browser start is guaranteed.
2. **Starts the browser suspended**, resumes it, and **attaches as its
   debugger**.
3. Waits for the browser's main module (`chrome.dll` / `msedge.dll`) to load,
   then:
   - scans its `.rdata` for the static string `OSCrypt.AppBoundProvider.Decrypt.ResultCode`,
   - scans `.text` for the `LEA RCX, [RIP+disp32]` instruction that references
     that string (resolved dynamically, so it survives version changes),
   - arms a **hardware breakpoint (Dr0)** on that instruction in every thread.
4. When the browser itself performs the app-bound decryption at startup and
   hits the breakpoint, the tool reads the **key pointer out of R15 (Chrome) /
   R14 (Edge)**, follows it, and copies the 256-bit AES key.
5. Detaches the debugger, waits for the browser to load its profile
   databases, and **scrapes them out of memory** (`Login Data` from the
   browser process, `Cookies` from the network service process, both from the
   `User Data\Default` profile) — no files on disk are ever opened.
6. The database images are deserialized into in-memory SQLite connections,
   every `v20` blob is decrypted with the captured key (AES-256-GCM), and the
   results are written to:
    - `logins.csv`
    - `cookies.csv`
    - `export.zip` (containing both CSVs)
   Only the default profile is dumped.
7. Terminates the browser processes it started.

The browser still runs normally (nothing about the technique needs a hidden
process), but a background thread attempts to continuously parks its windows off-screen
(`-32000, -32000`) for the duration of the run, so it never occupies the
desktop. The windows remain visible in the taskbar and Alt-Tab.

## Usage

```
appboundkatz.exe
```

No arguments, no modes, no config. Both Chrome and Edge are attempted every
run. Output files are written to the current directory.

## Building

On Windows (MSVC):

```
cargo build --release
```

Cross-compile from Linux (mingw-w64):

```
cargo build --release --target x86_64-pc-windows-gnu
```

## Credits

- Original technique and tool: **ElevationKatz** by Meckazin
  (github.com/Meckazin, ChromeKatz)

## Ethics stuff

I just gave you the guts for an infotealer. Please don't do crime against anyone who hasn't earned it :)

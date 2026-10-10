use windows::Win32::Foundation::HANDLE;

use crate::mem;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub size_of_raw_data: u32,
}

const DOS_HEADER_SIZE: usize = 64;
const FILE_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;

pub fn sections(h: HANDLE, base: usize) -> Option<Vec<Section>> {
    let dos: [u8; DOS_HEADER_SIZE] = mem::read_value(h, base)?;
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as usize;

    // PE signature (4 bytes) + file header (20 bytes)
    let nt: [u8; 4 + FILE_HEADER_SIZE] = mem::read_value(h, base + e_lfanew)?;
    let signature = u32::from_le_bytes(nt[0..4].try_into().ok()?);
    if signature != 0x0000_4550 {
        return None;
    }
    let number_of_sections = u16::from_le_bytes(nt[6..8].try_into().ok()?) as usize;
    let size_of_optional_header = u16::from_le_bytes(nt[20..22].try_into().ok()?) as usize;

    let section_table = e_lfanew + 4 + FILE_HEADER_SIZE + size_of_optional_header;
    let mut out = Vec::with_capacity(number_of_sections);
    for i in 0..number_of_sections {
        let raw: [u8; SECTION_HEADER_SIZE] =
            mem::read_value(h, base + section_table + i * SECTION_HEADER_SIZE)?;
        out.push(Section {
            name: String::from_utf8_lossy(&raw[0..8]).trim_end_matches('\0').to_string(),
            virtual_size: u32::from_le_bytes(raw[8..12].try_into().ok()?),
            virtual_address: u32::from_le_bytes(raw[12..16].try_into().ok()?),
            size_of_raw_data: u32::from_le_bytes(raw[16..20].try_into().ok()?),
        });
    }
    Some(out)
}

fn find_section(h: HANDLE, base: usize, name: &str) -> Option<Section> {
    sections(h, base)?.into_iter().find(|s| s.name.eq_ignore_ascii_case(name))
}

fn read_section(h: HANDLE, base: usize, section: &Section) -> Option<Vec<u8>> {
    let size = if section.virtual_size != 0 {
        section.virtual_size
    } else {
        section.size_of_raw_data
    } as usize;
    let va = base + section.virtual_address as usize;
    mem::read_bytes(h, va, size)
}

/// Scan the module's .rdata section for a raw byte pattern, returning its VA.
pub fn find_pattern(h: HANDLE, base: usize, needle: &[u8]) -> Option<usize> {
    let section = find_section(h, base, ".rdata")?;
    let data = read_section(h, base, &section)?;
    let offset = data.windows(needle.len()).position(|w| w == needle)?;
    let va = base + section.virtual_address as usize + offset;
    println!("[*] Found pattern at {va:#x}");
    Some(va)
}

/// Scan the module's .text section for `LEA RCX, [RIP+disp32]` (48 8D 0D xx xx
/// xx xx) instructions whose effective address equals `target`, and return the
/// instruction's VA to use as the breakpoint site.
///
/// 48  = REX.W
/// 8D  = LEA
/// 0D  = ModRM (Mod=00, Reg=001 -> RCX, R/M=101 -> RIP-relative)
/// ..  = disp32, resolved at runtime: instruction VA + 7 + disp
pub fn find_lea_xrefs(h: HANDLE, base: usize, target: usize) -> Vec<usize> {
    const INSTR_LEN: usize = 7;
    let Some(section) = find_section(h, base, ".text") else {
        crate::log_err!("[-] Failed to get .text section header.");
        return Vec::new();
    };
    let Some(data) = read_section(h, base, &section) else {
        crate::log_err!("[-] Failed to read the .text section.");
        return Vec::new();
    };
    if data.len() < INSTR_LEN {
        return Vec::new();
    }
    let section_base = base + section.virtual_address as usize;

    let mut hits = Vec::new();
    for i in 0..=(data.len() - INSTR_LEN) {
        if data[i] != 0x48 || data[i + 1] != 0x8D || data[i + 2] != 0x0D {
            continue;
        }
        let Ok(disp_bytes) = data[i + 3..i + 7].try_into() else { continue };
        let disp = i32::from_le_bytes(disp_bytes);
        let instruction_va = section_base + i;
        let effective = instruction_va.wrapping_add(INSTR_LEN).wrapping_add(disp as usize);
        if effective == target {
            crate::log_out!("[+] Found LEA RCX xref at {instruction_va:#x}");
            hits.push(instruction_va);
        }
    }
    hits
}

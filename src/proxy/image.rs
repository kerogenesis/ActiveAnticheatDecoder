//! Minimal PE32 export-table parser for the proxy target.
//!
//! Reads only what forwarding needs: section map, export directory,
//! name<->ordinal mapping. Fails closed on crafted images.

use crate::util::{read_u16, read_u32};

pub(super) struct Export {
    pub(super) name: Option<String>,
    pub(super) ordinal: u32,
    pub(super) rva: u32,
    /// Re-exported from another DLL: no static address, resolve by name (or
    /// ordinal) after loading instead of module_base + rva.
    pub(super) forwarded: bool,
}

pub(super) struct Image {
    bytes: Vec<u8>,
    sections: Vec<(u32, u32, u32)>, // (virt_begin, virt_end, raw)
    export_rva: u32,
    export_size: u32,
}

pub(super) fn parse_image(bytes: Vec<u8>) -> Option<Image> {
    if read_u16(&bytes, 0)? != 0x5A4D {
        return None;
    }
    let pe = read_u32(&bytes, 0x3C)? as usize;
    if read_u32(&bytes, pe)? != 0x0000_4550 {
        return None;
    }
    let num_sections = read_u16(&bytes, pe + 6)? as usize;
    let opt_size = read_u16(&bytes, pe + 20)? as usize;
    let opt = pe + 24;
    // We only ever proxy 32-bit DLLs.
    if read_u16(&bytes, opt)? != 0x10B {
        return None;
    }
    let export_rva = read_u32(&bytes, opt + 96)?;
    let export_size = read_u32(&bytes, opt + 100)?;
    if export_rva == 0 {
        return None;
    }
    let sections_at = opt + opt_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let at = sections_at + i * 40;
        let virt = read_u32(&bytes, at + 12)?;
        // Crafted images love overflowing this: fail closed instead.
        let end = virt.checked_add(read_u32(&bytes, at + 8)?)?;
        let raw = read_u32(&bytes, at + 20)?;
        sections.push((virt, end, raw));
    }
    let image = Image { bytes, sections, export_rva, export_size };
    Some(image)
}

impl Image {
    fn raw_of(&self, rva: u32) -> Option<usize> {
        self.sections.iter().find_map(|(begin, end, raw)| {
            (*begin <= rva && rva < *end)
                .then(|| u64::from(rva - *begin) + u64::from(*raw))
                .and_then(|offset| usize::try_from(offset).ok())
        })
    }

    fn is_forwarder(&self, rva: u32) -> bool {
        rva >= self.export_rva && rva < self.export_rva + self.export_size
    }

    fn read_cstring(&self, raw: usize) -> Option<String> {
        let end = self.bytes.get(raw..)?.iter().position(|byte| *byte == 0)?;
        String::from_utf8(self.bytes[raw..raw + end].to_vec()).ok()
    }

    pub(super) fn exports(&self) -> Option<Vec<Export>> {
        let dir = self.raw_of(self.export_rva)?;
        let base = read_u32(&self.bytes, dir + 16)?;
        let count = read_u32(&self.bytes, dir + 20)?;
        let name_count = read_u32(&self.bytes, dir + 24)?;
        // Unbounded pre-allocation from hostile input is a DoS vector (and a
        // hang via the loops below); no real export table is this large.
        if count > 1_000_000 || name_count > 1_000_000 {
            return None;
        }
        let names_rva = read_u32(&self.bytes, dir + 32)?;
        let rva_table = self.raw_of(names_rva)?;
        let ordinals_rva = read_u32(&self.bytes, dir + 36)?;
        let ordinals_raw = self.raw_of(ordinals_rva)?;
        let funcs_rva = read_u32(&self.bytes, dir + 28)?;
        let funcs_raw = self.raw_of(funcs_rva)?;

        // Ordinal -> name index, to tell named exports apart from NONAME ones.
        // NOTE: +32 is AddressOfNames; +24 is just the name *count*. Mixing
        // them up fails silently and scrambles every name<->slot mapping.
        let mut name_of_ordinal = vec![None; count as usize];
        for i in 0..name_count {
            let entry_rva = read_u32(&self.bytes, rva_table + 4 * i as usize)?;
            let ordinal = u32::from(read_u16(&self.bytes, ordinals_raw + 2 * i as usize)?);
            let name = self.read_cstring(self.raw_of(entry_rva)?)?;
            if let Some(slot) = name_of_ordinal.get_mut(ordinal as usize) {
                *slot = Some(name);
            }
        }

        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count {
            let rva = read_u32(&self.bytes, funcs_raw + 4 * i as usize)?;
            // Keep the slot even for re-exports so later ordinals stay
            // aligned with the static /EXPORT overlay.
            let forwarded = self.is_forwarder(rva);
            out.push(Export {
                name: name_of_ordinal.get(i as usize).cloned().flatten(),
                ordinal: base.checked_add(i)?,
                rva,
                forwarded,
            });
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_image;

    /// Guards the IMAGE_EXPORT_DIRECTORY layout (+24 count vs +32 names RVA):
    /// mixing them up fails silently and scrambles every name<->slot mapping.
    #[test]
    fn parses_ddraw_export_table() {
        let bytes =
            std::fs::read(r"C:\Windows\SysWOW64\ddraw.dll").expect("SysWOW64 ddraw must exist");
        let image = parse_image(bytes).expect("valid PE32 image");
        let exports = image.exports().expect("export table parses");
        assert_eq!(exports.len(), 22);
        assert_eq!(exports[0].name.as_deref(), Some("AcquireDDThreadLock"));
        assert_eq!(exports[0].ordinal, 1);
        assert_eq!(exports[7].name.as_deref(), Some("DirectDrawCreate"));
        assert_eq!(exports[21].name.as_deref(), Some("SetAppCompatData"));
        assert_eq!(exports[21].ordinal, 22);
    }

    #[test]
    fn parses_d3d9_with_nontrivial_base() {
        let bytes = std::fs::read(r"C:\Windows\SysWOW64\d3d9.dll").expect("d3d9 must exist");
        let image = parse_image(bytes).expect("valid PE32 image");
        let exports = image.exports().expect("export table parses");
        assert_eq!(exports.len(), 23);
        assert_eq!(exports[21].name.as_deref(), Some("Direct3DCreate9"));
        assert_eq!(exports[21].ordinal, 37);
        assert!(exports[0].name.is_none());
        assert_eq!(exports[0].ordinal, 16);
    }

    #[test]
    fn parses_xinput_ordinals_with_gaps() {
        let bytes = std::fs::read(r"C:\Windows\SysWOW64\xinput1_4.dll").expect("xinput must exist");
        let image = parse_image(bytes).expect("valid PE32 image");
        let exports = image.exports().expect("export table parses");
        assert_eq!(exports.len(), 109);
        assert_eq!(exports[1].name.as_deref(), Some("XInputGetState"));
        assert!(exports[5].name.is_none());
        assert_eq!(exports[5].ordinal, 6);
        assert!(exports[108].name.is_none());
        assert_eq!(exports[108].ordinal, 109);
    }

    #[test]
    fn forwarder_free_targets_keep_slots_aligned() {
        for (dll, count) in
            [(r"C:\Windows\SysWOW64\ddraw.dll", 22), (r"C:\Windows\SysWOW64\d3d9.dll", 23)]
        {
            let bytes = std::fs::read(dll).expect("system DLL must exist");
            let exports = parse_image(bytes).expect("image parses").exports().expect("exports");
            assert_eq!(exports.len(), count);
            assert!(exports.iter().all(|export| !export.forwarded));
            // Ordinals must run unbroken: any gap or shift would bind the
            // static /EXPORT overlay to the wrong stubs.
            let base = exports.first().map(|export| export.ordinal).unwrap_or(0);
            for (i, export) in exports.iter().enumerate() {
                assert_eq!(export.ordinal, base + i as u32, "slot {i} misaligned");
            }
        }
    }

    /// A section running past 4 GB must fail closed, not panic (fuzz-found)
    /// or wrap into a wrong mapping (release).
    #[test]
    fn overflowing_section_fails_closed() {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(&[0x4D, 0x5A]);
        bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        let pe = 0x40;
        bytes[pe..pe + 4].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        bytes[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        bytes[pe + 20..pe + 22].copy_from_slice(&0xE0u16.to_le_bytes());
        let opt = pe + 24;
        bytes[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
        bytes[opt + 96..opt + 100].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[opt + 100..opt + 104].copy_from_slice(&40u32.to_le_bytes());
        let section = opt + 0xE0;
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(parse_image(bytes).is_none());
    }
}

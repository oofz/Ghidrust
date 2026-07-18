//! IL2CPP `global-metadata.dat` parser (P0: v27 / v29 / v31).

use crate::error::{Error, Result};
use serde::Serialize;
use std::path::Path;

/// Canonical metadata magic (`0xFAB11BAF`).
pub const METADATA_MAGIC: u32 = 0xFAB11BAF;

/// Layout dialect selected by version (+ future structural probes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataDialect {
    V27,
    V29,
    V31,
}

impl MetadataDialect {
    pub fn from_version(version: i32) -> Result<Self> {
        match version {
            27 => Ok(Self::V27),
            29 => Ok(Self::V29),
            31 => Ok(Self::V31),
            v if (24..27).contains(&v) => Err(Error::UnsupportedVersion {
                version: v,
                hint: "v24.x is P1; use a Unity build that emits v27/29/31 or wait for follow-on support"
                    .into(),
            }),
            v if v >= 39 => Err(Error::UnsupportedVersion {
                version: v,
                hint: "v39+/v106 sectioned metadata is P1".into(),
            }),
            v => Err(Error::UnsupportedVersion {
                version: v,
                hint: "supported P0 versions: 27, 29, 31".into(),
            }),
        }
    }

    fn type_def_stride(self) -> usize {
        // Il2CppTypeDefinition without byrefTypeIndex (post-24.5): 88 bytes.
        88
    }

    fn method_def_stride(self) -> usize {
        // Il2CppMethodDefinition (no methodIndex/invokerIndex): 32 bytes.
        32
    }

    fn image_def_stride(self) -> usize {
        40
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataHeader {
    pub magic: u32,
    pub version: i32,
    pub dialect: MetadataDialect,
    pub string_offset: u32,
    pub string_size: u32,
    pub string_literal_offset: u32,
    pub string_literal_size: u32,
    pub string_literal_data_offset: u32,
    pub string_literal_data_size: u32,
    pub methods_offset: u32,
    pub methods_size: u32,
    pub type_definitions_offset: u32,
    pub type_definitions_size: u32,
    pub images_offset: u32,
    pub images_size: u32,
    pub assemblies_offset: u32,
    pub assemblies_size: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeDef {
    pub index: u32,
    pub name: String,
    pub namespace: String,
    pub method_start: i32,
    pub method_count: u16,
    pub token: u32,
}

impl TypeDef {
    pub fn full_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.namespace, self.name)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodDef {
    pub index: u32,
    pub name: String,
    pub declaring_type: i32,
    pub token: u32,
    pub parameter_count: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageDef {
    pub index: u32,
    pub name: String,
    pub type_start: i32,
    pub type_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Il2CppMetadata {
    pub header: MetadataHeader,
    pub types: Vec<TypeDef>,
    pub methods: Vec<MethodDef>,
    pub images: Vec<ImageDef>,
    /// Metadata string heap entries (index → string), sparse-friendly as vec of (offset, value).
    pub strings: Vec<(u32, String)>,
}

impl Il2CppMetadata {
    pub fn load_path(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path.as_ref()).map_err(|e| Error::Io(e.to_string()))?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 16 {
            return Err(Error::Parse("metadata too small".into()));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = i32::from_le_bytes(data[4..8].try_into().unwrap());
        if magic != METADATA_MAGIC {
            return Err(Error::EncryptedOrObfuscated {
                magic,
                version_field: version,
            });
        }
        let dialect = MetadataDialect::from_version(version)?;
        let header = parse_header(data, version, dialect)?;
        validate_table(data, header.string_offset, header.string_size, "string heap")?;
        validate_table(
            data,
            header.type_definitions_offset,
            header.type_definitions_size,
            "typeDefinitions",
        )?;
        validate_table(data, header.methods_offset, header.methods_size, "methods")?;
        validate_table(data, header.images_offset, header.images_size, "images")?;

        let strings = extract_string_heap(data, header.string_offset, header.string_size);
        let types = parse_type_defs(data, &header, &strings, dialect)?;
        let methods = parse_method_defs(data, &header, &strings, dialect)?;
        let images = parse_images(data, &header, &strings, dialect)?;

        Ok(Self {
            header,
            types,
            methods,
            images,
            strings,
        })
    }

    /// Peek magic/version without full parse (for inventory).
    pub fn peek(data: &[u8]) -> Result<(u32, i32, Option<MetadataDialect>)> {
        if data.len() < 8 {
            return Err(Error::Parse("metadata too small".into()));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = i32::from_le_bytes(data[4..8].try_into().unwrap());
        if magic != METADATA_MAGIC {
            return Err(Error::EncryptedOrObfuscated {
                magic,
                version_field: version,
            });
        }
        let dialect = MetadataDialect::from_version(version).ok();
        Ok((magic, version, dialect))
    }

    pub fn method_full_name(&self, method: &MethodDef) -> String {
        let ty = self
            .types
            .get(method.declaring_type as usize)
            .map(|t| t.full_name())
            .unwrap_or_else(|| format!("Type{}", method.declaring_type));
        format!("{ty}::{}", method.name)
    }

    pub fn filter_types(&self, needle: &str) -> Vec<&TypeDef> {
        let n = needle.to_ascii_lowercase();
        self.types
            .iter()
            .filter(|t| t.full_name().to_ascii_lowercase().contains(&n))
            .collect()
    }

    pub fn filter_methods(&self, needle: &str) -> Vec<&MethodDef> {
        let n = needle.to_ascii_lowercase();
        self.methods
            .iter()
            .filter(|m| {
                self.method_full_name(m).to_ascii_lowercase().contains(&n)
                    || m.name.to_ascii_lowercase().contains(&n)
            })
            .collect()
    }
}

fn validate_table(data: &[u8], offset: u32, size: u32, name: &str) -> Result<()> {
    let end = offset as u64 + size as u64;
    if end > data.len() as u64 {
        return Err(Error::Bounds(format!(
            "{name} table OOB: offset={offset} size={size} file={}",
            data.len()
        )));
    }
    Ok(())
}

fn read_i32(data: &[u8], off: &mut usize) -> Result<i32> {
    if *off + 4 > data.len() {
        return Err(Error::Bounds("header truncated".into()));
    }
    let v = i32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(v)
}

fn read_u32_pair(data: &[u8], off: &mut usize) -> Result<(u32, u32)> {
    let a = read_i32(data, off)? as u32;
    let b = read_i32(data, off)? as u32;
    Ok((a, b))
}

/// Walk versioned header field pairs (mirrors Il2CppDumper / Cpp2IL layout gates).
fn parse_header(data: &[u8], version: i32, dialect: MetadataDialect) -> Result<MetadataHeader> {
    let mut off = 8usize;
    let (string_literal_offset, string_literal_size) = read_u32_pair(data, &mut off)?;
    let (string_literal_data_offset, string_literal_data_size) = read_u32_pair(data, &mut off)?;
    let (string_offset, string_size) = read_u32_pair(data, &mut off)?;
    let (_events_off, _events_sz) = read_u32_pair(data, &mut off)?;
    let (_props_off, _props_sz) = read_u32_pair(data, &mut off)?;
    let (methods_offset, methods_size) = read_u32_pair(data, &mut off)?;
    let (_pdv_off, _pdv_sz) = read_u32_pair(data, &mut off)?;
    let (_fdv_off, _fdv_sz) = read_u32_pair(data, &mut off)?;
    let (_fpd_off, _fpd_sz) = read_u32_pair(data, &mut off)?;
    let (_fms_off, _fms_sz) = read_u32_pair(data, &mut off)?;
    let (_params_off, _params_sz) = read_u32_pair(data, &mut off)?;
    let (_fields_off, _fields_sz) = read_u32_pair(data, &mut off)?;
    let (_gp_off, _gp_sz) = read_u32_pair(data, &mut off)?;
    let (_gpc_off, _gpc_sz) = read_u32_pair(data, &mut off)?;
    let (_gc_off, _gc_sz) = read_u32_pair(data, &mut off)?;
    let (_nested_off, _nested_sz) = read_u32_pair(data, &mut off)?;
    let (_ifaces_off, _ifaces_sz) = read_u32_pair(data, &mut off)?;
    let (_vt_off, _vt_sz) = read_u32_pair(data, &mut off)?;
    let (_io_off, _io_sz) = read_u32_pair(data, &mut off)?;
    let (type_definitions_offset, type_definitions_size) = read_u32_pair(data, &mut off)?;
    // rgctx only <= 24.1 — skipped for P0 dialects
    let (images_offset, images_size) = read_u32_pair(data, &mut off)?;
    let (assemblies_offset, assemblies_size) = read_u32_pair(data, &mut off)?;
    // metadataUsage only < 27 — skipped
    let (_field_refs_off, _field_refs_sz) = read_u32_pair(data, &mut off)?;
    let (_ref_asm_off, _ref_asm_sz) = read_u32_pair(data, &mut off)?;
    if version < 29 {
        let (_attr_info_off, _attr_info_sz) = read_u32_pair(data, &mut off)?;
        let (_attr_types_off, _attr_types_sz) = read_u32_pair(data, &mut off)?;
    } else {
        let (_attr_data_off, _attr_data_sz) = read_u32_pair(data, &mut off)?;
        let (_attr_range_off, _attr_range_sz) = read_u32_pair(data, &mut off)?;
    }
    let (_uvc_types_off, _uvc_types_sz) = read_u32_pair(data, &mut off)?;
    let (_uvc_ranges_off, _uvc_ranges_sz) = read_u32_pair(data, &mut off)?;
    let (_wrtn_off, _wrtn_sz) = read_u32_pair(data, &mut off)?;
    if version >= 27 {
        let (_wrs_off, _wrs_sz) = read_u32_pair(data, &mut off)?;
    }
    let (_exported_off, _exported_sz) = read_u32_pair(data, &mut off)?;

    // Sanity: first table often starts at header size.
    if string_literal_offset as usize != off && string_literal_offset as usize + 8 < data.len() {
        // Not fatal — some builds pad or reorder; keep going.
    }

    Ok(MetadataHeader {
        magic: METADATA_MAGIC,
        version,
        dialect,
        string_offset,
        string_size,
        string_literal_offset,
        string_literal_size,
        string_literal_data_offset,
        string_literal_data_size,
        methods_offset,
        methods_size,
        type_definitions_offset,
        type_definitions_size,
        images_offset,
        images_size,
        assemblies_offset,
        assemblies_size,
    })
}

fn extract_string_heap(data: &[u8], offset: u32, size: u32) -> Vec<(u32, String)> {
    let start = offset as usize;
    let end = (offset + size) as usize;
    if end > data.len() || start >= end {
        return Vec::new();
    }
    let heap = &data[start..end];
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < heap.len() {
        let begin = i;
        while i < heap.len() && heap[i] != 0 {
            i += 1;
        }
        if i > begin {
            let s = String::from_utf8_lossy(&heap[begin..i]).into_owned();
            out.push((begin as u32, s));
        }
        i += 1;
    }
    out
}

fn string_at(heap: &[(u32, String)], index: i32) -> String {
    if index < 0 {
        return String::new();
    }
    let idx = index as u32;
    heap.iter()
        .find(|(off, _)| *off == idx)
        .map(|(_, s)| s.clone())
        .unwrap_or_default()
}

fn parse_type_defs(
    data: &[u8],
    header: &MetadataHeader,
    strings: &[(u32, String)],
    dialect: MetadataDialect,
) -> Result<Vec<TypeDef>> {
    let stride = dialect.type_def_stride();
    let count = header.type_definitions_size as usize / stride;
    let base = header.type_definitions_offset as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = base + i * stride;
        if off + stride > data.len() {
            return Err(Error::Bounds("type def truncated".into()));
        }
        let name_index = i32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let ns_index = i32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        // Layout: name, ns, byval, declaring, parent, element, genericContainer, flags (8*4),
        // then fieldStart, methodStart at +32,+36
        let method_start = i32::from_le_bytes(data[off + 36..off + 40].try_into().unwrap());
        let method_count = u16::from_le_bytes(data[off + 64..off + 66].try_into().unwrap());
        let token = u32::from_le_bytes(data[off + 84..off + 88].try_into().unwrap());
        out.push(TypeDef {
            index: i as u32,
            name: string_at(strings, name_index),
            namespace: string_at(strings, ns_index),
            method_start,
            method_count,
            token,
        });
    }
    Ok(out)
}

fn parse_method_defs(
    data: &[u8],
    header: &MetadataHeader,
    strings: &[(u32, String)],
    dialect: MetadataDialect,
) -> Result<Vec<MethodDef>> {
    let stride = dialect.method_def_stride();
    let count = header.methods_size as usize / stride;
    let base = header.methods_offset as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = base + i * stride;
        if off + stride > data.len() {
            return Err(Error::Bounds("method def truncated".into()));
        }
        let name_index = i32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let declaring_type = i32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let token = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
        let parameter_count = u16::from_le_bytes(data[off + 30..off + 32].try_into().unwrap());
        out.push(MethodDef {
            index: i as u32,
            name: string_at(strings, name_index),
            declaring_type,
            token,
            parameter_count,
        });
    }
    Ok(out)
}

fn parse_images(
    data: &[u8],
    header: &MetadataHeader,
    strings: &[(u32, String)],
    dialect: MetadataDialect,
) -> Result<Vec<ImageDef>> {
    let stride = dialect.image_def_stride();
    if header.images_size == 0 {
        return Ok(Vec::new());
    }
    let count = header.images_size as usize / stride;
    let base = header.images_offset as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = base + i * stride;
        if off + stride > data.len() {
            return Err(Error::Bounds("image def truncated".into()));
        }
        let name_index = i32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let type_start = i32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
        let type_count = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
        out.push(ImageDef {
            index: i as u32,
            name: string_at(strings, name_index),
            type_start,
            type_count,
        });
    }
    Ok(out)
}

/// Build a minimal valid metadata blob for tests (dialect v31 layout).
pub fn build_synthetic_v31() -> Vec<u8> {
    build_synthetic(31)
}

pub fn build_synthetic(version: i32) -> Vec<u8> {
    let mut heap = Vec::new();
    let mut push_str = |s: &str| -> i32 {
        let off = heap.len() as i32;
        heap.extend_from_slice(s.as_bytes());
        heap.push(0);
        off
    };
    let ns = push_str("UnityEngine");
    let cam = push_str("Camera");
    let get_main = push_str("get_main");
    let asm = push_str("UnityEngine.CoreModule.dll");

    let mut type_def = vec![0u8; 88];
    type_def[0..4].copy_from_slice(&cam.to_le_bytes());
    type_def[4..8].copy_from_slice(&ns.to_le_bytes());
    type_def[36..40].copy_from_slice(&0i32.to_le_bytes());
    type_def[64..66].copy_from_slice(&1u16.to_le_bytes());
    type_def[84..88].copy_from_slice(&0x02000001u32.to_le_bytes());

    let mut method_def = vec![0u8; 32];
    method_def[0..4].copy_from_slice(&get_main.to_le_bytes());
    method_def[4..8].copy_from_slice(&0i32.to_le_bytes());
    method_def[20..24].copy_from_slice(&0x06000001u32.to_le_bytes());
    method_def[30..32].copy_from_slice(&0u16.to_le_bytes());

    let mut image = vec![0u8; 40];
    image[0..4].copy_from_slice(&asm.to_le_bytes());
    image[8..12].copy_from_slice(&0i32.to_le_bytes());
    image[12..16].copy_from_slice(&1u32.to_le_bytes());

    let mut header_fields: Vec<u8> = Vec::new();
    header_fields.extend_from_slice(&METADATA_MAGIC.to_le_bytes());
    header_fields.extend_from_slice(&version.to_le_bytes());

    let mut slots: Vec<usize> = Vec::new();
    let mut push_pair = |hf: &mut Vec<u8>| {
        let idx = hf.len();
        hf.extend_from_slice(&0u32.to_le_bytes());
        hf.extend_from_slice(&0u32.to_le_bytes());
        slots.push(idx);
        slots.len() - 1
    };

    let i_sl = push_pair(&mut header_fields);
    let i_sld = push_pair(&mut header_fields);
    let i_str = push_pair(&mut header_fields);
    let _ = push_pair(&mut header_fields); // events
    let _ = push_pair(&mut header_fields); // properties
    let i_me = push_pair(&mut header_fields);
    for _ in 0..13 {
        let _ = push_pair(&mut header_fields);
    }
    let i_ty = push_pair(&mut header_fields);
    let i_im = push_pair(&mut header_fields);
    let _ = push_pair(&mut header_fields); // assemblies
    let _ = push_pair(&mut header_fields); // fieldRefs
    let _ = push_pair(&mut header_fields); // referencedAssemblies
    let _ = push_pair(&mut header_fields); // attr0
    let _ = push_pair(&mut header_fields); // attr1
    let _ = push_pair(&mut header_fields); // uvc types
    let _ = push_pair(&mut header_fields); // uvc ranges
    let _ = push_pair(&mut header_fields); // wrt names
    if version >= 27 {
        let _ = push_pair(&mut header_fields); // wrt strings
    }
    let _ = push_pair(&mut header_fields); // exported

    let hdr_len = header_fields.len() as u32;
    let mut out = header_fields;

    fn patch(out: &mut [u8], slots: &[usize], slot: usize, offset: u32, size: u32) {
        let idx = slots[slot];
        out[idx..idx + 4].copy_from_slice(&offset.to_le_bytes());
        out[idx + 4..idx + 8].copy_from_slice(&size.to_le_bytes());
    }

    patch(&mut out, &slots, i_sl, hdr_len, 0);
    patch(&mut out, &slots, i_sld, hdr_len, 0);

    let str_off = out.len() as u32;
    out.extend_from_slice(&heap);
    patch(&mut out, &slots, i_str, str_off, heap.len() as u32);

    let ty_off = out.len() as u32;
    out.extend_from_slice(&type_def);
    patch(&mut out, &slots, i_ty, ty_off, type_def.len() as u32);

    let me_off = out.len() as u32;
    out.extend_from_slice(&method_def);
    patch(&mut out, &slots, i_me, me_off, method_def.len() as u32);

    let im_off = out.len() as u32;
    out.extend_from_slice(&image);
    patch(&mut out, &slots, i_im, im_off, image.len() as u32);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_v31_roundtrip() {
        let bytes = build_synthetic_v31();
        let meta = Il2CppMetadata::parse(&bytes).expect("parse");
        assert_eq!(meta.header.version, 31);
        assert_eq!(meta.header.dialect, MetadataDialect::V31);
        assert!(meta.types.iter().any(|t| t.full_name() == "UnityEngine.Camera"));
        assert!(meta
            .methods
            .iter()
            .any(|m| meta.method_full_name(m).contains("get_main")));
    }

    #[test]
    fn encrypted_magic_fails_closed() {
        let mut bytes = build_synthetic_v31();
        bytes[0] = 0x04;
        bytes[1] = 0x05;
        bytes[2] = 0x06;
        bytes[3] = 0x07;
        let err = Il2CppMetadata::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::EncryptedOrObfuscated { .. }));
    }

    #[test]
    fn unsupported_version() {
        let mut bytes = build_synthetic(31);
        bytes[4..8].copy_from_slice(&106i32.to_le_bytes());
        // magic still valid but version unsupported
        let err = Il2CppMetadata::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion { version: 106, .. }));
    }
}

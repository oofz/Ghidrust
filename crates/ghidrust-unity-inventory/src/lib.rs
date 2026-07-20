//! Unity player install inventory (assemblies, plugins, metadata, XR-related fields).

use ghidrust_core::{load_path, version_info_for_file, VersionInfo};
use ghidrust_il2cpp::{Il2CppMetadata, METADATA_MAGIC};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XrVerdict {
    None,
    StockStubsOnly,
    UnityXrPackaged,
    ExternalModLikely,
    Mixed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileHash {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataPeek {
    pub path: String,
    pub present: bool,
    pub magic: Option<String>,
    pub version: Option<i32>,
    pub encrypted_or_obfuscated: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineFingerprint {
    pub il2cpp: bool,
    pub mono: bool,
    pub burst: bool,
    pub urp: bool,
    pub hdrp: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnityInventory {
    pub schema_version: u32,
    pub root: String,
    pub data_dir: Option<String>,
    pub app_info: Option<String>,
    pub boot_config: Option<Vec<String>>,
    pub scripting_assemblies: Vec<String>,
    pub runtime_initialize_on_loads: Option<usize>,
    pub plugins: Vec<String>,
    pub metadata: Option<MetadataPeek>,
    pub addressables_hint: bool,
    pub engine: EngineFingerprint,
    pub xr_stock_modules: Vec<String>,
    pub xr_packages: Vec<String>,
    pub xr_subsystem_manifests: Vec<String>,
    pub native_xr_imports: Vec<String>,
    pub external_vr_indicators: Vec<String>,
    pub key_hashes: Vec<FileHash>,
    /// PE VERSIONINFO for player exe / key native modules (shared inventory helpers).
    #[serde(default)]
    pub pe_versions: Vec<PeVersionRow>,
    pub verdict: XrVerdict,
    pub confidence: Confidence,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeVersionRow {
    pub path: String,
    pub version: VersionInfo,
}

/// Inventory a Unity player directory (exe + `*_Data/` layout).
pub fn inventory_path(root: impl AsRef<Path>) -> Result<UnityInventory, String> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(format!("not a directory: {}", root.display()));
    }
    let mut notes = Vec::new();
    let data_dir = find_data_dir(root);
    let data_dir_s = data_dir.as_ref().map(|p| p.display().to_string());

    let app_info = data_dir
        .as_ref()
        .and_then(|d| read_trimmed(d.join("app.info")));
    let boot_config = data_dir.as_ref().and_then(|d| {
        let p = d.join("boot.config");
        fs::read_to_string(p).ok().map(|s| {
            s.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
    });

    let scripting_assemblies = data_dir
        .as_ref()
        .map(|d| read_scripting_assemblies(&d.join("ScriptingAssemblies.json")))
        .unwrap_or_default();

    let runtime_initialize_on_loads = data_dir.as_ref().and_then(|d| {
        let p = d.join("RuntimeInitializeOnLoads.json");
        fs::read_to_string(p).ok().and_then(|s| {
            serde_json::from_str::<serde_json::Value>(&s)
                .ok()
                .and_then(|v| v.as_array().map(|a| a.len()))
        })
    });

    let plugins = data_dir
        .as_ref()
        .map(|d| list_plugins(&d.join("Plugins")))
        .unwrap_or_default();

    let metadata = data_dir.as_ref().map(|d| peek_metadata(d));

    let addressables_hint = data_dir
        .as_ref()
        .map(|d| d.join("StreamingAssets").join("aa").is_dir())
        .unwrap_or(false);

    let (xr_stock_modules, xr_packages) = classify_assemblies(&scripting_assemblies);
    let xr_subsystem_manifests = data_dir
        .as_ref()
        .map(|d| find_subsystem_manifests(d))
        .unwrap_or_default();

    let mut native_xr_imports = Vec::new();
    let mut external_vr_indicators = Vec::new();
    let mut key_hashes = Vec::new();
    let mut pe_versions = Vec::new();

    // Hash player exe + GameAssembly / UnityPlayer when present.
    for name in ["GameAssembly.dll", "UnityPlayer.dll"] {
        let p = root.join(name);
        if p.is_file() {
            if let Some(h) = hash_file(&p) {
                key_hashes.push(h);
            }
            pe_versions.push(PeVersionRow {
                path: p.display().to_string(),
                version: version_info_for_file(&p),
            });
            if let Ok(prog) = load_path(&p) {
                for e in &prog.imports {
                    let dll = e.dll.to_ascii_lowercase();
                    let name = e.name.as_deref().unwrap_or("").to_ascii_lowercase();
                    if dll.contains("openxr")
                        || dll.contains("xr")
                        || name.contains("openxr")
                        || name.contains("xrgetinstance")
                    {
                        let label =
                            format!("{}!{}", e.dll, e.name.clone().unwrap_or_else(|| "?".into()));
                        if !native_xr_imports.contains(&label) {
                            native_xr_imports.push(label);
                        }
                    }
                }
            }
        }
    }
    for p in fs::read_dir(root).into_iter().flatten().flatten() {
        let path = p.path();
        let fname = path
            .file_name()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if fname.ends_with(".exe") {
            if let Some(h) = hash_file(&path) {
                key_hashes.push(h);
            }
            pe_versions.push(PeVersionRow {
                path: path.display().to_string(),
                version: version_info_for_file(&path),
            });
        }
        if fname.contains("inject") && fname.ends_with(".dll") {
            external_vr_indicators.push(format!("sidecar_dll:{}", path.display()));
        }
        if fname.contains("openxr") && fname.ends_with(".dll") && xr_packages.is_empty() {
            external_vr_indicators.push(format!("openxr_loader_no_xr_packages:{}", path.display()));
        }
        if fname.starts_with("dxgi") && fname.ends_with(".dll") {
            external_vr_indicators.push(format!("dxgi_proxy:{}", path.display()));
        }
    }

    if scripting_assemblies.is_empty() && data_dir.is_none() {
        notes.push("no *_Data directory or ScriptingAssemblies.json found".into());
    }

    let engine = EngineFingerprint {
        il2cpp: metadata.as_ref().is_some_and(|m| m.present)
            || root.join("GameAssembly.dll").is_file(),
        mono: scripting_assemblies.iter().any(|a| a.contains("mscorlib"))
            && !root.join("GameAssembly.dll").is_file(),
        burst: scripting_assemblies
            .iter()
            .any(|a| a.contains("Unity.Burst")),
        urp: scripting_assemblies.iter().any(|a| {
            a.contains("UniversalRenderPipeline") || a.contains("Unity.RenderPipelines.Universal")
        }),
        hdrp: scripting_assemblies.iter().any(|a| {
            a.contains("HighDefinition") || a.contains("Unity.RenderPipelines.HighDefinition")
        }),
    };

    let (verdict, confidence) = verdict(
        &xr_stock_modules,
        &xr_packages,
        &xr_subsystem_manifests,
        &native_xr_imports,
        &external_vr_indicators,
    );

    Ok(UnityInventory {
        schema_version: SCHEMA_VERSION,
        root: root.display().to_string(),
        data_dir: data_dir_s,
        app_info,
        boot_config,
        scripting_assemblies,
        runtime_initialize_on_loads,
        plugins,
        metadata,
        addressables_hint,
        engine,
        xr_stock_modules,
        xr_packages,
        xr_subsystem_manifests,
        native_xr_imports,
        external_vr_indicators,
        key_hashes,
        pe_versions,
        verdict,
        confidence,
        notes,
    })
}

fn find_data_dir(root: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("_Data"))
                    .unwrap_or(false)
        })
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_scripting_assemblies(path: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    // Format: { "names": ["A.dll", ...], "types": [...] }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(names) = v.get("names").and_then(|n| n.as_array()) {
            return names
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
    }
    Vec::new()
}

fn list_plugins(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p
                .extension()
                .map(|x| x.eq_ignore_ascii_case("dll") || x.eq_ignore_ascii_case("so"))
                .unwrap_or(false)
            {
                out.push(p.display().to_string());
            }
        }
    }
    walk(dir, &mut out);
    out.sort();
    out
}

fn peek_metadata(data_dir: &Path) -> MetadataPeek {
    let path = data_dir
        .join("il2cpp_data")
        .join("Metadata")
        .join("global-metadata.dat");
    let path_s = path.display().to_string();
    if !path.is_file() {
        return MetadataPeek {
            path: path_s,
            present: false,
            magic: None,
            version: None,
            encrypted_or_obfuscated: false,
            note: Some("global-metadata.dat not found".into()),
        };
    }
    let Ok(bytes) = fs::read(&path) else {
        return MetadataPeek {
            path: path_s,
            present: true,
            magic: None,
            version: None,
            encrypted_or_obfuscated: false,
            note: Some("failed to read metadata".into()),
        };
    };
    match Il2CppMetadata::peek(&bytes) {
        Ok((magic, version, _)) => MetadataPeek {
            path: path_s,
            present: true,
            magic: Some(format!("{magic:#010x}")),
            version: Some(version),
            encrypted_or_obfuscated: false,
            note: None,
        },
        Err(ghidrust_il2cpp::Error::EncryptedOrObfuscated {
            magic,
            version_field,
        }) => MetadataPeek {
            path: path_s,
            present: true,
            magic: Some(format!("{magic:#010x}")),
            version: Some(version_field),
            encrypted_or_obfuscated: true,
            note: Some(format!(
                "expected magic {METADATA_MAGIC:#010x}; treat as encrypted/obfuscated"
            )),
        },
        Err(e) => MetadataPeek {
            path: path_s,
            present: true,
            magic: None,
            version: None,
            encrypted_or_obfuscated: false,
            note: Some(e.to_string()),
        },
    }
}

fn classify_assemblies(names: &[String]) -> (Vec<String>, Vec<String>) {
    let mut stock = Vec::new();
    let mut packages = Vec::new();
    for n in names {
        let l = n.to_ascii_lowercase();
        if l.contains("unityengine.xrmodule") || l.contains("unityengine.vrmodule") {
            stock.push(n.clone());
        } else if l.contains("unity.xr.")
            || l.contains("unityengine.xr.")
            || l.contains("openxr")
            || l.contains("oculus")
            || l.contains("steamvr")
            || l.contains("openvr")
            || l.contains("xr.management")
        {
            // Stock modules already caught; remaining XR-ish → packages/providers
            if !l.contains("unityengine.xrmodule") && !l.contains("unityengine.vrmodule") {
                packages.push(n.clone());
            }
        }
    }
    (stock, packages)
}

fn find_subsystem_manifests(data_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let roots = [data_dir.join("StreamingAssets"), data_dir.join("Plugins")];
    for root in roots {
        if !root.exists() {
            continue;
        }
        fn walk(dir: &Path, out: &mut Vec<String>) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p
                    .file_name()
                    .map(|n| n == "UnitySubsystemsManifest.json")
                    .unwrap_or(false)
                {
                    out.push(p.display().to_string());
                }
            }
        }
        walk(&root, &mut out);
    }
    out.sort();
    out
}

fn hash_file(path: &Path) -> Option<FileHash> {
    let data = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    Some(FileHash {
        path: path.display().to_string(),
        sha256: hex::encode(digest),
    })
}

fn verdict(
    stock: &[String],
    packages: &[String],
    manifests: &[String],
    native: &[String],
    external: &[String],
) -> (XrVerdict, Confidence) {
    let has_stock = !stock.is_empty();
    let has_pkg = !packages.is_empty() || !manifests.is_empty();
    let has_ext = !external.is_empty();
    let has_native = !native.is_empty();

    if !has_stock && !has_pkg && !has_ext && !has_native {
        return (XrVerdict::None, Confidence::Medium);
    }
    if has_ext && has_pkg {
        return (XrVerdict::Mixed, Confidence::High);
    }
    if has_ext && !has_pkg {
        return (XrVerdict::ExternalModLikely, Confidence::High);
    }
    if has_pkg {
        return (XrVerdict::UnityXrPackaged, Confidence::High);
    }
    if has_stock && !has_pkg {
        let conf = if has_native {
            Confidence::Medium
        } else {
            Confidence::High
        };
        return (XrVerdict::StockStubsOnly, conf);
    }
    (XrVerdict::None, Confidence::Low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_stubs_verdict() {
        let dir = tempfile_dir("stock");
        let data = dir.join("Game_Data");
        fs::create_dir_all(&data).unwrap();
        let json = r#"{"names":["UnityEngine.dll","UnityEngine.XRModule.dll","Assembly-CSharp.dll"],"types":[0,0,0]}"#;
        fs::write(data.join("ScriptingAssemblies.json"), json).unwrap();
        let inv = inventory_path(&dir).unwrap();
        assert_eq!(inv.verdict, XrVerdict::StockStubsOnly);
        assert!(inv.xr_stock_modules.iter().any(|s| s.contains("XRModule")));
        assert!(inv.xr_packages.is_empty());
    }

    #[test]
    fn packaged_xr_verdict() {
        let dir = tempfile_dir("pkg");
        let data = dir.join("Game_Data");
        fs::create_dir_all(&data).unwrap();
        let json = r#"{"names":["Unity.XR.Management.dll","Unity.XR.OpenXR.dll"],"types":[0,0]}"#;
        fs::write(data.join("ScriptingAssemblies.json"), json).unwrap();
        let inv = inventory_path(&dir).unwrap();
        assert_eq!(inv.verdict, XrVerdict::UnityXrPackaged);
    }

    fn tempfile_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ghidrust_unity_inv_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }
}

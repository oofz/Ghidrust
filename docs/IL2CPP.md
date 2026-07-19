# IL2CPP + Unity inventory (Ghidrust)

Hand-rolled support for Unity IL2CPP metadata and player-install inventory. No Il2CppDumper, Cpp2IL, or goblin at runtime — see [DEPENDENCIES.md](../DEPENDENCIES.md).

## Commands

```text
ghidrust strings <path> [--raw] [--match substr|token|whole|glob] [--limit N] [--out FILE]
ghidrust bytes <path> --addr HEX [--count N] [--out FILE] [--json]
ghidrust il2cpp meta <global-metadata.dat> [--filter SUB] [--json] [--out FILE]
ghidrust il2cpp map --binary <GameAssembly.dll> --meta <metadata.dat> [--script-json]
ghidrust il2cpp stubs --binary <GameAssembly.dll> [--filter SUB]
ghidrust il2cpp icalls --binary <UnityPlayer.dll> [--filter SUB] [--json] [--out FILE]
ghidrust xrefs … [--skip-stubs] [--classify] [--out FILE]
ghidrust disasm … [--out FILE]
ghidrust decompile … [--follow-stub] [--out FILE]
ghidrust unity-inventory <player-dir> [--json]
```

## Engine icall resolve (name‖fn tables)

Unity engine PEs often store parallel pointer arrays: one of C-string name VAs (`Namespace.Type::method` / `*_Injected`) and one of code VAs. After `Create Address Tables` (stitched runs with `DataPtrs` / `CodePtrs` roles):

```text
ghidrust strings <engine.dll> --filter <ICallNameFragment> --json
ghidrust xrefs <engine.dll> --to <name_string_va> --json    # hits rdata pointer slots
ghidrust il2cpp icalls --binary <engine.dll> --filter <ICallNameFragment> --json
ghidrust bytes <engine.dll> --addr <fn_va> --count 64 --json
ghidrust disasm <engine.dll> --addr <fn_va> --count 20 --json
```

`il2cpp icalls` never invents RVAs: it only emits pairs when a name table of length `N` sits adjacent to a code table of length `N`. Ambiguous multi-table hits are returned as candidates with confidence.

## Resolve stubs vs real callers

GameAssembly resolve thunks (`LEA` name → resolve → store slot → `jmp reg`) are lazy. Prefer:

```text
ghidrust xrefs GA.dll --to HEX --skip-stubs --classify --json
ghidrust il2cpp stubs --binary GA.dll --filter <ICallNameFragment> --json
ghidrust decompile GA.dll --addr <stub_va> --follow-stub --json
```

`--follow-stub` reports `follow_stub.status = runtime_unresolved` when the slot is still zero (filled at runtime). Filter matches parsed `icall_name` or the C-string at `name_string_va`.

## MCP tools

Launch: `ghidrust mcp` (or `target/release/ghidrust.exe mcp` after build). Stdio JSON-RPC; no host-specific paths required.

| Tool | Args | Purpose |
|------|------|---------|
| `il2cpp_meta` | `path`, optional `filter` | Parse `global-metadata.dat` → types/methods |
| `il2cpp_map` | `binary`, `meta`, optional `filter` | Metadata ↔ RVA map (`rva` null when unproven) |
| `il2cpp_stubs` | `binary`, optional `filter`, `max` | Classify resolve stubs |
| `il2cpp_icalls` | `binary`, optional `filter` | Engine name‖fn icall tables |
| `read_bytes` | `path`, `addr`, optional `count` | Raw VA dump |
| `unity_inventory` | `path` | Player layout inventory (assemblies, plugins, metadata) |
| `list_strings` | `path`, optional `encoding`/`filter`/`match`/`limit`/`raw`/`min` | Blob-capable string scan |
| `get_xrefs_to` | `path`, `addr`, optional `skip_stubs`/`classify` | Data-ptr + stub-aware xrefs |
| `decompile` | `path`, optional `addr`/`count`/`stage`/`follow_stub` | Follow resolve stub when mapped |

## Metadata version matrix

| Metadata version | Dialect | Status |
|------------------|---------|--------|
| 27.x | `V27` | supported |
| 29.x | `V29` | supported |
| 31.x | `V31` | supported |
| 24.x family | — | P1 (unsupported error with hint) |
| 39 / 106 | — | P1 (sectioned / variable-width) |

Magic must be `0xFAB11BAF`. Wrong magic → fail closed. CLI/MCP JSON:

```json
{
  "error": "metadata_encrypted_or_obfuscated",
  "magic": "0x…",
  "next_steps": [
    "Use engine PE strings + il2cpp icalls for native internal-call RVAs",
    "Treat GameAssembly resolve stubs as lazy thunks, not gameplay callers (xrefs --skip-stubs)",
    "Instance/type latch may require live inspection when metadata is unavailable"
  ]
}
```

## Notes

1. Managed type/method names live in metadata heaps — use `il2cpp meta`, not PE string scans alone.
2. Method RVAs are emitted only when CodeRegistration-style pointer arrays pass multi-field validation; otherwise `rva: null`.
3. Encrypted/obfuscated metadata is reported with `next_steps`, not guessed.
4. `unity-inventory` classifies scripting assemblies and plugins from the player layout (including stock engine XR modules vs XR provider packages when present).
5. Lone rdata qword pointers to strings are found by `xrefs --to` (kind `ptr`), not only by address-table slots.

## Fixtures

Synthetic acceptance fixtures (no private game trees):

```text
fixtures/il2cpp/meta_v27.dat
fixtures/il2cpp/meta_v29.dat
fixtures/il2cpp/meta_v31.dat
fixtures/il2cpp/il2cpp_stub_lab.pe
```

Regenerate: `python scripts/gen_il2cpp_fixtures.py`

## Unity inventory schema

`unity-inventory` emits `schema_version: 1` with scripting assemblies, plugins, metadata peek, engine fingerprint, and optional XR-related fields:

- `xr_stock_modules` / `xr_packages` / `xr_subsystem_manifests`
- `native_xr_imports` / `external_vr_indicators`
- `verdict`: `none` | `stock_stubs_only` | `unity_xr_packaged` | `external_mod_likely` | `mixed`
- `confidence`: `low` | `medium` | `high`

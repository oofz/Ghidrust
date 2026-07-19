---
name: ghidrust
description: >
  Use Ghidrust (Rust RE toolkit: PE/ELF/blob load, x86-64 disasm, Auto Analysis, projects,
  CLI/MCP, egui GUI, IL2CPP metadata, Unity player inventory, GPU analyzer kernels +
  multipass decompile) to reverse-engineer binaries without Ghidra. Exhaustive feature
  catalog with when-to-use guidance.
  Triggers: /ghidrust, reverse engineer, RE a PE/ELF, disassemble, RTTI, auto analysis,
  analyze binary, Ghidrust project, MCP ghidrust, strings/functions, GPU decompile,
  IL2CPP, global-metadata, unity-inventory, GameAssembly, analyzer-bench,
  rtti-gpu-bench, bulk-bench.
metadata:
  short-description: "Ghidrust RE — CLI, MCP, IL2CPP, Unity, analyzers, GPU"
---

# Ghidrust — agent skill

Hand-rolled **Rust** reverse-engineering core (Ghidra-inspired labels; measurable **Ghidra-surpass** target on x86-64, Stage-0 decompile today). Prefer **CLI or MCP** for agents; GUI is for humans. **Never invent analysis** — if a fixture has no evidence, outputs are empty/honest.

## Paths & binaries

| Item | Path / command |
|------|----------------|
| Workspace root | repo root (`Cargo.toml` with `ghidrust-core`, `ghidrust-cli`, `ghidrust-gui`, `ghidrust-decomp`, `ghidrust-il2cpp`, `ghidrust-unity-inventory`) |
| CLI | `cargo run -p ghidrust-cli --release -- <cmd>` or `target/release/ghidrust.exe` |
| GUI | `cargo run -p ghidrust-gui --release` |
| Fixtures | `fixtures/tiny_x64.pe`, `fixtures/analysis_lab.pe`, `fixtures/tiny_x64.elf`, `fixtures/il2cpp/*` |
| Docs | `README.md`, `docs/IL2CPP.md`, `docs/GPU_ANALYZER_MATRIX.md`, `docs/PARALLEL_RE_RESEARCH.md` |
| Core API | `load_path` / `load_path_opts` / `load_blob`, `collect_strings_opts`, `run_analyzers_opts`, `Project`, `gpu_analyzers`, `bulk_scan` |

CLI always builds with `gpu` feature on deps. On Windows PowerShell: `.\target\release\ghidrust.exe …`.

```bash
cargo build -p ghidrust-cli --release
cargo build -p ghidrust-gui --release
```

---

## Agent friction SOPs (required)

- **Version / stale MCP**: Call `server_info` first (or read `initialize.serverInfo`). This skill requires **`tool_surface >= 2`** (live process + artifacts + inventory). If `server_info` is missing, `tool_surface` is below that minimum, or `process_list` / `artifact_query` / `inventory` are absent from `tools/list` → rebuild `ghidrust`, point the MCP `command` at that binary, **restart the MCP server**. Do **not** conclude live process is unsupported; do **not** invent heap-scan scripts as a substitute. CLI/GUI/MCP share one package version (`ghidrust --version`, MCP `version`, egui About).
- **Artifacts**: When envelope `entry_count` > preview or the host truncates tool text, drain via `artifact_query` / `artifact get` until `next_offset` is null. Never assume truncated MCP text is complete.
- **Program identity**: Prefer `load` with absolute `path`, or `project` + `file_id`. Facts always include `resolved_path` or honest null — resolve before analyze/decompile.
- **Inventory / tree**: Use `inventory <dir>` (PE VERSIONINFO + exe/dll) before OS `dir`/`Get-Item`. Use `tree` / `list_tree` for non-PE sidecars (existence/size only; no unpack).
- **Address→function**: Always pass `addr` to `decompile` / `disassemble` / `gpu_decompile`; trust `resolved_entry` / `resolve` meta. Mid-body hits resolve to containing entry; unmapped → `no_containing_function` (no invented 1-insn fn).
- **RTTI catalog**: Prefer `rtti_query` (`--filter`/`--exact`) before mangled `.?AV` string archaeology. Multi-vtable types report `vtable_vas[]` honestly.
- **UTF-16 xrefs**: If `search_strings` returns `utf16le`, query `get_string_xrefs` with `encoding=all` (or `utf16le`) before concluding “no refs”.
- **Live process (Windows)**: Multi-step live work **must** use MCP (or one long-lived process) — `process_list` → `process_attach` → `process_modules` → `process_resolve` (`static_to_live`) → `process_read` → optional `process_regions` / `process_detach`. Never chain separate CLI `ghidrust process` spawns expecting the same `session_id` (sessions are in-process). Bytes ≠ types. No write/breakpoints in MVP.
- **IL2CPP offline → live**: (1) `il2cpp_meta` / `il2cpp_map` for method RVAs (null = unknown offline). (2) `decompile` + `follow_stub` for resolve stubs with mapped slots. (3) On `runtime_unresolved` / `trampoline_or_invoker` (see `next_steps` in JSON) → live attach → `process_resolve(module, rva)` → `process_read` for class/instance bytes. `follow_stub` is **not** “get managed method body for every RVA.”
- **Skill bootstrap**: GUI project open / Start writes `.grok/skills/ghidrust/SKILL.md` (disk or embedded fallback) and shows a fail-loud checklist (mcp/skill/agents/context + hash).
- **Do not**: invent enum ordinals; treat `section_notes` as proof of hooks; read `.gdecomp` dumps as text (metrics JSON only).

## Decision tree

```
Need durable workspace?
  YES → project create → import → analyze [--analyzer …] [--gpu] → export
  NO  → load | disasm | rtti | analyze [--analyzer …] [--gpu]

Need machine-readable?
  → --json  OR  ghidrust mcp
  → large dumps → artifact spill + artifact_query drain

Need install layout without shell?
  → inventory DIR   (PE versions + exe/dll)
  → tree DIR        (sidecars / media existence)

Need GPU for selected analyzers (not just bench)?
  → analyze … --gpu   OR  GUI checkbox  OR  MCP analyze gpu:true
  → bulk mode for ASCII Strings + SIMT seed enrich per selected name

Need GPU decompile at a VA?
  → gpu-decompile <path> --addr HEX   (metrics JSON; .gdecomp opaque)

Need RTTI CPU vs GPU timings (PCIe split)?
  → rtti-gpu-bench <path>

Need full matrix bench?
  → analyzer-bench / analyzer-bench-matrix

Need decompiled C?
  → Staged capability (be honest about which stage you have):
     Stage-1    (**default**): expression-folded SSA +
                                structure + types → readable if/while/do-while/return with nested
                                arith (single-use temps inlined; JSON `folded_temps`), named
                                import/function calls when the program knows them, `this` on
                                `Class::method`, float seeds from SSE notes, early-exit `return`
                                polish, emit-time tokens (`token_count`) for GUI click-nav.
                                Still: typed params/locals, `p->field_<off>` / `p[i]`, switch,
                                `&&`/`||`, break/continue (lab goto_rate <0.15). Mid-body `addr`
                                resolves to containing function. CLI: `decompile PATH`; GUI:
                                Decompiler (Stage-1); MCP: `decompile` (default stage1). Library:
                                `ghidrust_decomp::decompile_stage1_at`. Rubric:
                                docs/READABILITY_RUBRIC.md. Falls back when lift <50% or
                                irreducible — no fabrication.
     Stage-0    (oracle):  `decompile PATH --stage0` → CFG→goto / mnemonic-style pseudo-C.
                                Kept as regression baseline; Ghidra head-to-head uses this only
                                for pre-Stage-1 checks, never for external comparison tables.
     Stage-0.5  (oracle):  `decompile PATH --stage05` → IR-informed emit (xor a,a → a=0, augmented
                                assign, push/pop, direct call, flag-driven jcc). Same fallback
                                rules — Stage-0.5 is IR-informed but pre-SSA.
     typed-C    (in progress → Hex-Rays ceiling): expression fold + naming shipped;
                                unions/bitfields/EH still evidence-gated after Ghidra bar.
  → Do not invent Hex-Rays-quality C; emit only what the current stage produces.
    See docs/READABILITY_RUBRIC.md (readability checklist).

Need Stage-0 vs Stage-0.5 vs Stage-1 wall-clock + lift-ratio numbers?
  → `decompile-bench PATH [--functions N] [--count N] [--out FILE] [--json]`

Need Ghidra ↔ Ghidrust head-to-head?
  → `ghidra-headtohead PATH [--ghidra DIR] [--captured JSON] [--out FILE] [--json]`
  → `--ghidra DIR` auto-spawns `analyzeHeadless` (locates `support/analyzeHeadless(.bat)`,
     writes the embedded `DecompileAndReport.java`, parses per-function `wall_us`).
  → `--captured JSON` replays a manual capture for offline / airgapped hosts.
  → When neither is supplied, the report is methodology-only: Ghidra column left blank
     + full runbook (dev/GHIDRA_HEADTOHEAD.md). Spawn failures surface as factual
     `ghidra spawn failed: <reason>` notes — no fabricated timings.

Unity player / IL2CPP?
  → unity-inventory GAME_DIR for install layout (assemblies, plugins, metadata)
  → il2cpp meta …/global-metadata.dat for managed types/methods
  → il2cpp stubs / map on GameAssembly.dll; xrefs --skip-stubs; decompile --follow-stub
  → encrypted metadata (wrong magic) → report encrypted, do not invent types
  → See docs/IL2CPP.md

Large string dumps / raw non-PE files?
  → strings PATH --match token|whole --limit N --out FILE
  → strings PATH --raw for blobs (metadata dumps, etc.)
```

---

## Select analyzers + GPU (CLI / GUI / MCP)

### CLI — one-shot

```bash
# Comma list
ghidrust analyze PATH --analyzers "ASCII Strings,Function Start Search" --json

# Individual flags (repeatable)
ghidrust analyze PATH --analyzer "ASCII Strings" --analyzer "Stack" --json

# Defaults (catalog default_enabled) + GPU enrich
ghidrust analyze PATH --gpu --json

# Subset + GPU
ghidrust analyze PATH --analyzer "WindowsPE x86 PE RTTI Analyzer" --gpu --json
```

### CLI — project

```bash
ghidrust project analyze PROJ_DIR --file ID \
  --analyzer "Function Start Search" \
  --analyzer "ASCII Strings" \
  --gpu
# or: --analyzers "a,b,c" --gpu
```

### What `--gpu` does

1. Sets bulk scan mode to **GPU-or-fallback** (ASCII Strings uses wgpu when available).
2. After each CPU analyzer run, runs that analyzer’s **GPU strategy kernel** (`rtti_scan`, `printable_run`, …) and **host-merges** seeds into the program.
3. Annotates result messages with `gpu_enrich hits_merged=… backend=…`.
4. Restores previous bulk mode after the run.

**Not** the same as `gpu-decompile` (VRAM multipass decompile of entry).

### GUI

**Analysis options** dialog:

- Checkbox per analyzer (Defaults / All / None).
- **GPU (strings bulk + per-analyzer seed kernels)** checkbox.
- **Run Analysis** runs only checked analyzers; GPU flag applies as above.

### MCP (`ghidrust mcp`)

Requires **`tool_surface >= 2`**. Check with `server_info` after connect.

| Tool | Args | Notes |
|------|------|-------|
| `server_info` | — | Package `version`, `tool_surface`, features, live session_model |
| `load` | `path` **or** `project`+`file_id` | Map + `section_notes` + `resolved_path` |
| `disassemble` | `path`, optional `addr`, `count` | Containing-fn resolve + `decode_gaps` |
| `rtti` / `rtti_query` | `path`, optional `filter`/`exact`/`match` | Catalog; multi-vtable; artifact if large |
| `artifact_get` / `artifact_query` / `artifact_list` | `id` / optional `offset`/`limit` / optional `max` | Drain or list spilled results |
| `inventory` | `path`, optional `max_depth`/`hash` | PE VERSIONINFO + exe/dll catalog |
| `list_tree` | `path`, optional depth/ext/glob | Bounded tree; errors as rows |
| `list_analyzers` | — | Auto Analysis names |
| `analyze` | `path`, optional `analyzers[]`, **`gpu`** | CPU + optional GPU enrich |
| `list_strings` / `search_strings` | `path`, optional `encoding`, `filter`, **`match`**, `min`, **`limit`**, **`raw`** | Blob scan when `raw:true` |
| `get_xrefs_to` | `path`, `addr`, optional **`skip_stubs`**, **`classify`** | RIP/tables + data ptrs; IL2CPP stubs |
| `get_xrefs_from` | `path`, `addr`, optional `count` | Xrefs from VA |
| `get_string_xrefs` | `path`, `filter`, optional `encoding` | UTF-16LE parity (`ascii`\|`utf16le`\|`all`) |
| `list_imports` / `get_import_xrefs` | `path`, optional `dll`/`name` | PE IAT |
| `function_at` / `get_function_by_address` | `path`, `addr` | Containing function |
| `read_bytes` | `path`, `addr`, optional `count` | Raw VA hex dump |
| `il2cpp_meta` | `path`, optional `filter` | `global-metadata.dat` types/methods (v27/29/31); encrypted → `next_steps` JSON |
| `il2cpp_map` | `binary`, `meta`, optional `filter` | Method RVA map; null when unproven |
| `il2cpp_stubs` | `binary`, optional `filter`, `max` | Resolve stubs (filter: name or C-string at `name_string_va`) |
| `il2cpp_icalls` | `binary`, optional `filter` | Engine name‖fn icall tables → index / RVA |
| `unity_inventory` | `path` | Player dir + PE VERSIONINFO helpers |
| `decompile` | `path`, optional `addr`, `count`, `stage`, **`follow_stub`** | Resolve meta + Stage-1; JSON: `folded_temps`, `token_count`, `goto_rate`; `follow_stub` may be `runtime_unresolved` / `trampoline_or_invoker` with `next_steps` → live process |
| `list_gpu_strategies` | — | Strategy matrix |
| `gpu_decompile` | `path`, optional `addr`, `out` | VA resolve; metrics JSON; dump opaque |
| `rtti_gpu_bench` | `path` | CPU vs GPU RTTI |
| `process_list` / `process_attach` / `process_detach` / `process_modules` / `process_read` / `process_resolve` / `process_regions` | pid / session / module / rva / max | Live Process Bridge (Windows; read-only) |

MCP launch: `ghidrust mcp` / `target/release/ghidrust.exe mcp` (stdio; no host-specific paths).

---

## Unity / IL2CPP (CLI + MCP)

Canonical detail: [`docs/IL2CPP.md`](../docs/IL2CPP.md).

| Task | CLI | MCP |
|------|-----|-----|
| Player install inventory | `ghidrust unity-inventory GAME_DIR --json` | `unity_inventory` `{path}` |
| Managed types/methods | `ghidrust il2cpp meta META.dat [--filter F] --json` | `il2cpp_meta` `{path, filter?}` |
| Metadata ↔ RVA | `ghidrust il2cpp map --binary GA.dll --meta META.dat --json` | `il2cpp_map` `{binary, meta, filter?}` |
| Engine icall name→fn | `ghidrust il2cpp icalls --binary ENGINE.dll --filter F --json` | `il2cpp_icalls` `{binary, filter?}` |
| Resolve stubs | `ghidrust il2cpp stubs --binary GA.dll --filter F --json` | `il2cpp_stubs` `{binary, filter?, max?}` |
| Raw bytes at VA | `ghidrust bytes PATH --addr HEX --count N --json` | `read_bytes` `{path, addr, count?}` |
| Xrefs (incl. data ptrs / skip stubs) | `ghidrust xrefs PATH --to HEX [--skip-stubs] [--classify]` | `get_xrefs_to` `{…, skip_stubs, classify}` |
| Decompile through stub | `ghidrust decompile GA.dll --addr HEX --follow-stub --json` | `decompile` `{…, follow_stub: true}` |
| Live resolve + read (runtime slots) | `ghidrust process …` (single spawn only) | MCP: attach → resolve → read (keep session) |
| Strings on metadata blob | `ghidrust strings META.dat --raw --match token --limit N` | `list_strings` `{path, raw:true, match, limit}` |

Wrong metadata magic → encrypted/obfuscated JSON with `next_steps` (fail closed). Never invent method or icall RVAs when pairing/map leaves them null. Empty/runtime stub slots → `runtime_unresolved` + live `next_steps`; do not heap-scan as a substitute.

**Engine icall recipe (generic):**

```bash
ghidrust strings ENGINE.dll --filter ICallNameFragment --json
ghidrust xrefs ENGINE.dll --to <name_string_va> --json
ghidrust il2cpp icalls --binary ENGINE.dll --filter ICallNameFragment --json
ghidrust bytes ENGINE.dll --addr <fn_va> --count 64 --json
ghidrust disasm ENGINE.dll --addr <fn_va> --count 20 --json
```

---

## CLI features (exhaustive)

Add `--json` for structured stdout.

| Feature | Command |
|---------|---------|
| Help | `ghidrust help` |
| Version | `ghidrust version` / `--version` / `-V` `[--json]` (package + `tool_surface`) |
| Load | `ghidrust load <path\|--project DIR --file-id ID>` |
| Disasm | `ghidrust disasm <path> [--addr HEX] [--count N] [--skip-bad]` |
| Strings | `ghidrust strings <path> [--raw] [--encoding …] [--match MODE] [--limit N] [--out FILE] [--filter SUB]` |
| Xrefs | `ghidrust xrefs <path> (--to\|--from\|--string\|--import) [--encoding ascii\|utf16le\|all] [--skip-stubs] [--classify] [--out FILE]` |
| Bytes | `ghidrust bytes <path> --addr HEX [--count N] [--out FILE]` |
| Imports | `ghidrust imports <path> [--dll\|--name]` |
| Function-at | `ghidrust function-at <path> --addr HEX` |
| Inventory | `ghidrust inventory <dir> [--max-depth N] [--hash]` |
| Tree | `ghidrust tree <path> [--max-depth N] [--ext LIST] [--name GLOB]` |
| Artifact | `ghidrust artifact get\|query\|list …` |
| Process (Windows) | `ghidrust process list\|attach\|detach\|modules\|read\|resolve\|regions …` |
| IL2CPP | `ghidrust il2cpp meta\|map\|stubs\|icalls …` (see `docs/IL2CPP.md`) |
| Unity inventory | `ghidrust unity-inventory <game-dir>` |
| RTTI catalog | `ghidrust rtti <path> [--filter\|--name\|--exact] [--match MODE]` |
| List analyzers | `ghidrust analyzers` |
| **Analyze** | `ghidrust analyze <path> [--analyzers a,b \| --analyzer NAME …] [--gpu]` |
| Bulk bench | `ghidrust bulk-bench <path>` |
| Decompile (Stage-1 default; `--follow-stub` for IL2CPP; metrics with `--verbose`) | `ghidrust decompile <path> [--addr HEX] [--follow-stub] [--verbose]` |
| Decompile (Stage-0 CFG scaffolding, oracle) | `ghidrust decompile <path> --stage0` |
| Decompile (Stage-0.5 IR-informed, oracle) | `ghidrust decompile <path> --stage05` |
| Decompile bench (Stage-0 vs Stage-0.5 vs Stage-1) | `ghidrust decompile-bench <path> [--functions N] [--count N] [--out F]` |
| Ghidra head-to-head (shared-entry, Stage-1) | `ghidrust ghidra-headtohead <path> [--ghidra DIR] [--captured JSON] [--out F]` |
| **GPU decompile** | `ghidrust gpu-decompile <path> [--addr HEX] [--out F] [--metrics F]` |
| RE bench | `ghidrust re-bench <path>` |
| Analyzer CPU/GPU matrix bench | `ghidrust analyzer-bench <path> [--large] [--out F]` |
| Strategy matrix | `ghidrust analyzer-bench-matrix` |
| **RTTI GPU bench** | `ghidrust rtti-gpu-bench <path> [--out F]` |
| Project | `create\|open\|import\|list\|analyze\|export` (analyze supports `--analyzer` / `--gpu`) |
| MCP | `ghidrust mcp` |

### Recipes

```bash
# Quick triage
ghidrust load PATH --json
ghidrust load --project PROJ --file-id ID --json
ghidrust strings PATH --encoding all --filter SomeName --match token --limit 50 --json
ghidrust xrefs PATH --string SomeName --encoding all --skip-stubs --json
ghidrust function-at PATH --addr 0x140001234 --json
ghidrust imports PATH --json
ghidrust rtti PATH --filter Widget --json
ghidrust analyze PATH --analyzer "ASCII Strings" --analyzer "Function Start Search" --json
ghidrust decompile PATH --addr 0x140001234 --json
ghidrust gpu-decompile PATH --addr 0x140001234 --metrics gdec.json --json

# Install / tree without OS shell
ghidrust inventory INSTALL_DIR --max-depth 8 --json
ghidrust tree GAME_DIR --ext dll,dat --name "*meta*" --json

# Artifact drain (when envelope entry_count > preview)
ghidrust artifact list --json
ghidrust artifact query ARTIFACT_ID --offset 0 --limit 64 --json
ghidrust artifact get ARTIFACT_ID

# Live process (Windows; read-only)
ghidrust process list --json
ghidrust process attach PID
ghidrust process modules SESSION --json
ghidrust process resolve SESSION --module app.exe --rva 0x1234 --json
ghidrust process read SESSION --addr LIVE_VA --size 64 --json
ghidrust process regions SESSION --json
ghidrust process detach SESSION

# Unity / IL2CPP
ghidrust unity-inventory GAME_DIR --json
ghidrust il2cpp meta GAME_DIR/*_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp stubs --binary GAME_DIR/GameAssembly.dll --filter Camera --json
ghidrust il2cpp icalls --binary GAME_DIR/UnityPlayer.dll --filter Camera --json
ghidrust xrefs GAME_DIR/GameAssembly.dll --to HEX --skip-stubs --classify --json

# GPU RTTI seed path on one analyzer
ghidrust analyze PATH --analyzer "WindowsPE x86 PE RTTI Analyzer" --gpu --json

# Project case
ghidrust project create PROJ --name Case
ghidrust project import PROJ PATH
ghidrust project analyze PROJ --analyzers "Function Start Search,ASCII Strings,WindowsPE x86 PE RTTI Analyzer" --gpu

# Performance
ghidrust bulk-bench PATH --json
ghidrust analyzer-bench PATH --large --out metrics.txt
ghidrust rtti-gpu-bench PATH --out rtti_metrics.txt --json
```

---

## GPU strategy matrix (all analyzers + decompile)

See `docs/GPU_ANALYZER_MATRIX.md`. Every Auto Analysis name has a dedicated strategy class (not one printable kernel rebranded). Examples:

| Analyzer | Strategy |
|----------|----------|
| ASCII Strings | `printable_run` |
| Unicode Strings | `cstr_multi` (host UTF-16LE authoritative) |
| Function Start Search | `prologue_seed` |
| WindowsPE x86 PE RTTI Analyzer | `rtti_scan` |
| Embedded Media | `magic_media` |
| Function ID | `hash_window` |
| … | `ghidrust analyzer-bench-matrix` |

Timing model: **pcie_upload / device_ms / pcie_download** split. On large binaries, on-device is often ≫ CPU seed; wall may still be setup+PCIe.

---

## Library / core

| API | When |
|-----|------|
| `run_analyzers(prog, names)` | CPU Auto Analysis (empty names → defaults) |
| **`run_analyzers_opts(prog, names, use_gpu)`** | Same + GPU bulk/enrich |
| `gpu_enrich_analyzers` | Seed merge only |
| `Project::analyze_file` / **`analyze_file_opts(..., use_gpu)`** | Project analyze |
| `set_preferred_bulk_mode` | Low-level bulk backend |
| `bench_analyzer` / `bench_all_analyzers` | Matrix harness |
| Feature `gpu` | wgpu; CLI enables it |

---

## Auto Analysis — exhaustive catalog (21)

Exact names, honest outputs. Use the `Name` column verbatim in
`--analyzer "…"` / `--analyzers "a,b"`. Every row is a **PASS** in the shipped
eval report ([`dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md`](../dev/EVAL_ANALYSIS_DECOMPILE_REPORT.md),
JSON: `dev/eval_analysis_decompile.json`); regenerate with
`cargo test -p ghidrust-cli --test eval_analysis_decompile -- --nocapture`.

Message column is the human status line (`[status] NAME — message`);
Output column names the field on `AnalyzerOutput` you get in `--json`
(`analysis.results[*]`).

| # | Name | What it does | Output field(s) | Message |
|---|---|---|---|---|
| 1 | `ASCII Strings` | Bulk ≥4-char printable scan (Sequential / ParallelCpu / GpuOrFallback backend). | `strings: [{va, value, length, encoding}]` | `found N ASCII string(s) [BulkScanMode…]` |
| 1b | `Unicode Strings` | UTF-16LE printable runs across mapped blocks. | `strings: [{va, value, length, encoding: utf16le}]` | `found N UTF-16LE string(s)` |
| 2 | `Aggressive Instruction Finder` | Fills real code gaps only; adds new `FunctionInfo` + a `DiscoveredRange`. No fabrication if the fixture has no gap. | `recovered_ranges: [{start, end}]` (+ `functions[]`) | `found N recovered code range(s)` |
| 3 | `Call Convention ID` | Tags each function with Win64/cdecl/stdcall/thiscall. | `conventions: [[va, name], …]` (+ `functions[*].calling_convention`) | `identified N calling convention(s)` |
| 4 | `Call-Fixup Installer` | Security-cookie / thunk stub detection. | `call_fixups: [{fixup_name, call_va}]` | `installed N call fixup(s)` |
| 5 | `Create Address Tables` | Contiguous VA tables in `.rdata` / data. | `address_tables: [{base, count, entries: [va, …]}]` | `found N address table(s)` |
| 6 | `Decompiler Parameter ID` | `mov [rbp+…], rcx/rdx` spill detection → `arg0:rcx` / `arg1:rdx`. No inventions on bare bodies. | `functions: [{entry, parameters: [str,…]}]` | `recovered parameters for N function(s)` |
| 7 | `Decompiler Switch Analysis` | Address tables → switch cases. | `switches: [{jump_va, cases: [[val, target], …]}]` | `recovered N switch table(s)` |
| 8 | `Demangler Microsoft` | MSVC `?…@@` demangler; `demangled` alongside raw. | `symbols: [{name, va, demangled?}]` | `demangled N symbol(s)` |
| 9 | `Embedded Media` | PNG / JPG / GIF / WAV / … magic scan. | `media: [{kind, va}]` | `found N media signature(s)` |
| 10 | `Function ID` | Prologue-window hash → shipped `fid_*` catalog match. | `fid_matches: [{entry, matched_name}]` | `matched N FID signature(s)` |
| 11 | `Function Start Search` | Entry + symbols + exact `55 48 89 e5` + orphan `sub rsp, imm8`; grows to `ret`/`int3`; drops mid-body seeds. | `functions: [{entry, end, name}]` | `identified N function start(s)` |
| 12 | `Non-Returning Functions - Discovered` | `int3`-terminated bodies + known no-return imports. | `noreturn_entries: [va, …]` (+ `functions[*].noreturn`) | `marked N noreturn function(s)` |
| 13 | `PDB MSDIA` | MSF7 reader with MSDIA-shaped filtering. | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (msdia→universal)` |
| 14 | `PDB Universal` | MSF7 reader, unfiltered stream symbols (`MSF7` marker included). | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (universal)` |
| 15 | `Shared Return Calls` | Callers reusing one epilogue (tail-call). | `shared_returns: [va, …]` | `marked N shared return site(s)` |
| 16 | `Stack` | Frame size + `param_…` slots from `sub rsp, imm` / `push rbp; mov rbp, rsp`; won't fabricate frames on functions with no real prologue. | `stack_frames: [[va, ["frame_size=0x…", "param_…", …]], …]` | `recovered N stack frame(s)` |
| 17 | `Variadic Function Signature Override` | Ensures `printf`/`sprintf`/`scanf` family symbols exist and marks them cdecl / `varargs=true` with a `format` param. | `varargs_entries: [va, …]` (+ `functions[*].varargs`) | `applied varargs to N function(s)` |
| 18 | `WindowsPE x86 PE RTTI Analyzer` | MSVC C++ RTTI: COL → class hierarchy → type-info → vtable, demangled class name. | `rtti: {classes: [{name, type_info_va, vtable_va, col_va, kind}], notes: [str,…]}` | `recovered N RTTI class record(s)` |
| 19 | `Windows x86 Propagate External Parameters` | Known Win32 API prototypes attached to import call sites. | `external_params: [[va, prototype], …]` | `applied N external parameter prototype(s)` |
| 20 | `WindowsResourceReference` | `.rsrc` records (`VERSION`, `RT_ICON`, …). | `resources: [{name, va}]` | `parsed N resource record(s)` |

**Defaults** (empty selection): `ASCII Strings`, `Unicode Strings`, `WindowsPE x86 PE RTTI Analyzer`, `Function Start Search`, `Create Address Tables`, `Embedded Media`, `Demangler Microsoft`.

With `--gpu`: same CPU output plus a `| gpu_enrich hits_merged=… backend=…` suffix on the human message. Not a replacement for `gpu-decompile`.

---

## Decompile methods — exhaustive catalog

All rows exercised by `eval_analysis_decompile.rs`; check the eval report for
the exact evidence (blocks / insns / ir_ops / lift ratio / GPU backend).

| Method | CLI | What you get | Output shape |
|---|---|---|---|
| **Stage-1** (**default**) | `ghidrust decompile PATH [--addr HEX] [--count N]` | Full SSA → structure → types → **expression-folded** typed pseudo-C: nested arith, named import/function calls when known, `this` on `Class::method`, float seeds from SSE notes, single-field structs when base is already `Ptr`, early-exit `return` polish, emit-time tokens for GUI nav. Still: `param_N`/`local_<off>`, switch/&&/&#124;&#124;/break/continue (lab goto_rate <0.15). Readability rubric: [`docs/READABILITY_RUBRIC.md`](../docs/READABILITY_RUBRIC.md). | stdout `pseudo_c`; `--json` ⇒ stage1 includes `folded_temps`, `token_count`, `lift_ratio`, `goto_rate`, … |
| **Stage-0** (oracle) | `ghidrust decompile PATH --stage0 [--addr HEX] [--count N]` | CFG → pseudo-C: `void FUN_<va>() { block_0: … goto/return; }`. Mnemonic-style scaffolding — no fabricated locals or types. | stdout `pseudo_c`; stderr `[name] stage=0 blocks=… edges=… insns=… lines=…`; `--json` ⇒ `Decompile { name, blocks[], edges[], insn_count, pseudo_c }`. |
| **Stage-0.5 IR** (oracle) | `ghidrust decompile PATH --stage05 [--addr HEX] [--count N]` | IR-informed emit from x86-64 lifter → `ghidrust-ir`: `xor a,a → a=0`, augmented assign, `push`/`pop`, direct `call`, flag-driven `jcc`. Falls back to Stage-0 for uncovered ops. | stdout `pseudo_c`; stderr adds `ir_ops=… lift=…%`; `--json` ⇒ `{decompile: …, lift_coverage: {total_ops, unimplemented_ops, source_instructions, ratio}}`. |
| **decompile-bench** | `ghidrust decompile-bench PATH [--functions N] [--count N] [--out F]` | Runs default analyzers, then benches Stage-0 vs Stage-0.5 vs Stage-1 across all discovered functions: totals `insns`, `ir_ops`, per-stage `µs`, avg `lift_ratio`. | Text (or JSON via `--json`); writes to `--out FILE` too. |
| **ghidra-headtohead** | `ghidrust ghidra-headtohead PATH [--functions N] [--count N] [--ghidra DIR] [--captured JSON] [--out F]` | Fair oracle: shared-entry intersection between Ghidra `DecompInterface` output and Ghidrust analyzer function list; compares Stage-1 vs Ghidra with normalized-token similarity metric and per-entry Stage-1 wall-time. Without `--ghidra` / `--captured` the report is methodology-only. | Text or JSON; rows carry `token_similarity`, `ghidrust_stage1_us`, `ghidra_wall_us`. |
| **gpu-decompile** | `ghidrust gpu-decompile PATH [--out F] [--metrics F]` | Full GPU-resident VRAM multipass decompile of entry: decode → leaders → blocks → emit; single final download; asserts `mid_pipeline_host_reads == 0` and matches CPU multipass oracle. | `.gdecomp` binary dump; stdout `pseudo_c`; `--json`/`--metrics` ⇒ `{gpu_backend, gpu_device, gpu_ms, mid_pipeline_host_reads, kernels, dump_path, dump_bytes, gpu_ir_count, gpu_block_count, gpu_edge_count, equivalence_multipass, pseudo_c_head}`. Non-zero exit on equivalence break. |
| **re-bench** | `ghidrust re-bench PATH [--out F]` | CPU decompile of entry + bulk RE on a padded haystack, once on CPU parallel and once on GPU/fallback. Asserts equal bulk hit counts. | Text (or JSON): `decompile_cpu {backend, ms, entry, name, blocks, edges, insns, lines, chars, pseudo_c_head}`, `bulk_cpu`, `bulk_gpu` (each: `{mode, backend, ms, hits, haystack_bytes}`), `note`. |

Related GPU / matrix benches (shipped, callable, **not** part of the eval sweep):

| Method | CLI | Purpose |
|---|---|---|
| `analyzer-bench` | `ghidrust analyzer-bench PATH [--large] [--out F] [--json]` | All analyzers + a GPU-decompile row: CPU wall-time vs `pcie_upload / device_ms / pcie_download` split, per-analyzer `equal` correctness flag. |
| `analyzer-bench-matrix` | `ghidrust analyzer-bench-matrix` | Static analyzer → GPU-strategy matrix (e.g. `ASCII Strings → printable_run`, `WindowsPE x86 PE RTTI Analyzer → rtti_scan`). |
| `bulk-bench` | `ghidrust bulk-bench PATH [--json]` | Seq / parallel-CPU / GPU-or-fallback bulk-string timings. |
| `rtti-gpu-bench` | `ghidrust rtti-gpu-bench PATH [--out F] [--json]` | CPU `recover_rtti` vs GPU `rtti_scan` seed with PCIe / device split. |

Guardrails to respect:

- Don't claim Hex-Rays or Ghidra C parity. Emit only what the current stage produces (Stage-0 scaffolding or Stage-0.5 IR-informed lines).
- If `gpu-decompile` exits non-zero (`equivalence_multipass = false` or `mid_pipeline_host_reads != 0`), treat the GPU output as suspect — CPU multipass is the oracle.
- Small binaries often show GPU wall-clock slower than CPU: `pcie_upload` and adapter init dominate. Always read the `device_ms` split, not the wall-clock alone, when arguing about GPU perf.

---

## GUI features

| Feature | Notes |
|---------|--------|
| Per-analyzer checkboxes | Individual enable |
| **GPU checkbox** | Bulk strings + per-analyzer GPU seed kernels |
| Progress | One analyzer per frame |
| Project tree | Open / Analyze / Delete |
| Decompiler pane | Placeholder / GPU dump via CLI preferred |

---

## Agent rules

**Do:** exact analyzer names; `--analyzer` or `--analyzers`; `--gpu` when GPU enrich wanted; `--json` for scripts; `analyzer-bench-matrix` for strategy list; prefer `decompile --stage05` when you want the IR-informed emit; `decompile-bench` to capture wall-clock + lift-ratio numbers.

**Don't:** invent typed/Hex-Rays C beyond the emit stage in use; claim Ghidra MCP is Ghidrust; claim Ghidra-surpass metrics without captured benches; skip empty-result honesty; conflate PCIe with on-device time; claim absence of managed types from PE strings alone when IL2CPP metadata exists (run `il2cpp meta`); invent method RVAs when the map leaves them null.

---

## Quick verification

```bash
cargo test -p ghidrust-core --features gpu
cargo test -p ghidrust-il2cpp -p ghidrust-unity-inventory --lib
ghidrust analyzers --json
ghidrust analyze fixtures/analysis_lab.pe --analyzer "ASCII Strings" --gpu --json
ghidrust gpu-decompile fixtures/analysis_lab.pe --json
ghidrust analyzer-bench-matrix
ghidrust il2cpp meta fixtures/il2cpp/meta_v31.dat --filter Camera --json
ghidrust il2cpp stubs --binary fixtures/il2cpp/il2cpp_stub_lab.pe --filter Camera --json
ghidrust decompile fixtures/il2cpp/il2cpp_stub_lab.pe --addr 0x140001000 --follow-stub --json
ghidrust bytes fixtures/il2cpp/il2cpp_stub_lab.pe --addr 0x140001000 --count 32 --json
ghidrust strings fixtures/il2cpp/meta_v31.dat --raw --filter Camera --match token --limit 5 --json
```

---
name: ghidrust
description: >
  x86-64 Auto Analysis, projects, CLI/MCP, egui GUI, IL2CPP metadata, Unity player inventory,
  GPU analyzer kernels + multipass decompile, crypt-constants / recover-strings / decode bake /
  crypto-capabilities. Exhaustive feature catalog with when-to-use guidance.
  Triggers: /ghidrust, reverse engineer, RE a PE/ELF, disassemble, decode-support, decode-query,
  MCP ghidrust, strings/functions, crypt-constants, recover-strings, decode bake, decode magic,
  crypto-capabilities, GPU decompile, IL2CPP, global-metadata, unity-inventory, GameAssembly,
  analyzer-bench, rtti-gpu-bench, bulk-bench.
metadata:
  short-description: "Ghidrust RE — decode, crypto recover, CLI, MCP, IL2CPP, Unity, analyzers, GPU"
---

# Ghidrust — agent skill

**Rust** reverse-engineering core (-inspired labels; measurable **-surpass** target on x86-64, Stage-0 decompile today). Prefer **CLI or MCP** for agents; GUI is for humans. **Never invent analysis** — if a fixture has no evidence, outputs are empty/honest.

## Paths & binaries

| Item | Path / command |
|------|----------------|
| Workspace root | repo root (`Cargo.toml` with `ghidrust-core`, `ghidrust-cli`, `ghidrust-gui`, `ghidrust-decomp`, `ghidrust-il2cpp`, `ghidrust-unity-inventory`) |
| CLI | `cargo run -p ghidrust-cli --release -- <cmd>` or `target/release/ghidrust.exe` |
| GUI | `cargo run -p ghidrust-gui --release` |
| Fixtures | `fixtures/tiny_x64.pe`, `fixtures/analysis_lab.pe`, `fixtures/tiny_x64.elf`, `fixtures/il2cpp/*` |
| Docs | `README.md`, `docs/IL2CPP.md`, `docs/GPU_ANALYZER_MATRIX.md`, `docs/PARALLEL_RE_RESEARCH.md` |
| Decode API | `ghidrust-decode::Engine` — `open`, `disasm`, `disasm_one`, `option`, `insn_name`, `reg_name`, `group_name`, `regs_access`; re-exported from `ghidrust-core` |
| Core API | `load_path` / `load_path_opts` / `load_blob`, `collect_strings_opts`, `run_analyzers_opts`, `Project`, `gpu_analyzers`, `bulk_scan` |

CLI always builds with `gpu` feature on deps. On Windows PowerShell: `.\target\release\ghidrust.exe …`.

```bash
cargo build -p ghidrust-cli --release
cargo build -p ghidrust-gui --release
```

---


Hand-rolled **`ghidrust-decode`** crate — Capstone-compatible `Engine` API over **23 ISAs**, implemented entirely in-tree. **No Capstone, iced-x86, or Zydis at runtime.** Program-aware disasm (`ghidrust-core::disassemble_range_ex_opts`) wraps the engine with bounded/flow/linear walks, loader-derived arch/mode, and JSON instruction records.

Library entry points: `Engine::open(arch, mode)`, `disasm` / `disasm_one` / `disasm_iter`, `option(Opt::…)`, introspection helpers (`insn_name`, `reg_name`, `group_name`, `op_count`, `regs_access`, …). Legacy x86-64 helper: `decode_one`.

### Decode support — `decode-support` / `server_info.decode`

Run **`ghidrust decode-support [--json]`** or MCP **`decode_support`** / read **`server_info.decode`** after connect.

JSON shape:

| Field | Meaning |
|-------|---------|
| `version` | `DECODE_VERSION` (crate version) |
| `arches[]` | `{ name, supported }` for every `Arch::ALL` entry (all `supported: true`) |
| `options[]` | Engine option names: `syntax`, `detail`, `detail_real`, `mode`, `skipdata`, `skipdata_setup`, `mnemonic`, `unsigned`, `only_offset_branch`, `litbase` |
| `syntax_values[]` | Allowed `--syntax` / MCP `syntax` strings |
| `features.decode_diet` | `false` — full detail path (not diet build) |
| `features.x86_reduce` | `false` — full x86 table (not x86 reduce build) |

`server_info` also sets **`tool_surface: 6`** and lists decode + crypto tools under `features.surface` (`decode_support` / `decode_query` / `crypt_constants` / `recover_strings` / `decode_bake` / `decode_magic` / `list_crypto_capabilities`).

### CLI — `disasm`, `decode-support`, `decode-query`

Add `--json` for structured stdout. Shared decode flags come from `DecodeOpts` (`crates/ghidrust-cli/src/decode_opts.rs`).

#### `ghidrust disasm <path>` (alias `disassemble`)

**Path modes:** PE/ELF (loader arch/mode) · raw blob when **`--arch`** is set (reads file bytes; `--addr` offset into blob).

| Flag | Purpose |
|------|---------|
| `--addr HEX` | Start VA (default: program entry or image base) |
| `--count N` | Max instructions (default **16**) |
| `--skip-bad` | Skip undecodable bytes; JSON reports `decode_gaps`, `first_gap_va` |
| `--linear` | Unbounded linear walk — **ground truth** when bounds are unknown/suspect |
| `--flow` | Control-flow walk within function bounds (trusted ends only) |
| `--brief` | One line per insn: `addr: mnemonic operands` (no hex); no `python -c` needed |
| `--pretty` | Header `entry/end/n/mode/stop_reason` + brief lines + bounds warning if any |
| `--arch NAME` | Override architecture (see catalog; aliases below) |
| `--mode NAME\|INT` | mode bits or named mode (`64`, `thumb`, `mips32`, `le`, …) |
| `--syntax SYNTAX` | Assembly syntax flavor (see options catalog) |
| `--detail` | Enable structured `detail` on each instruction |
| `--no-detail` | Force detail off |
| `--detail-real` | Real-number detail formatting where applicable |
| `--skipdata` | Treat unknown bytes as data (skip-data mode) |
| `--skipdata-mnemonic S` | Mnemonic for skip-data pseudo-instructions |
| `--skipdata-size N` | Default skip size hint |
| `--unsigned-imm` | Print immediates unsigned |
| `--only-offset-branch` | Branch targets as offsets only |
| `--litbase HEX` | Literal base for architectures that use it |
| `--mnem-override ID:MNEMONIC` | Repeatable per-instruction-id mnemonic override |
| `--out FILE` | With `--json`: JSON file. Without: human listing text (default/`--brief`/`--pretty`). UTF-8, no BOM |
| `--json` | Structured stdout / JSON `--out` |

JSON envelope (mapped binary): `insns`, `decode_gaps`, `first_gap_va`, `stop_reason`, `mode`, `entry`, `end`, plus honesty fields when relevant (`bounds_suspect`, `bounds_warning`, `suggested_end`, `heal_hint`, `callsite_hints`). MCP `disassemble` adds `resolve`, `listing_text` (brief lines).

**PowerShell-safe:** never nest `python -c "..."` in agent shell pipelines (ScriptBlock / quoting kills the job). Prefer `ghidrust disasm … --pretty` / `--brief`, or `--json --out file.json` then `Get-Content` / `ConvertFrom-Json`. Flags accept `--name` or `-name`.

#### `ghidrust decode-support [--json]`

No arguments. Emits engine catalog (see above).

#### `ghidrust decode-query`

| Flag | Purpose |
|------|---------|
| `--query NAME` | **Required.** One of: `insn_name`, `reg_name`, `group_name`, `insn_group`, `reg_read`, `reg_write`, `op_count`, `op_index`, `regs_access` |
| `--arch NAME` | Architecture (default `x86`) |
| `--mode NAME\|INT` | Mode (default `64` for x86, `little_endian` otherwise) |
| `--id N` | Instruction / register / group id (`insn_name`, `reg_name`, `group_name`) |
| `--index N` | Operand / group / reg index (default 0) |
| `--bytes HEX` | Instruction bytes for insn-dependent queries |
| `--addr HEX` | Address for decode context (default 0) |
| `--detail` | Enable detail before decode (required for `regs_access`) |
| `--json` | Structured stdout |

Positional query name (without `--query`) is also accepted: `ghidrust decode-query insn_name --arch x86 --id 1 --json`.

### MCP — `disassemble`, `decode_support`, `decode_query`

Requires **`tool_surface >= 5`** for decode tools; **`>= 6`** for crypto recover / bake tools (check `server_info` before assuming these tools/args exist).

#### `decode_support`

Arguments: `{}`. Returns same JSON as CLI `decode-support`.

#### `decode_query`

| Arg | Type | Purpose |
|-----|------|---------|
| `query` | string **required** | `insn_name` \| `reg_name` \| `group_name` \| `insn_group` \| `reg_read` \| `reg_write` \| `op_count` \| `op_index` \| `regs_access` |
| `arch` | string | Architecture name |
| `mode` | string \| integer | Mode name or bitfield |
| `id` | integer | Insn/reg/group id |
| `index` | integer | Operand/group/reg index |
| `bytes` | string | Hex bytes for instruction-dependent queries |
| `addr` | string | Address for decode |
| `detail` | boolean | Enable detail (needed for `regs_access`) |

#### `disassemble`

| Arg | Type | Purpose |
|-----|------|---------|
| `path` | string **required** | PE/ELF path |
| `addr` | string | Start VA |
| `count` | integer | Max insns (default 16) |
| `skip_bad` | boolean | Skip bad bytes |
| `linear` | boolean | Unbounded linear walk |
| `flow` | boolean | Control-flow walk within function |
| `arch` | string | Arch override |
| `mode` | string \| integer | Mode override |
| `syntax` | string | `default` \| `intel` \| `att` \| `noregname` \| `masm` \| `motorola` \| `cs_reg_alias` \| `percent` \| `no_dollar` \| `no_alias_text` \| `no_alias_text_compressed` |
| `detail` | boolean | Structured detail |
| `detail_real` | boolean | Real-number detail |
| `skipdata` | boolean | Skip-data mode |
| `skipdata_mnemonic` | string | Skip-data mnemonic |
| `skipdata_size` | integer | Skip-data size hint |
| `unsigned_imm` | boolean | Unsigned immediates |
| `only_offset_branch` | boolean | Offset-only branches |
| `litbase` | string \| integer | Literal base |
| `mnem_overrides` | array | `"ID:MNEMONIC"` strings or `{ id, mnemonic }` objects |

Returns: `resolve`, `mode`, `stop_reason`, `entry`, `end`, `decode_gaps`, `first_gap_va`, `insns`.

### Options catalog

| Option | CLI flag | MCP field | Values / notes |
|--------|----------|-----------|----------------|
| **syntax** | `--syntax` | `syntax` | `default`, `intel`, `att`, `noregname`, `masm`, `motorola`, `cs_reg_alias`, `percent`, `no_dollar`, `no_alias_text`, `no_alias_text_compressed` |
| **detail** | `--detail` / `--no-detail` | `detail` | boolean — structured operands + register access lists |
| **detail_real** | `--detail-real` | `detail_real` | boolean |
| **mode** | `--mode` | `mode` | Integer bitfield or named: `16`, `32`, `64`, `thumb`, `mclass`, `v8`, `mips32`, `mips64`, `ppc32`, `ppc64`, `riscv32`, `riscv64`, `riscv_c`, `le`/`little`, `be`/`big`, `bpf_classic`, `bpf_extended`, `6502`, `65c02`, … |
| **skipdata** | `--skipdata` | `skipdata` | boolean |
| **skipdata_setup** | `--skipdata-mnemonic`, `--skipdata-size` | `skipdata_mnemonic`, `skipdata_size` | Mnemonic + size hint (`skipdata_setup` in engine) |
| **mnemonic** | `--mnem-override ID:MNEM` | `mnem_overrides[]` | Per-instruction-id override |
| **unsigned** | `--unsigned-imm` | `unsigned_imm` | boolean |
| **only_offset_branch** | `--only-offset-branch` | `only_offset_branch` | boolean |
| **litbase** | `--litbase HEX` | `litbase` | u32 |

### Architectures catalog (`Arch::ALL` — 23)

All report `"supported": true` from `decode-support`. CLI/MCP `--arch` / `arch` accepts the aliases below (from `parse_arch`); other canonical names are engine-supported — use `Engine::open` in library code or extend CLI aliases if needed.

| Name | CLI/MCP `--arch` aliases |
|------|--------------------------|
| `arm` | `arm` |
| `arm64` | `arm64`, `aarch64` |
| `mips` | `mips` |
| `x86` | `x86`, `x86_64`, `x64`, `amd64` |
| `ppc` | `ppc`, `powerpc` |
| `sparc` | `sparc` |
| `sysz` | `sysz`, `s390` |
| `xcore` | *(canonical `xcore` — engine only until CLI alias added)* |
| `m68k` | `m68k`, `68k` |
| `tms320c64x` | *(engine only)* |
| `m680x` | *(engine only)* |
| `evm` | `evm` |
| `mos65xx` | `mos65xx`, `6502` |
| `wasm` | `wasm` |
| `bpf` | `bpf`, `ebpf` |
| `riscv` | `riscv`, `riscv32`, `riscv64` |
| `sh` | *(engine only)* |
| `tricore` | *(engine only)* |
| `alpha` | `alpha` |
| `hppa` | *(engine only)* |
| `loongarch` | *(engine only)* |
| `xtensa` | *(engine only)* |
| `arc` | *(engine only)* |

Per-arch notes: [docs/DECODE_COVERAGE.md](../docs/DECODE_COVERAGE.md).

### Groups catalog


| ID | Name | Meaning |
|----|------|---------|
| 0 | `Invalid` | Placeholder |
| 1 | `Jump` | Jump group |
| 2 | `Call` | Call group |
| 3 | `Ret` | Return group |
| 4 | `Int` | Interrupt |
| 5 | `Iret` | Interrupt return |
| 6 | `Privilege` | Privileged |
| 7 | `BranchRelative` | PC-relative branch |
| ≥8 | `Arch(n)` | Architecture-specific groups — resolve with `decode-query --query group_name --id N` |

### Instruction JSON fields

Each entry in `insns[]`:

| Field | Type | When present |
|-------|------|--------------|
| `address` | u64 | Always |
| `bytes` | `[u8]` | Always — raw opcode bytes |
| `mnemonic` | string | Always |
| `operands` | string | Always — formatted operand text |
| `length` | u8 | Always |
| `detail` | object | When `--detail` / `detail: true` |
| `detail.operands[]` | array | Structured operands: `Reg`, `Imm { value, size }`, `Mem { base, index, scale, disp, segment, size }`, `Fp`, `Invalid` |
| `detail.groups[]` | array | `GroupId` membership |
| `detail.regs_read[]` | array | Explicit read registers |
| `detail.regs_write[]` | array | Explicit write registers |
| `detail.implicit_read[]` | array | Implicit reads |
| `detail.implicit_write[]` | array | Implicit writes |

Human text line (non-JSON default): `{addr:016x}: {hex bytes} {mnemonic} {operands}`.
Brief line (`--brief` / MCP `listing_text`): `{addr:#x}: {mnemonic} {operands}`.

### Decode SOPs (required)

- **`tool_surface` check**: Call `server_info` first. Require **`tool_surface >= 5`** for `decode_support`, `decode_query`, and extended `disassemble` decode args. Require **`>= 6`** for `crypt_constants`, `recover_strings`, `decode_bake`, `decode_magic`, `list_crypto_capabilities`. If below the needed minimum or tools missing from `tools/list` → rebuild `ghidrust`, restart MCP. (Broader surface still requires **`>= 3`**, prefer **`>= 4`** for bounded disasm / `get_calls_from`.)
- **Decode mode decision tree**:
  - Need body of **unknown / wrong / suspect** bounds? → `disasm --linear --count N` first (ground truth) → `function create --addr` to heal → then `--flow` / `decompile` on healed range.
  - Need CFG inside a **known-good** function? → `--flow` (or default bounded).
  - If JSON/text shows `bounds_suspect` or stop after a handful of insns with `function_end` → do **not** treat that as the full body; heal first.
- **Bounded disasm**: Default **`Bounded`** clamps to containing function end. Trust it only when ends look honest (not prologue-only). Prefer `--linear` before decompile when unsure.
- **Detail-first**: Pass **`--detail`** / `detail: true` when you need structured operands, **`regs_access`**, or `callsite_hints`. Without detail, rely on mnemonic/operand / listing_text strings only.
- **Arch/mode from loader**: Omit **`--arch`/`--mode`** on PE/ELF so `arch_mode_for_program` selects from machine type. Override only for cross-arch blobs or deliberate experiments.
- **Query helpers**: Use **`decode-query`** for `insn_name`/`reg_name`/`group_name` tables and per-instruction **`op_count`/`op_index`/`regs_access`** — do not guess ids from strings alone.
- **Skipdata**: Enable **`--skipdata`** when linear sweeps hit inline data pools; tune **`--skipdata-mnemonic`** / **`--skipdata-size`** for readable `.byte`-style placeholders.

---

## Agent friction SOPs (required)

- **Version / stale MCP**: Call `server_info` first (or read `initialize.serverInfo`). This skill requires **`tool_surface >= 3`** (touch-map, body_class map, function_create, live process + artifacts). Prefer **`>= 4`** for bounded disasm / `get_calls_from`. Require **`>= 5`** for `decode_support`, `decode_query`, and extended `disassemble` decode flags. Require **`>= 6`** for crypt-constants / recover-strings / decode bake|magic / crypto-capabilities. If `server_info` is missing, `tool_surface` is below the needed minimum, or expected tools are absent from `tools/list` → rebuild `ghidrust`, point the MCP `command` at that binary, **restart the MCP server**. Do **not** conclude live process is unsupported; do **not** invent heap-scan scripts as a substitute. CLI/GUI/MCP share one package version (`ghidrust --version`, MCP `version`, egui About).
- **Crypto / obfuscated strings**: Prefer `crypt_constants` → `recover_strings` → `decode_bake`/`decode_magic` on leftover blobs; use `list_crypto_capabilities` to locate decrypt/encrypt API sites. Never invent plaintext — empty hits are honest.
- **Artifacts**: When envelope `entry_count` > preview or the host truncates tool text, drain via `artifact_query` / `artifact get` until `next_offset` is null. Never assume truncated MCP text is complete.
- **Program identity**: Prefer `load` with absolute `path`, or `project` + `file_id`. Facts always include `resolved_path` or honest null — resolve before analyze/decompile.
- **Inventory / tree**: Use `inventory <dir>` (PE VERSIONINFO + exe/dll) before OS `dir`/`Get-Item`. Use `tree` / `list_tree` for non-PE sidecars (existence/size only; no unpack).
- **Seed pipeline**: Exception Directory / FSS → `function_create` (heal orphans **and** re-grow truncated stored ends) → tagged synthesize when still missing. Never invent managed names on synthesized ranges.
- **PowerShell / agent shell**: Never recommend `python -c` with nested quotes in PS pipelines. Prefer `ghidrust disasm … --pretty` / `--brief`, or `--json --out FILE` + `ConvertFrom-Json` / MCP `disassemble` (`listing_text`, `insns[].mnemonic`/`operands`).
- **Bounded disasm honesty**: Default bounded/flow clamps to function end. When `bounds_suspect` / short `function_end` / &lt;~8 insns then stop → `--linear` first, then `function create --addr`, then `--flow`/decompile. Never treat a 5-insn bounded result as a full function.
- **Address→function**: Always pass `addr` to `decompile` / `disassemble` / `gpu_decompile`; trust `resolved_entry` / `resolve` meta. Mid-body hits resolve to containing entry; unmapped → create/synthesize or honest `no_containing_function` (no invented 1-insn fn).
- **RTTI catalog**: Prefer `rtti_query` (`--filter`/`--exact`) before mangled `.?AV` string archaeology. Multi-vtable types report `vtable_vas[]` honestly.
- **UTF-16 xrefs**: If `search_strings` returns `utf16le`, query `get_string_xrefs` with `encoding=all` (or `utf16le`) before concluding “no refs”.
- **Live process (Windows)**: Multi-step live work **must** use MCP (or one long-lived process) — `process_list` → `process_attach` **or** `process_launch` (CREATE_SUSPENDED) → `process_modules` → `process_resolve` (`static_to_live`) → `process_read` → optional `process_resume` / `process_regions` / `process_detach`. Launch is suspended spawn + read session, **not** debug break-at-entry. Never chain separate CLI `ghidrust process` spawns expecting the same `session_id` (sessions are in-process). Bytes ≠ types. No write/breakpoints in MVP.
- **IL2CPP offline → live**: (1) `il2cpp_touch_map` / `il2cpp_meta` / `il2cpp_map` for names + method RVAs (null = unknown offline; encrypted → `next_steps` with meta-sections/touch-map). (2) Require `body_class` not `shared_stub` / `semantics_mismatch` before treating a name as a hook target. (3) `decompile` + `follow_stub` for resolve stubs with mapped slots. (4) On `runtime_unresolved` / `trampoline_or_invoker` → live attach → `process_resolve(module, rva)` → `process_read`. (5) Multi-build work: `il2cpp map --baseline PREV.json` → inspect `build_skew` (stale **map catalog**, not only stale MCP binary).
- **Skill bootstrap**: GUI project open / Start writes `.grok/skills/ghidrust/SKILL.md` (disk or embedded fallback) and shows a fail-loud checklist (mcp/skill/agents/context + hash).
- **Do not**: invent enum ordinals; treat `section_notes` as proof of hooks; read `.gdecomp` dumps as text (metrics JSON only); hook shared stubs as unique gameplay methods.

## Decision tree

```
Need body of unknown/wrong bounds?
  → disasm PATH --addr HEX --count N --linear [--pretty|--brief|--json --out FILE]
  → if bounds_suspect / truncated end → function create PATH --addr HEX
  → then disasm --flow / decompile on healed range

Need CFG inside known-good function?
  → disasm --flow (or default bounded)

Avoid:
  → treating short bounded (e.g. 5-insn function_end) as full body
  → PowerShell python -c nested-quote pipelines

Need durable workspace?
  YES → project create → import → analyze [--analyzer …] [--gpu] → export
  NO  → load | disasm | rtti | analyze [--analyzer …] [--gpu]

Need machine-readable without python -c?
  → disasm --pretty / --brief   OR  --json --out FILE   OR  MCP disassemble
  → large dumps → artifact spill + artifact_query drain

Need install layout without shell?
  → inventory DIR   (PE versions + exe/dll)
  → tree DIR        (sidecars / media existence)

Need GPU for selected analyzers (not just bench)?
  → analyze … --gpu   OR  GUI checkbox  OR  MCP analyze gpu:true
  → bulk mode for ASCII Strings + SIMT seed enrich per selected name

Need crypto constants / obfuscated strings / peel a blob?
  → crypt-constants PATH [--algo AES] --json
  → recover-strings PATH [--only stack,tight,decoded] --json
  → crypto-capabilities PATH [--tag decrypt] --json
  → decode bake (-b64|-hex|-path+-addr) -op FromBase64|XOR|… [--annotate-va HEX with -path] --json
  → decode magic (-b64|-hex|…) [-depth N] [--crib TEXT] --json
  → MCP: crypt_constants / recover_strings / list_crypto_capabilities / decode_bake / decode_magic
  → analyze --analyzer "Find Crypt" / "Obfuscated Strings" / "Crypto Capabilities"

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
 Kept as regression baseline; head-to-head uses this only
                                for pre-Stage-1 checks, never for external comparison tables.
     Stage-0.5  (oracle):  `decompile PATH --stage05` → IR-informed emit (xor a,a → a=0, augmented
                                assign, push/pop, direct call, flag-driven jcc). Same fallback
                                rules — Stage-0.5 is IR-informed but pre-SSA.
 unions/bitfields/EH still evidence-gated after bar.
    See docs/READABILITY_RUBRIC.md (readability checklist).

Need Stage-0 vs Stage-0.5 vs Stage-1 wall-clock + lift-ratio numbers?
  → `decompile-bench PATH [--functions N] [--count N] [--out FILE] [--json]`

Need ↔ Ghidrust head-to-head?
 → `-headtohead PATH [-- DIR] [--captured JSON] [--out FILE] [--json]`
 → `-- DIR` auto-spawns `` (locates `support/(.bat)`,
     writes the embedded `DecompileAndReport.java`, parses per-function `wall_us`).
  → `--captured JSON` replays a manual capture for offline / airgapped hosts.
 → When neither is supplied, the report is methodology-only: column left blank
     + full runbook (dev/GHIDRA_HEADTOHEAD.md). Spawn failures surface as factual
 ` spawn failed: <reason>` notes — no fabricated timings.

Unity player / IL2CPP?
  → unity-inventory GAME_DIR for install layout (assemblies, plugins, metadata)
  → il2cpp touch-map --meta META|--meta-sections DIR --filter NAME (names first)
  → il2cpp map --binary GA.dll --meta META [--baseline PREV.json] → require body_class
    (reject shared_stub / semantics_mismatch before hooking); inspect build_skew on rebuilds
  → il2cpp meta for managed types/methods; stubs; xrefs --skip-stubs; decompile --follow-stub
  → encrypted metadata (wrong magic) → report encrypted + next_steps; do not invent types
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

Requires **`tool_surface >= 3`** (prefer **`>= 4`** for bounded disasm / `get_calls_from`; **`>= 5`** for decode tools; **`>= 6`** for crypto recover / bake). Check with `server_info` after connect.

| Tool | Args | Notes |
|------|------|-------|
| `server_info` | — | Package `version`, `tool_surface`, `decode` block, features, live session_model |
| `load` | `path` **or** `project`+`file_id` | Map + `section_notes` + `resolved_path` |
| `decode_support` | — | Engine version, 23 arches, options, syntax values, compile features |
| `decode_query` | `query`, optional `arch`, `mode`, `id`, `index`, `bytes`, `addr`, `detail` | Introspection queries (see decode section) |
| `disassemble` | `path`, optional `addr`, `count`, `skip_bad`, `linear`, `flow`, `arch`, `mode`, `syntax`, `detail`, `detail_real`, `skipdata`, `skipdata_mnemonic`, `skipdata_size`, `unsigned_imm`, `only_offset_branch`, `litbase`, `mnem_overrides` | Bounded by function end by default; JSON `stop_reason` + `decode_gaps` |
| `rtti` / `rtti_query` | `path`, optional `filter`/`exact`/`match` | Catalog; multi-vtable; artifact if large |
| `artifact_get` / `artifact_query` / `artifact_list` | `id` / optional `offset`/`limit` / optional `max` | Drain or list spilled results |
| `inventory` | `path`, optional `max_depth`/`hash` | PE VERSIONINFO + exe/dll catalog |
| `list_tree` | `path`, optional depth/ext/glob | Bounded tree; errors as rows |
| `list_analyzers` | — | Auto Analysis names |
| `analyze` | `path`, optional `analyzers[]`, **`gpu`** | CPU + optional GPU enrich |
| `list_strings` / `search_strings` | `path`, optional `encoding`, `filter`, **`match`**, `min`, **`limit`**, **`raw`** | Blob scan when `raw:true` |
| `crypt_constants` / `list_crypt_constants` | `path`, optional `algo`, `limit` | Crypto constant tables (S-box, TEA delta, hash K, …) |
| `recover_strings` | `path`, optional `only[]`, `no[]`, `functions[]`, `limit` | Stack / tight / decoded obfuscated strings |
| `decode_bake` | `recipe`\|`ops`, plus `input_hex`\|`input_b64`\|`path`+`addr` (+ `count?`) | Recipe peel (FromBase64, XOR, AESDecrypt, …) |
| `decode_magic` | `depth?`, plus same input fields as bake | Auto peel chain by printable ratio |
| `list_crypto_capabilities` | `path`, optional `tag` | Encrypt/decrypt/encoding capability hits |
| `get_xrefs_to` | `path`, `addr`, optional **`skip_stubs`**, **`classify`** | RIP/tables + data ptrs; IL2CPP stubs; `to_entry` |
| `get_xrefs_from` | `path`, `addr`, optional `count` | Xrefs from VA; `from_entry` / `from_function` / `to_entry` |
| `get_calls_from` | `path`, `addr` | Callee edges inside containing function (CLI: `xrefs --calls`) |
| `get_string_xrefs` | `path`, `filter`, optional `encoding` | UTF-16LE / ASCII modes (`ascii`\|`utf16le`\|`all`) |
| `list_imports` / `get_import_xrefs` | `path`, optional `dll`/`name` | PE IAT |
| `function_at` / `get_function_by_address` | `path`, `addr` | Containing function + `seed_kind` |
| `read_bytes` | `path`, `addr`, optional `count` | Raw VA hex dump |
| `il2cpp_meta` | `path`, optional `filter` | `global-metadata.dat` types/methods (v27/29/31); encrypted → `next_steps` JSON |
| `il2cpp_map` | `binary`, `meta` or `meta_sections`, optional `filter`, `baseline` | Method RVA map + `body_class` / `shared_stubs` / `semantics_mismatch` / optional `build_skew`; null RVA when unproven |
| `il2cpp_touch_map` | `filter`, `meta` or `meta_sections`, optional `binary` | Heap substring touch-map (`name_only` \| `rva_bound`) |
| `il2cpp_stubs` | `binary`, optional `filter`, `max` | Resolve stubs (filter: name or C-string at `name_string_va`) |
| `il2cpp_icalls` | `binary`, optional `filter` | Engine name‖fn icall tables → index / RVA |
| `function_create` | `path`, `addr`, optional `end` | Create/heal function (pdata/export/FSS; may synthesize `SYNTH_*`) |
| `unity_inventory` | `path` | Player dir + PE VERSIONINFO helpers |
| `decompile` | `path`, optional `addr`, `count`, `stage`, **`follow_stub`** | Resolve meta + Stage-1; JSON: `folded_temps`, `token_count`, `goto_rate`; `follow_stub` may be `runtime_unresolved` / `trampoline_or_invoker` with `next_steps` → live process |
| `list_gpu_strategies` | — | Strategy matrix |
| `gpu_decompile` | `path`, optional `addr`, `out` | VA resolve; metrics JSON; dump opaque |
| `rtti_gpu_bench` | `path` | CPU vs GPU RTTI |
| `process_list` / `process_attach` / `process_launch` / `process_resume` / `process_detach` / `process_modules` / `process_read` / `process_resolve` / `process_regions` | pid / image / session / module / rva / max | Live Process Bridge (Windows; read-only; launch = CREATE_SUSPENDED) |

MCP launch: `ghidrust mcp` / `target/release/ghidrust.exe mcp` (stdio; no host-specific paths).

---

## Crypto recover + decode bake (CLI + MCP) — `tool_surface >= 6`

Hand-rolled in-tree scanners and recipe peels. **Never invent plaintext** — empty hits / failed bake are honest. Prefer this pipeline:

1. **Find sites** — `crypt_constants` and/or `list_crypto_capabilities`
2. **Recover in-binary strings** — `recover_strings` (and/or Auto Analysis `Obfuscated Strings`)
3. **Peel leftover blobs** — `decode_bake` / `decode_magic` on hex, Base64 text, or VA ranges

### Phase A — Find Crypt / `crypt-constants`

Discovers cryptographic **constant tables** (AES S-box, TEA delta, MD5/SHA-256 K prefix, ChaCha sigma, Blowfish P, CRC32 tab, …). Labels `CRYPT_*` symbols when run via Auto Analysis.

| Surface | Invocation |
|---------|------------|
| CLI | `ghidrust crypt-constants <path> [--algo AES\|TEA\|…] [--limit N] [--json]` |
| Analyze | `ghidrust analyze <path> --analyzer "Find Crypt" --json` |
| MCP | `crypt_constants` / `list_crypt_constants` `{ path, algo?, limit? }` |

JSON hits: `{ va, algorithm, constant, size }`.

```bash
ghidrust crypt-constants fixtures/analysis_lab.pe --json
ghidrust analyze fixtures/analysis_lab.pe --analyzer "Find Crypt" --json
```

### Phase B — Obfuscated Strings / `recover-strings`

Recovers **stack**, **tight** (stack + nearby XOR), and **decoded** (single-byte XOR runs) strings from executable blocks.

| Surface | Invocation |
|---------|------------|
| CLI | `ghidrust recover-strings <path> [--only stack,tight,decoded] [--no static] [--functions HEX[,HEX…]] [--limit N] [--json]` |
| Analyze | `ghidrust analyze <path> --analyzer "Obfuscated Strings" --json` |
| MCP | `recover_strings` `{ path, only?, no?, functions?, limit? }` |

JSON hits: `{ va, value, kind, decoder_va?, call_site? }`.

```bash
ghidrust recover-strings PATH --only stack,tight,decoded --json
```

### Phase C — `decode bake` / `decode magic`

Recipe engine over buffers (not an Auto Analysis scanner). Input is **recipe input bytes**:

| Input flag / MCP field | Meaning |
|------------------------|---------|
| CLI `-hex HEX` / MCP `input_hex` | Hex bytes |
| CLI `-b64 TEXT` | Base64 **text** as UTF-8 bytes (add `-op FromBase64` to peel) |
| MCP `input_b64` | Base64-decoded input bytes |
| CLI `-raw TEXT` | Raw UTF-8 bytes |
| CLI `-in FILE` | File bytes |
| CLI `-path PATH -addr HEX [-count N]` / MCP `path`+`addr`+`count?` | Bytes from mapped image |

**Ops** (`-op NAME` or recipe JSON `[{op, args}]`): `FromBase64`, `FromHex`, `FromCharcode`, `UrlDecode`, `HtmlEntityDecode`, `XOR` (`key_hex`/`key`), `XORBrute`, `RC4`, `ChaCha20Decrypt` (`key_hex`, `nonce_hex`, `counter`), `AESDecrypt`, `DESDecrypt`, `TripleDESDecrypt`, `BlowfishDecrypt`, `Gunzip`, `Inflate`, `ROT13`, `Reverse`, `DecodeUTF16LE`. CLI operation arguments accept `-key`, `-key-hex`, `-iv`, `-iv-hex`, `-nonce`, `-nonce-hex`, `-counter`, `-mode`, and `-encoding`.

| Surface | Invocation |
|---------|------------|
| CLI bake | `ghidrust decode bake (-hex\|-b64\|-raw\|-in\|-path+-addr) [-recipe JSON \| -op NAME [-key\|-key-hex\|-iv\|-iv-hex\|-nonce\|-nonce-hex\|-counter\|-mode\|-encoding VALUE]…] [--annotate-va HEX with -path] [--json]` |
| CLI magic | `ghidrust decode magic (…) [-depth N] [--crib TEXT] [--json]` |
| MCP bake | `decode_bake` `{ recipe\|ops, input_hex\|input_b64\|path+addr, count?, annotate_va? }` |
| MCP magic | `decode_magic` `{ depth?, crib?, input_hex\|input_b64\|path+addr, count? }` |

```bash
# Base64 → plaintext
ghidrust decode bake -b64 SGVsbG8= -op FromBase64 --json

# XOR with key
ghidrust decode bake -hex 09040d0d0e -op XOR -key-hex 41 --json

# Auto peel
ghidrust decode magic -b64 SGVsbG8= -depth 3 --json

# Bytes at VA
ghidrust decode bake -path PATH -addr 0x140002000 -count 64 -op XORBrute --json

# Require a known plaintext fragment; annotate is in-memory only for a plain path load
ghidrust decode magic -hex 48656c6c6f -crib Hello --json
ghidrust decode bake -path PATH -addr 0x140002000 -op Gunzip --annotate-va 0x140002000 --json
```

MCP examples:

```json
{ "name": "decode_bake", "arguments": {
  "input_hex": "534756736247383d",
  "recipe": [{ "op": "FromBase64", "args": {} }]
}}
```

```json
{ "name": "decode_magic", "arguments": { "input_b64": "SGVsbG8=", "depth": 3 } }
```

Bake JSON: `{ result: { ok, output_hex, output_utf8?, message, recipe_applied[] }, iocs[], annotation? }`. `annotation` records whether an EOL comment was applied; plain path loads have no project save target, so such comments are explicitly reported as in-memory only. `crib` boosts a matching magic candidate.

### Phase D — Crypto Capabilities / `crypto-capabilities`

Matches encrypt/decrypt/encoding **capabilities** (WinCrypt/BCrypt/DPAPI-style imports, AES-NI opcodes, prior constant hits, stackstring presence). Tags: `decrypt` \| `encrypt` \| `encoding` \| `hashing`.

| Surface | Invocation |
|---------|------------|
| CLI | `ghidrust crypto-capabilities <path> [--tag decrypt\|encrypt\|encoding] [--json]` |
| Analyze | `ghidrust analyze <path> --analyzer "Crypto Capabilities" --json` |
| MCP | `list_crypto_capabilities` `{ path, tag? }` |

JSON hits: `{ function_va?, capability, tag, evidence, attack?, mbc? }`.

```bash
ghidrust crypto-capabilities PATH --tag decrypt --json
```

### Agent SOP (crypto)

1. `server_info` → confirm `tool_surface >= 6`.
2. `crypt_constants` + `list_crypto_capabilities` to locate algorithms / API decrypt sites.
3. `recover_strings` (or `analyze` with `Obfuscated Strings`) for hidden IOCs.
4. On opaque blobs / resources / VA ranges → `decode_magic` first; if key/IV known → `decode_bake` with explicit ops.
5. Chain: constants/capabilities → seed `recover_strings` `--functions` → bake remnants.
6. Do **not** claim decrypted plaintext without a successful bake/`ok: true` or recovered string hit.

---

## Unity / IL2CPP (CLI + MCP)

Canonical detail: [`docs/IL2CPP.md`](../docs/IL2CPP.md).

| Task | CLI | MCP |
|------|-----|-----|
| Player install inventory | `ghidrust unity-inventory GAME_DIR --json` | `unity_inventory` `{path}` |
| Managed types/methods | `ghidrust il2cpp meta META.dat [--filter F] --json` | `il2cpp_meta` `{path, filter?}` |
| Touch-map (names) | `ghidrust il2cpp touch-map --meta META\|--meta-sections DIR --filter F [--binary GA.dll] --json` | `il2cpp_touch_map` |
| Metadata ↔ RVA + body proof | `ghidrust il2cpp map --binary GA.dll --meta META.dat\|--meta-sections DIR [--baseline PREV.json] [--baseline-strict] --json` | `il2cpp_map` `{binary, meta\|meta_sections, filter?, baseline?}` |
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
| Disasm | `ghidrust disasm <path> [--addr HEX] [--count N] [--skip-bad] [--linear\|--flow] [--brief\|--pretty] [--arch ARCH] [--mode MODE] [--syntax SYNTAX] [--detail] [--no-detail] [--detail-real] [--skipdata] [--skipdata-mnemonic S] [--skipdata-size N] [--unsigned-imm] [--only-offset-branch] [--litbase HEX] [--mnem-override ID:MNEM]… [--out FILE] [--json]` |
| Decode support | `ghidrust decode-support [--json]` |
| Decode query | `ghidrust decode-query --query NAME [--arch] [--mode] [--id] [--index] [--bytes HEX] [--addr HEX] [--detail] [--json]` |
| Strings | `ghidrust strings <path> [--raw] [--encoding …] [--match MODE] [--limit N] [--out FILE] [--filter SUB]` |
| Xrefs | `ghidrust xrefs <path> (--to\|--from\|--string\|--import\|--calls) [--encoding ascii\|utf16le\|all] [--skip-stubs] [--classify] [--out FILE]` |
| Bytes | `ghidrust bytes <path> --addr HEX [--count N] [--out FILE]` |
| Imports | `ghidrust imports <path> [--dll\|--name]` |
| Function-at | `ghidrust function-at <path> --addr HEX` (`seed_kind`) |
| Function create | `ghidrust function create <path> --addr HEX [--end HEX]` |
| Inventory | `ghidrust inventory <dir> [--max-depth N] [--hash]` |
| Tree | `ghidrust tree <path> [--max-depth N] [--ext LIST] [--name GLOB]` |
| Artifact | `ghidrust artifact get\|query\|list …` |
| Process (Windows) | `ghidrust process list\|attach\|launch\|resume\|detach\|modules\|read\|resolve\|regions …` |
| IL2CPP | `ghidrust il2cpp meta\|map\|touch-map\|stubs\|icalls …` (`--baseline` / `--meta-sections`; see `docs/IL2CPP.md`) |
| Unity inventory | `ghidrust unity-inventory <game-dir>` |
| RTTI catalog | `ghidrust rtti <path> [--filter\|--name\|--exact] [--match MODE]` |
| List analyzers | `ghidrust analyzers` |
| **Analyze** | `ghidrust analyze <path> [--analyzers a,b \| --analyzer NAME …] [--gpu]` |
| Bulk bench | `ghidrust bulk-bench <path>` |
| Decompile (Stage-1 default; `--follow-stub` for IL2CPP; metrics with `--verbose`) | `ghidrust decompile <path> [--addr HEX] [--follow-stub] [--verbose]` |
| Decompile (Stage-0 CFG scaffolding, oracle) | `ghidrust decompile <path> --stage0` |
| Decompile (Stage-0.5 IR-informed, oracle) | `ghidrust decompile <path> --stage05` |
| Decompile bench (Stage-0 vs Stage-0.5 vs Stage-1) | `ghidrust decompile-bench <path> [--functions N] [--count N] [--out F]` |
| head-to-head (shared-entry, Stage-1) | `ghidrust -headtohead <path> [-- DIR] [--captured JSON] [--out F]` |
| **GPU decompile** | `ghidrust gpu-decompile <path> [--addr HEX] [--out F] [--metrics F]` |
| RE bench | `ghidrust re-bench <path>` |
| Analyzer CPU/GPU matrix bench | `ghidrust analyzer-bench <path> [--large] [--out F]` |
| Strategy matrix | `ghidrust analyzer-bench-matrix` |
| **RTTI GPU bench** | `ghidrust rtti-gpu-bench <path> [--out F]` |
| Project | `create\|open\|import\|list\|analyze\|export` (analyze supports `--analyzer` / `--gpu`) |
| MCP | `ghidrust mcp` |

### Recipes

```bash
# Unknown / suspect function body (linear-first; PowerShell-safe — no python -c)
ghidrust disasm PATH --addr 0x140001234 --count 90 --linear --pretty
ghidrust disasm PATH --addr 0x140001234 --count 90 --linear --json --out enum.json
ghidrust function create PATH --addr 0x140001234
ghidrust decompile PATH --addr 0x140001234 --json --out enum_decomp.json
# Typed-object enum pattern (generic): manager* + type_bit:u32 + out* at a FindObjects-style call;
# walk table slots; field offsets are evidence-gated from listing/callsite_hints — do not invent names.

# Quick triage
ghidrust load PATH --json
ghidrust decode-support --json
ghidrust decode-query --query insn_name --arch x86 --id 1 --json
ghidrust disasm PATH --addr 0x140001234 --count 32 --detail --syntax intel --pretty
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
ghidrust process launch PATH.exe --args "…" --cwd DIR --json
ghidrust process resume SESSION
ghidrust process modules SESSION --json
ghidrust process resolve SESSION --module app.exe --rva 0x1234 --json
ghidrust process read SESSION --addr LIVE_VA --size 64 --json
ghidrust process regions SESSION --json
ghidrust process detach SESSION

# Unity / IL2CPP
ghidrust unity-inventory GAME_DIR --json
ghidrust il2cpp touch-map --meta GAME_DIR/*_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp meta GAME_DIR/*_Data/il2cpp_data/Metadata/global-metadata.dat --filter Camera --json
ghidrust il2cpp map --binary GAME_DIR/GameAssembly.dll --meta GAME_DIR/*_Data/il2cpp_data/Metadata/global-metadata.dat --json
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
| 5b | `Crypto Capabilities` | Encrypt/decrypt/encoding capability matches (imports, AES-NI, constant seeds). | `crypto_capabilities: [{function_va?, capability, tag, evidence, attack?, mbc?}]` | `matched N crypto/encoding capability hit(s)` |
| 6 | `Decompiler Parameter ID` | `mov [rbp+…], rcx/rdx` spill detection → `arg0:rcx` / `arg1:rdx`. No inventions on bare bodies. | `functions: [{entry, parameters: [str,…]}]` | `recovered parameters for N function(s)` |
| 7 | `Decompiler Switch Analysis` | Address tables → switch cases. | `switches: [{jump_va, cases: [[val, target], …]}]` | `recovered N switch table(s)` |
| 8 | `Demangler Microsoft` | MSVC `?…@@` demangler; `demangled` alongside raw. | `symbols: [{name, va, demangled?}]` | `demangled N symbol(s)` |
| 9 | `Embedded Media` | PNG / JPG / GIF / WAV / … magic scan. | `media: [{kind, va}]` | `found N media signature(s)` |
| 9b | `Find Crypt` | Cryptographic constant tables (S-box, TEA delta, hash K, stream sigma, …). | `crypt_constants: [{va, algorithm, constant, size}]` | `found N cryptographic constant hit(s)` |
| 10 | `Function ID` | Prologue-window hash → shipped `fid_*` catalog match. | `fid_matches: [{entry, matched_name}]` | `matched N FID signature(s)` |
| 11 | `Function Start Search` | Entry + symbols + exact `55 48 89 e5` + orphan `sub rsp, imm8`; grows to `ret`/`int3`; drops mid-body seeds. | `functions: [{entry, end, name}]` | `identified N function start(s)` |
| 12 | `Non-Returning Functions - Discovered` | `int3`-terminated bodies + known no-return imports. | `noreturn_entries: [va, …]` (+ `functions[*].noreturn`) | `marked N noreturn function(s)` |
| 12b | `Obfuscated Strings` | Stack / tight / decoded string recovery from executable blocks. | `obfuscated_strings: [{va, value, kind, decoder_va?, call_site?}]` | `recovered N obfuscated string(s)` |
| 13 | `PDB MSDIA` | MSF7 reader with MSDIA-shaped filtering. | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (msdia→universal)` |
| 14 | `PDB Universal` | MSF7 reader, unfiltered stream symbols (`MSF7` marker included). | `symbols: [{name, va}]` | `parsed N PDB symbol(s) (universal)` |
| 15 | `Shared Return Calls` | Callers reusing one epilogue (tail-call). | `shared_returns: [va, …]` | `marked N shared return site(s)` |
| 16 | `Stack` | Frame size + `param_…` slots from `sub rsp, imm` / `push rbp; mov rbp, rsp`; won't fabricate frames on functions with no real prologue. | `stack_frames: [[va, ["frame_size=0x…", "param_…", …]], …]` | `recovered N stack frame(s)` |
| 17 | `Variadic Function Signature Override` | Ensures `printf`/`sprintf`/`scanf` family symbols exist and marks them cdecl / `varargs=true` with a `format` param. | `varargs_entries: [va, …]` (+ `functions[*].varargs`) | `applied varargs to N function(s)` |
| 18 | `WindowsPE x86 PE RTTI Analyzer` | MSVC C++ RTTI: COL → class hierarchy → type-info → vtable, demangled class name. | `rtti: {classes: [{name, type_info_va, vtable_va, col_va, kind}], notes: [str,…]}` | `recovered N RTTI class record(s)` |
| 19 | `Windows x86 Propagate External Parameters` | Known Win32 API prototypes attached to import call sites. | `external_params: [[va, prototype], …]` | `applied N external parameter prototype(s)` |
| 20 | `WindowsResourceReference` | `.rsrc` records (`VERSION`, `RT_ICON`, …). | `resources: [{name, va}]` | `parsed N resource record(s)` |

**Defaults** (empty selection): `ASCII Strings`, `Unicode Strings`, `WindowsPE x86 PE RTTI Analyzer`, `Function Start Search`, `Create Address Tables`, `Embedded Media`, `Demangler Microsoft`, `Find Crypt`.

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

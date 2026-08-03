# Ghidnet — native network investigation (`tool_surface >= 8`)

In-tree attribute → detect → dig. No foreign capture/IDS products. Prefer MCP or GUI for multi-step sessions (`session_id` is process-local; CLI one-shot cannot reuse it).

## Surfaces

| Surface | Entry |
|---------|--------|
| MCP | `net_*` tools; check `server_info.network` (`native`, `wave`, `caps`, `capture`) |
| CLI | `ghidrust net dig\|playbook\|connections\|owners\|ifaces\|capture\|flows\|detect\|alerts\|rules\|pivots … [--json]` |
| GUI | **Network** menu / **Window → Network** — tabs Connections \| Capture \| Alerts \| Rules \| Dig |
| Helper bin | `target/release/ghidrust-netcap` |
| Rules pack | `rules/ghidrust-minimal.rules` (default for detect / GUI Rules **Check**) |

## MCP tools

| Tool | Args (common) | Notes |
|------|----------------|-------|
| `net_dig` | `path`, `pid`, `host`, `ioc`, `alert_id`, `execute`, `live` | Compile/execute playbook; closed-loop from alert |
| `net_playbook` | same hint fields | Plan only (MCP chain shape) |
| `net_connections` | `pid`, `path`, `proto`, `max` | Socket → owner; airgap refuses |
| `net_owners` | `pid` | Owner detail |
| `net_ifaces` | — | Interface list (loopback/replay stubs ok) |
| `net_capture_start` | `iface`, `filter`, `pid`, `path`, `out`, `replay_path` | Returns `session_id` |
| `net_capture_stop` / `net_capture_status` | `session_id` | |
| `net_flows` | `session_id`, `max` | Attributed flows |
| `net_detect` | `pcap`, `rules` | GNR → alerts |
| `net_alerts` | `max` | Severity queue |
| `net_rules_list` | — | Loaded/default pack summary |
| `net_rules_load` / `net_rules_check` | `path` | Compile-check GNR |
| `net_pivots` | `pcap` | DNS / TLS SNI / HTTP / SMB fields |
| `net_job_get` | `job_id` | **Stub** today (`status: unknown`) — do not rely on async jobs |

## Workflows

1. **Connections → Dig:** `net_connections` → pick remote/image → `net_dig` with `path` + `host`/`ioc` + `execute`.
2. **Capture → Dig:** `net_ifaces` → `net_capture_start` (`replay_path` in CI) → `net_flows` → `net_capture_stop` → dig owner `path`.
3. **Detect → Dig:** `net_rules_check` on pack → `net_detect` → `net_dig` with `alert_id` (+ `path` if alert has no owner).
4. **Pivots → Dig:** `net_pivots` → feed DNS/SNI/HTTP/SMB host into `net_dig` `host`/`ioc`.
5. **GUI:** Connections/Capture **Dig** → Dig tab **Compile**/**Execute** → **Open in Listing**. Capture **Export path** reveals `out_path`. Host header / Help→About show NetworkInfo. **Inline block** disabled unless `GHIDRUST_NET_INLINE=1|true`.

## Honesty

- Never invent hosts/IOCs; `pid_confidence=unknown` is not ground truth.
- Airgap: refuses `net_connections` / `net_owners` / `net_ifaces` / `net_capture_*` / `net_flows` / `net_detect`; path-only `net_dig` / `net_playbook` allowed.
- Live NIC may be stub/replay-first; prefer `replay_path` for proofs.
- Do not install Suricata/Wireshark/etc. as a substitute — engines are `ghidrust-net-*`.

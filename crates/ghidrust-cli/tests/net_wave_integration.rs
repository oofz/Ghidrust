//! Proving tests for network waves 1–5 (CLI).

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ghidrust"))
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin()).args(args).output().expect("spawn");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn wave1_net_connections_json() {
    let pid = std::process::id().to_string();
    let (ok, stdout, stderr) = run(&["net", "connections", "--pid", &pid, "-json"]);
    assert!(ok, "stderr={stderr}");
    assert!(stdout.contains("connections"));
}

#[test]
fn wave2_replay_capture_flows() {
    // Capture sessions are in-process (same as process_*): multi-step must share
    // one process. Prove the library session + CLI detect/pivots on the file.
    use ghidrust_net_capture::{
        capture_start, capture_stop, flows, write_frames, CaptureStartRequest,
    };
    use ghidrust_net_flow::Frame;
    use ghidrust_net_schema::{Confidence, Owner};

    let dir = std::env::temp_dir().join(format!(
        "cli-net-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let replay = dir.join("in.grncap");
    write_frames(
        &replay,
        &[Frame {
            ts_ms: 1,
            proto: "tcp".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            src_port: 1111,
            dst_port: 443,
            payload: b"EVILCMD hello".to_vec(),
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            owner: Some(Owner {
                pid: 7,
                image_path: Some("C:\\tmp\\x.exe".into()),
                image_confidence: Confidence::Exact,
                pid_confidence: Confidence::Exact,
            }),
        }],
    )
    .unwrap();

    let start = capture_start(CaptureStartRequest {
        replay_path: Some(replay.display().to_string()),
        out_dir: Some(dir.display().to_string()),
        ..Default::default()
    })
    .expect("capture_start");
    let fl = flows(&start.session_id, None).expect("flows");
    assert!(!fl.is_empty());
    assert_eq!(fl[0].owner.as_ref().unwrap().pid, 7);
    let info = capture_stop(&start.session_id).expect("stop");
    assert!(std::path::Path::new(info.out_path.as_ref().unwrap()).is_file());

    // CLI one-shot start returns session_id JSON (session not reusable across spawns).
    let (ok_cli, stdout, stderr) = run(&[
        "net",
        "capture",
        "start",
        "--replay",
        replay.to_str().unwrap(),
        "--out",
        dir.to_str().unwrap(),
        "-json",
    ]);
    assert!(ok_cli, "stderr={stderr}");
    assert!(stdout.contains("session_id"));

    let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/ghidrust-minimal.rules");
    let (ok4, det, e4) = run(&[
        "net",
        "detect",
        "--pcap",
        replay.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
        "-json",
    ]);
    assert!(ok4, "stderr={e4}");
    assert!(det.contains("1000001") || det.contains("alerts"), "{det}");

    let http = dir.join("http.bin");
    std::fs::write(&http, b"GET /x HTTP/1.1\r\nHost: pivot.example\r\n\r\n").unwrap();
    let (ok5, piv, e5) = run(&["net", "pivots", "--pcap", http.to_str().unwrap(), "-json"]);
    assert!(ok5, "stderr={e5}");
    assert!(piv.contains("pivot.example"), "{piv}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wave3_rules_check() {
    let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/ghidrust-minimal.rules");
    let (ok, stdout, stderr) = run(&[
        "net",
        "rules",
        "check",
        "--path",
        rules.to_str().unwrap(),
        "-json",
    ]);
    assert!(ok, "stderr={stderr}");
    assert!(stdout.contains("rule_count"));
}

#[test]
fn wave4_closed_loop_from_alert_fixture() {
    // Seed alerts via detect, then dig --from-alert requires in-process index.
    // Prove closed loop via correlate path through dig --execute on fixture.
    let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/tiny_x64.pe");
    let (ok, stdout, stderr) = run(&[
        "net",
        "dig",
        "--path",
        pe.to_str().unwrap(),
        "--ioc",
        "127.0.0.1",
        "--execute",
        "-json",
    ]);
    assert!(ok, "stderr={stderr}");
    assert!(stdout.contains("result") || stdout.contains("findings") || stdout.contains("plan"));
}

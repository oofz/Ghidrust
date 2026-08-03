//! Privilege-isolated capture helper process owned by Ghidrust.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("usage: ghidrust-netcap replay <capture-file> | status");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "status" => {
            println!(r#"{{"ok":true,"helper":"ghidrust-netcap","native":true}}"#);
            ExitCode::SUCCESS
        }
        "replay" => {
            let Some(path) = args.get(1) else {
                eprintln!("usage: ghidrust-netcap replay <capture-file>");
                return ExitCode::from(2);
            };
            match ghidrust_net_capture::read_frames(std::path::Path::new(path)) {
                Ok(frames) => {
                    println!(
                        "{}",
                        serde_json::json!({"ok":true,"frames":frames.len()})
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown command: {other}");
            ExitCode::from(2)
        }
    }
}

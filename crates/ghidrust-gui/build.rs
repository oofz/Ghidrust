fn main() {
    // Build scripts compile for the *host*. `winres` is only a
    // `[target.'cfg(windows)'.build-dependencies]` crate, so a runtime
    // `CARGO_CFG_TARGET_OS` check alone still type-checks `winres::` on Linux
    // hosts and fails with E0433. Compile-gate the call on host `cfg(windows)`,
    // and still skip when the *target* is not Windows (cross builds).
    #[cfg(windows)]
    {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        if target_os != "windows" {
            return;
        }
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/ghidrust.ico");
        if let Err(err) = res.compile() {
            // Keep non-MSVC / missing-RC toolchains buildable; icon is best-effort.
            println!("cargo:warning=windows icon embed skipped: {err}");
        }
    }
}

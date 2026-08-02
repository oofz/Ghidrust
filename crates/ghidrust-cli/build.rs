fn main() {
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

fn main() {
    let mut hay = vec![0u8; 2 * 1024 * 1024];
    for i in (0..hay.len()).step_by(100) {
        let m = b"GpuBulkTokenABCDEF";
        let e = (i + m.len()).min(hay.len());
        hay[i..e].copy_from_slice(&m[..e - i]);
    }
    let rep = ghidrust_core::scan_printable_runs_gpu_or_fallback(&hay, 4);
    let t = ghidrust_core::time_bulk_printable(&hay, 4);
    println!("gpu_backend={:?}", rep.backend);
    println!("hits={} workgroups={}", rep.hits.len(), rep.workgroups);
    println!(
        "seq_ms={:.3} par_ms={:.3} gpu_ms={:.3} threads={} seq_hits={} par_hits={} gpu_hits={}",
        t.seq_ms, t.par_ms, t.gpu_ms, t.threads, t.seq_hits, t.par_hits, t.gpu_hits
    );
    println!("par_backend={:?}", t.par_backend);
    println!("gpu_timing_backend={:?}", t.gpu_backend);
}

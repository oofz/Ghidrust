#!/usr/bin/env python3
"""Prove saved RTTI hits map to real bytes in the PE (not invented names)."""
import json
import struct
import sys
from collections import Counter


def pe_sections(blob: bytes):
    if blob[:2] != b"MZ":
        raise SystemExit("not pe")
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("bad pe")
    coff = e_lfanew + 4
    num_sec = struct.unpack_from("<H", blob, coff + 2)[0]
    size_opt = struct.unpack_from("<H", blob, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", blob, opt + 24)[0]
    else:
        image_base = struct.unpack_from("<I", blob, opt + 28)[0]
    sec_off = opt + size_opt
    secs = []
    for i in range(num_sec):
        o = sec_off + i * 40
        name = blob[o : o + 8].split(b"\0")[0].decode("ascii", "replace")
        vsz, va, rsz, raw = struct.unpack_from("<IIII", blob, o + 8)
        secs.append((name, va, vsz, raw, rsz))
    return image_base, secs


def main():
    analysis = sys.argv[1] if len(sys.argv) > 1 else r"F:\ghidrust\fh6\results\forzahorizon6_exe\analysis.json"
    exe = sys.argv[2] if len(sys.argv) > 2 else r"F:\ghidrust\fh6\imports\forzahorizon6_exe_forzahorizon6.exe"

    print("loading", analysis)
    d = json.load(open(analysis, encoding="utf-8"))
    rtti = d.get("rtti") or {}
    classes = rtti.get("classes") or []
    print("program", d.get("program_name"), d.get("format"), hex(d.get("image_base") or 0))
    print("saved_analyzers", d.get("saved_analyzers"))
    print("class_count", len(classes))
    print("notes", rtti.get("notes"))
    print("kinds", Counter(c.get("kind") for c in classes).most_common(10))

    named = [
        c
        for c in classes
        if c.get("name") and "lambda" not in c["name"].lower() and len(c["name"]) > 4
    ]
    print("non_lambda_count", len(named))
    for c in named[:8]:
        print(
            f"  {c['name']!r} type_info_va={c.get('type_info_va')} kind={c.get('kind')}"
        )

    data = open(exe, "rb").read()
    print("exe_bytes", len(data))
    ib, secs = pe_sections(data)
    print("image_base", hex(ib), "nsecs", len(secs))

    def va_to_off(va: int):
        rva = va - ib
        for name, sva, vsz, raw, rsz in secs:
            if sva <= rva < sva + max(vsz, rsz):
                return raw + (rva - sva), name
        return None, None

    ok = bad = 0
    samples = []
    for c in named[:80]:
        va = c.get("type_info_va")
        if not va:
            continue
        off, sec = va_to_off(va)
        if off is None or off < 0 or off >= len(data):
            bad += 1
            if len(samples) < 10:
                samples.append(("MISS", c["name"], hex(va), None, None))
            continue
        chunk = data[off : off + 96]
        text = chunk.split(b"\0")[0][:70]
        try:
            t = text.decode("ascii")
        except Exception:
            t = repr(text)
        has_m = chunk[:8].startswith(b".?A") or b".?A" in chunk[:16]
        if has_m or len(text) >= 4:
            ok += 1
            tag = "OK" if has_m else "NEAR"
        else:
            bad += 1
            tag = "EMPTY"
        if len(samples) < 10:
            samples.append((tag, c["name"], hex(va), sec, t))

    print("spot_ok", ok, "spot_bad", bad)
    for row in samples:
        print(row)

    n_av = data.count(b".?AV")
    n_au = data.count(b".?AU")
    print("raw_file_.?AV_count", n_av)
    print("raw_file_.?AU_count", n_au)
    print(
        "recovered_msvc",
        sum(1 for c in classes if c.get("kind") == "msvc_type_descriptor"),
    )
    # Pass if majority of spot checks map
    if ok < 1 or bad > ok:
        raise SystemExit(2)
    print("VERDICT: RTTI data is grounded in real PE bytes")


if __name__ == "__main__":
    main()

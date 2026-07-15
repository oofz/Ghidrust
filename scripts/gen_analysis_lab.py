#!/usr/bin/env python3
"""Build fixtures/analysis_lab.pe — PE32+ with real patterns for all analyzers."""
from __future__ import annotations
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
FIX.mkdir(exist_ok=True)

IMAGE_BASE = 0x140000000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def build() -> bytes:
    # --- .text layout (RVA 0x1000) ---
    # entry @ 0: standard FID prologue
    entry = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])
    # gap then second function (AIF target) with same start hash
    pad = b"\xCC" * 8
    # func_stack @ offset 0x20: push rbp; mov rbp,rsp; sub rsp,0x20; mov [rbp+10h],rcx; ret
    func_stack = bytes(
        [
            0x55,
            0x48,
            0x89,
            0xE5,
            0x48,
            0x83,
            0xEC,
            0x20,
            0x48,
            0x89,
            0x4D,
            0x10,
            0xC3,
        ]
    )
    # func_nr @ 0x40: no ret, ends in int3 (noreturn body)
    func_nr = bytes([0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xCC, 0xCC])
    # shared epilogue pattern twice for shared-return (add rsp; pop rbp; ret)
    shared_ep = bytes([0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3])
    # func_a ends with shared_ep; func_b ends with same
    func_a = bytes([0x55, 0x48, 0x89, 0xE5, 0x90, 0x90]) + shared_ep
    func_b = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC9]) + shared_ep

    text = bytearray(0x200)
    text[0:8] = entry
    text[0x10:0x10 + len(pad)] = pad
    # orphan code for AIF at 0x18 (gap from entry which ends 0x8)
    text[0x18:0x18 + 8] = bytes([0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0x5D, 0xC3])
    text[0x30 : 0x30 + len(func_stack)] = func_stack
    text[0x50 : 0x50 + len(func_nr)] = func_nr
    text[0x70 : 0x70 + len(func_a)] = func_a
    text[0x90 : 0x90 + len(func_b)] = func_b

    # --- .rdata (RVA 0x2000) ---
    rdata = bytearray()
    text_va = IMAGE_BASE + 0x1000

    def rva_here() -> int:
        return 0x2000 + len(rdata)

    def va_here() -> int:
        return IMAGE_BASE + rva_here()

    # API name strings (scanned by call_fixup / varargs / noreturn / external_params)
    api_names = [
        b"ExitProcess\0",
        b"printf\0",
        b"__security_check_cookie\0",
        b"?MyFunc@@YAXXZ\0",
        b".?AVLabClass@@\0",
    ]
    api_vas = []
    for name in api_names:
        api_vas.append(va_here())
        rdata += name
        while len(rdata) % 8:
            rdata += b"\0"

    # PNG
    png_va = va_here()
    rdata += bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    rdata += bytes([0, 0, 0, 0x0D, ord("I"), ord("H"), ord("D"), ord("R")]) + b"\0" * 16

    # Address / switch table: 4 pointers into .text
    while len(rdata) % 8:
        rdata += b"\0"
    at_va = va_here()
    targets = [text_va + 0x30, text_va + 0x50, text_va + 0x70, text_va + 0x90]
    for t in targets:
        rdata += struct.pack("<Q", t)

    # Resource marker
    rsrc_va = va_here()
    rdata += b"RS\0\0" + struct.pack("<I", 16) + b"VS_VERSION_INFO\0"
    while len(rdata) % 8:
        rdata += b"\0"

    # Mini-PDB: MSF7 magic + page size + symbol stream (hand format)
    pdb_va = va_here()
    pdb = bytearray(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")
    pdb += struct.pack("<I", 0x1000)  # page size
    # stream: u32 count, then (u64 va, u16 len, name bytes)
    syms = [
        (text_va, b"LabEntry"),
        (text_va + 0x30, b"LabStackFrame"),
        (text_va + 0x50, b"LabNoReturn"),
    ]
    stream = struct.pack("<I", len(syms))
    for va, nm in syms:
        stream += struct.pack("<QH", va, len(nm)) + nm
    pdb += stream
    rdata += pdb

    # --- assemble PE ---
    text_rva, rdata_rva = 0x1000, 0x2000
    entry_rva = text_rva
    size_of_headers = 0x200
    text_raw_size = align(len(text), FILE_ALIGN)
    rdata_raw_size = align(len(rdata), FILE_ALIGN)
    text_file = size_of_headers
    rdata_file = text_file + text_raw_size
    size_of_image = align(rdata_rva + align(len(rdata), SECT_ALIGN), SECT_ALIGN)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    opt[2] = 14
    struct.pack_into("<I", opt, 16, entry_rva)
    struct.pack_into("<Q", opt, 24, IMAGE_BASE)
    struct.pack_into("<I", opt, 32, SECT_ALIGN)
    struct.pack_into("<I", opt, 36, FILE_ALIGN)
    struct.pack_into("<H", opt, 40, 6)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, size_of_headers)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<H", opt, 70, 0x160)
    struct.pack_into("<Q", opt, 72, 0x100000)
    struct.pack_into("<Q", opt, 80, 0x1000)
    struct.pack_into("<Q", opt, 88, 0x100000)
    struct.pack_into("<Q", opt, 96, 0x1000)
    struct.pack_into("<I", opt, 108, 0x10)

    def sec(name, vsize, va, raw_size, raw_ptr, chars):
        return name[:8].ljust(8, b"\0") + struct.pack(
            "<IIIIIIHHI", vsize, va, raw_size, raw_ptr, 0, 0, 0, 0, chars
        )

    sh = sec(b".text", SECT_ALIGN, text_rva, text_raw_size, text_file, 0x60000020)
    sh += sec(b".rdata", SECT_ALIGN, rdata_rva, rdata_raw_size, rdata_file, 0x40000040)

    out = bytearray()
    out += dos + b"PE\0\0" + coff + opt + sh
    out += b"\0" * (size_of_headers - len(out))
    out += bytes(text).ljust(text_raw_size, b"\0")
    out += bytes(rdata).ljust(rdata_raw_size, b"\0")

    meta = {
        "image_base": hex(IMAGE_BASE),
        "entry": hex(IMAGE_BASE + entry_rva),
        "func_stack": hex(text_va + 0x30),
        "func_nr": hex(text_va + 0x50),
        "func_a": hex(text_va + 0x70),
        "func_b": hex(text_va + 0x90),
        "aif_orphan": hex(text_va + 0x18),
        "png_va": hex(png_va),
        "addr_table": hex(at_va),
        "rsrc_va": hex(rsrc_va),
        "pdb_va": hex(pdb_va),
        "api_exit": hex(api_vas[0]),
        "api_printf": hex(api_vas[1]),
        "api_cookie": hex(api_vas[2]),
        "mangled": hex(api_vas[3]),
    }
    (FIX / "analysis_lab.meta.txt").write_text(
        "\n".join(f"{k}={v}" for k, v in meta.items()) + "\n", encoding="utf-8"
    )
    return bytes(out)


def main():
    pe = build()
    path = FIX / "analysis_lab.pe"
    path.write_bytes(pe)
    print(f"wrote {path} ({len(pe)} bytes)")
    print((FIX / "analysis_lab.meta.txt").read_text())


if __name__ == "__main__":
    main()

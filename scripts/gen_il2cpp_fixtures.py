#!/usr/bin/env python3
"""Write synthetic IL2CPP fixtures (no game binaries)."""
from __future__ import annotations
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures" / "il2cpp"
FIX.mkdir(parents=True, exist_ok=True)

MAGIC = 0xFAB11BAF
IMAGE_BASE = 0x140000000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000


def align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def build_meta(version: int = 31) -> bytes:
    heap = bytearray()

    def push_str(s: str) -> int:
        off = len(heap)
        heap.extend(s.encode("utf-8") + b"\0")
        return off

    ns = push_str("UnityEngine")
    cam = push_str("Camera")
    get_main = push_str("get_main")
    asm = push_str("UnityEngine.CoreModule.dll")

    type_def = bytearray(88)
    struct.pack_into("<i", type_def, 0, cam)
    struct.pack_into("<i", type_def, 4, ns)
    struct.pack_into("<i", type_def, 36, 0)
    struct.pack_into("<H", type_def, 64, 1)
    struct.pack_into("<I", type_def, 84, 0x02000001)

    method_def = bytearray(32)
    struct.pack_into("<i", method_def, 0, get_main)
    struct.pack_into("<i", method_def, 4, 0)
    struct.pack_into("<I", method_def, 20, 0x06000001)

    image = bytearray(40)
    struct.pack_into("<i", image, 0, asm)
    struct.pack_into("<i", image, 8, 0)
    struct.pack_into("<I", image, 12, 1)

    pair_count = 31
    i_sl, i_sld, i_str, i_me, i_ty, i_im = 0, 1, 2, 5, 19, 20

    hdr = bytearray(struct.pack("<Ii", MAGIC, version))
    hdr += b"\0" * (pair_count * 8)

    def patch(i: int, offset: int, size: int) -> None:
        base = 8 + i * 8
        hdr[base : base + 8] = struct.pack("<II", offset, size)

    tables = bytearray()
    hdr_len = len(hdr)
    patch(i_sl, hdr_len, 0)
    patch(i_sld, hdr_len, 0)

    str_off = hdr_len + len(tables)
    tables += heap
    patch(i_str, str_off, len(heap))

    ty_off = hdr_len + len(tables)
    tables += type_def
    patch(i_ty, ty_off, len(type_def))

    me_off = hdr_len + len(tables)
    tables += method_def
    patch(i_me, me_off, len(method_def))

    im_off = hdr_len + len(tables)
    tables += image
    patch(i_im, im_off, len(image))

    return bytes(hdr + tables)


def build_stub_pe() -> bytes:
    text = bytearray(0x80)
    rdata = bytearray()
    name = b"UnityEngine.Camera::get_main\0"
    rdata += name
    while len(rdata) % 8:
        rdata += b"\0"
    slot_off = len(rdata)
    rdata += struct.pack("<Q", 0)

    name_va = IMAGE_BASE + 0x2000
    slot_va = IMAGE_BASE + 0x2000 + slot_off
    stub_va = IMAGE_BASE + 0x1000

    disp = name_va - (stub_va + 7)
    text[0:3] = bytes([0x48, 0x8D, 0x0D])
    struct.pack_into("<i", text, 3, disp)
    text[7:12] = bytes([0xE8, 0, 0, 0, 0])
    store_va = stub_va + 12
    disp2 = slot_va - (store_va + 7)
    text[12:15] = bytes([0x48, 0x89, 0x05])
    struct.pack_into("<i", text, 15, disp2)
    text[19:21] = bytes([0xFF, 0xE0])
    text[0x40:0x43] = bytes([0x31, 0xC0, 0xC3])

    text_rva, rdata_rva = 0x1000, 0x2000
    entry_rva = text_rva + 0x40
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
    return bytes(out)


def main() -> None:
    for ver in (27, 29, 31):
        p = FIX / f"meta_v{ver}.dat"
        p.write_bytes(build_meta(ver))
        print(f"wrote {p} ({p.stat().st_size} bytes)")
    stub = FIX / "il2cpp_stub_lab.pe"
    stub.write_bytes(build_stub_pe())
    print(f"wrote {stub} ({stub.stat().st_size} bytes)")
    (FIX / "README.txt").write_text(
        "Synthetic IL2CPP fixtures for ghidrust-il2cpp / CLI acceptance.\n"
        "Regenerate: python scripts/gen_il2cpp_fixtures.py\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

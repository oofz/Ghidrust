#!/usr/bin/env python3
"""Generate tiny PE32+ / ELF64 fixtures with known code and MSVC-style RTTI."""
from __future__ import annotations
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures"
FIX.mkdir(exist_ok=True)

# x86-64 prologue used as ground truth:
# 55                push rbp
# 48 89 e5          mov rbp, rsp
# 31 c0             xor eax, eax
# 5d                pop rbp
# c3                ret
CODE = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])


def align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def build_pe_with_rtti() -> bytes:
    """Minimal PE32+ with .text + .rdata containing MSVC RTTI for class Widget."""
    image_base = 0x140000000
    file_align = 0x200
    sect_align = 0x1000

    # Section layout (RVAs)
    text_rva = 0x1000
    rdata_rva = 0x2000
    entry_rva = text_rva

    # --- build .rdata content with RTTI ---
    # Layout in .rdata:
    # 0x00: TypeDescriptor for Widget
    #   +0: vfptr (8) = 0 (placeholder)
    #   +8: spare (8) = 0
    #   +16: name ".?AVWidget@@\0"
    # then pad to 8
    # COL at known offset
    #   signature=1, offset=0, cdOffset=0, pTypeDescriptor=RVA, pClassDescriptor=RVA, pSelf=COL_RVA
    # ClassHierarchyDescriptor minimal
    # vtable: [COL_ptr][fn0]

    name = b".?AVWidget@@\0"
    # We'll compute RVAs as we assemble a bytearray for rdata
    rdata = bytearray()

    def rva_here() -> int:
        return rdata_rva + len(rdata)

    # TypeDescriptor
    td_rva = rva_here()
    rdata += struct.pack("<QQ", 0, 0)  # vfptr, spare
    rdata += name
    while len(rdata) % 8:
        rdata += b"\0"

    # ClassHierarchyDescriptor: signature, attributes, numBaseClasses, pBaseClassArray
    chd_rva = rva_here()
    # pBaseClassArray filled later
    chd_placeholder = len(rdata)
    rdata += struct.pack("<IIII", 0, 0, 1, 0)  # last is pBaseClassArray RVA

    # BaseClassDescriptor: pTypeDescriptor, numContained, mdisp, pdisp, vdisp, attributes, pClassDescriptor
    bcd_rva = rva_here()
    rdata += struct.pack("<IIIIIII", td_rva, 0, 0, -1 & 0xFFFFFFFF, 0, 0, chd_rva)

    # Base class array: one pointer (RVA) to BCD
    bca_rva = rva_here()
    rdata += struct.pack("<I", bcd_rva)
    while len(rdata) % 8:
        rdata += b"\0"

    # fix CHD pBaseClassArray
    struct.pack_into("<I", rdata, chd_placeholder + 12, bca_rva)

    # Complete Object Locator
    col_rva = rva_here()
    rdata += struct.pack(
        "<IIIIII",
        1,  # signature x64
        0,  # offset
        0,  # cdOffset
        td_rva,
        chd_rva,
        col_rva,  # pSelf
    )
    while len(rdata) % 8:
        rdata += b"\0"

    # meta pointer slot then vtable[0] = entry (as fake virtfn)
    # MSVC: object -> vtable; vtable[-1] = COL*
    col_va = image_base + col_rva
    vtable_meta_rva = rva_here()
    rdata += struct.pack("<Q", col_va)  # COL pointer (vtable[-1])
    vtable_rva = rva_here()
    rdata += struct.pack("<Q", image_base + entry_rva)  # vtable[0]

    # also embed a pure Itanium-style name for second class recovery path
    itanium = b"_ZTS6Gadget\0"
    rdata += itanium
    while len(rdata) % 16:
        rdata += b"\0"

    text_raw = bytearray(CODE)
    while len(text_raw) < 0x40:
        text_raw += b"\xCC"
    rdata_raw = bytes(rdata)

    # headers
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    pe_offset = 0x80
    # COFF
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine
        2,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xF0,  # SizeOfOptionalHeader PE32+
        0x22,  # Characteristics EXECUTABLE | LARGE_ADDRESS_AWARE
    )

    # Optional header PE32+
    size_of_headers = align(pe_offset + 4 + 20 + 0xF0 + 2 * 40, file_align)
    text_file = size_of_headers
    rdata_file = text_file + align(len(text_raw), file_align)
    size_of_image = align(rdata_rva + align(len(rdata_raw), sect_align), sect_align)

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)  # magic
    opt[2] = 14  # major linker
    struct.pack_into("<I", opt, 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, image_base)
    struct.pack_into("<I", opt, 32, sect_align)
    struct.pack_into("<I", opt, 36, file_align)
    struct.pack_into("<H", opt, 40, 6)  # major OS
    struct.pack_into("<H", opt, 48, 6)  # major subsystem ver? actually MajorImageVersion at 44
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, size_of_headers)
    struct.pack_into("<H", opt, 68, 3)  # subsystem console
    struct.pack_into("<H", opt, 70, 0x160)  # dll characteristics
    struct.pack_into("<Q", opt, 72, 0x100000)  # stack reserve
    struct.pack_into("<Q", opt, 80, 0x1000)
    struct.pack_into("<Q", opt, 88, 0x100000)
    struct.pack_into("<Q", opt, 96, 0x1000)
    struct.pack_into("<I", opt, 108, 0x10)  # number of RVA/sizes
    # data directories leave zero

    # Section headers
    def sec_hdr(name: bytes, vsize, va, raw_size, raw_ptr, chars) -> bytes:
        nb = name[:8].ljust(8, b"\0")
        return nb + struct.pack("<IIIIIIHHI", vsize, va, raw_size, raw_ptr, 0, 0, 0, 0, chars)

    text_chars = 0x60000020  # CODE | EXECUTE | READ
    rdata_chars = 0x40000040  # INIT_DATA | READ
    text_raw_size = align(len(text_raw), file_align)
    rdata_raw_size = align(len(rdata_raw), file_align)
    sh_text = sec_hdr(b".text", align(len(text_raw), sect_align), text_rva, text_raw_size, text_file, text_chars)
    sh_rdata = sec_hdr(b".rdata", align(len(rdata_raw), sect_align), rdata_rva, rdata_raw_size, rdata_file, rdata_chars)

    out = bytearray()
    out += dos
    out += b"PE\0\0"
    out += coff
    out += opt
    out += sh_text
    out += sh_rdata
    assert len(out) <= size_of_headers
    out += b"\0" * (size_of_headers - len(out))
    out += text_raw.ljust(text_raw_size, b"\0")
    out += rdata_raw.ljust(rdata_raw_size, b"\0")

    # write a sidecar of expected addresses for tests
    meta = {
        "image_base": hex(image_base),
        "entry": hex(image_base + entry_rva),
        "text_va": hex(image_base + text_rva),
        "rdata_va": hex(image_base + rdata_rva),
        "td_va": hex(image_base + td_rva),
        "col_va": hex(image_base + col_rva),
        "vtable_va": hex(image_base + vtable_rva),
        "class": "Widget",
        "code_hex": CODE.hex(),
    }
    (FIX / "tiny_x64_pe.meta.txt").write_text(
        "\n".join(f"{k}={v}" for k, v in meta.items()) + "\n", encoding="utf-8"
    )
    return bytes(out)


def build_elf() -> bytes:
    """Minimal ELF64 ET_EXEC with one PT_LOAD + .text-like content at 0x401000."""
    entry = 0x401000
    # We'll use section headers for named .text
    # Simple approach: ELF header + program header + section headers + data

    # Layout in file:
    # 0x00: ELF header (64)
    # 0x40: program header (56)
    # 0x78: section headers — null, .text, .shstrtab
    # then data

    ehdr_size = 64
    phdr_size = 56
    shdr_size = 64
    phoff = 64
    # put section data after headers
    shnum = 3
    shstrtab = b"\0.text\0.shstrtab\0"
    # file layout after ehdr+phdr:
    text_off = 0x200
    text = CODE + b"\xCC" * 8
    shstr_off = text_off + 0x100
    shoff = shstr_off + align(len(shstrtab), 16)

    # section 0 NULL
    # section 1 .text name at 1
    # section 2 .shstrtab name at 7

    def shdr(name_off, typ, flags, addr, offset, size, link=0, info=0, addralign=16, entsize=0):
        return struct.pack(
            "<IIQQQQIIQQ",
            name_off,
            typ,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
        )

    sh_null = shdr(0, 0, 0, 0, 0, 0)
    sh_text = shdr(1, 1, 6, entry, text_off, len(text), addralign=16)  # PROGBITS, ALLOC|EXEC
    sh_shstr = shdr(7, 3, 0, 0, shstr_off, len(shstrtab))  # STRTAB

    # program header PT_LOAD covering text
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # PF_R|PF_X
        text_off,
        entry,
        entry,
        len(text),
        len(text),
        0x1000,
    )

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # ELFCLASS64
    ehdr[5] = 1  # little
    ehdr[6] = 1
    struct.pack_into("<H", ehdr, 16, 2)  # ET_EXEC
    struct.pack_into("<H", ehdr, 18, 0x3E)  # EM_X86_64
    struct.pack_into("<I", ehdr, 20, 1)
    struct.pack_into("<Q", ehdr, 24, entry)
    struct.pack_into("<Q", ehdr, 32, phoff)
    struct.pack_into("<Q", ehdr, 40, shoff)
    struct.pack_into("<H", ehdr, 52, ehdr_size)
    struct.pack_into("<H", ehdr, 54, phdr_size)
    struct.pack_into("<H", ehdr, 56, 1)  # phnum
    struct.pack_into("<H", ehdr, 58, shdr_size)
    struct.pack_into("<H", ehdr, 60, shnum)
    struct.pack_into("<H", ehdr, 62, 2)  # shstrndx

    out = bytearray(shoff + shnum * shdr_size)
    out[0:64] = ehdr
    out[phoff : phoff + phdr_size] = phdr
    out[text_off : text_off + len(text)] = text
    out[shstr_off : shstr_off + len(shstrtab)] = shstrtab
    shblob = sh_null + sh_text + sh_shstr
    out[shoff : shoff + len(shblob)] = shblob

    (FIX / "tiny_x64_elf.meta.txt").write_text(
        f"entry={hex(entry)}\ncode_hex={CODE.hex()}\n", encoding="utf-8"
    )
    return bytes(out)


def main():
    pe = build_pe_with_rtti()
    (FIX / "tiny_x64.pe").write_bytes(pe)
    elf = build_elf()
    (FIX / "tiny_x64.elf").write_bytes(elf)
    print(f"wrote {FIX / 'tiny_x64.pe'} ({len(pe)} bytes)")
    print(f"wrote {FIX / 'tiny_x64.elf'} ({len(elf)} bytes)")
    print((FIX / "tiny_x64_pe.meta.txt").read_text())


if __name__ == "__main__":
    main()

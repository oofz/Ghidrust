#!/usr/bin/env python3
"""Generate mos65xx/table.rs from Capstone inc files (one-time bootstrap)."""
import re
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/capstone-engine/capstone/next/arch/MOS65XX/"

AM_MAP = {
    "MOS65XX_AM_NONE": "None",
    "MOS65XX_AM_IMP": "Imp",
    "MOS65XX_AM_ACC": "Acc",
    "MOS65XX_AM_IMM": "Imm",
    "MOS65XX_AM_REL": "Rel",
    "MOS65XX_AM_ZP": "Zp",
    "MOS65XX_AM_ZP_X": "ZpX",
    "MOS65XX_AM_ZP_Y": "ZpY",
    "MOS65XX_AM_ABS": "Abs",
    "MOS65XX_AM_ABS_X": "AbsX",
    "MOS65XX_AM_ABS_Y": "AbsY",
    "MOS65XX_AM_ZP_IND": "ZpInd",
    "MOS65XX_AM_ZP_X_IND": "ZpXInd",
    "MOS65XX_AM_ZP_IND_Y": "ZpIndY",
    "MOS65XX_AM_ABS_IND": "AbsInd",
    "MOS65XX_AM_INT": "Int",
    "MOS65XX_AM_ZP_REL": "ZpRel",
    "MOS65XX_AM_ABS_X_IND": "AbsXInd",
    "MOS65XX_AM_ABS_IND_LONG": "AbsIndLong",
    "MOS65XX_AM_ZP_IND_LONG": "ZpIndLong",
    "MOS65XX_AM_ZP_IND_LONG_Y": "ZpIndLongY",
    "MOS65XX_AM_ABS_LONG": "AbsLong",
    "MOS65XX_AM_ABS_LONG_X": "AbsLongX",
    "MOS65XX_AM_SR": "Sr",
    "MOS65XX_AM_SR_IND_Y": "SrIndY",
    "MOS65XX_AM_BLOCK": "Block",
}


def fetch(name: str) -> str:
    return urllib.request.urlopen(BASE + name).read().decode()


def parse_inc(name: str):
    rows = []
    for line in fetch(name).splitlines():
        m = re.match(
            r"\{\s*MOS65XX_INS_(\w+)\s*,\s*(MOS65XX_AM_\w+)\s*,\s*(\d+)\s*\}",
            line.strip().rstrip(","),
        )
        if not m:
            continue
        ins, am, ob = m.group(1), m.group(2), int(m.group(3))
        rows.append((ins, AM_MAP[am], ob))
    assert len(rows) == 256, (name, len(rows))
    return rows


def emit_table(name: str, rows) -> str:
    lines = [f"pub const {name}: [OpEntry; 256] = ["]
    for i, (ins, am, ob) in enumerate(rows):
        if ins == "INVALID":
            entry = f'OpEntry {{ mnemonic: "nop", insn: InsnId::INVALID, mode: AddrMode::{am}, operand_bytes: {ob} }}'
        else:
            mn = ins.lower()
            entry = (
                f'OpEntry {{ mnemonic: "{mn}", insn: InsnId::{ins}, '
                f"mode: AddrMode::{am}, operand_bytes: {ob} }}"
            )
        lines.append(f"    {entry}, // 0x{i:02x}")
    lines.append("];")
    return "\n".join(lines)


def main():
    out = Path(__file__).resolve().parents[1] / "src" / "arch" / "mos65xx" / "table.rs"
    out.parent.mkdir(parents=True, exist_ok=True)
    m6502 = parse_inc("m6502.inc")
    m65c02 = parse_inc("m65c02.inc")
    body = """//! Auto-generated 6502 / 65C02 opcode tables (Capstone m6502.inc / m65c02.inc layout).

use super::{AddrMode, InsnId, OpEntry};

"""
    body += emit_table("TABLE_6502", m6502) + "\n\n"
    body += emit_table("TABLE_65C02", m65c02) + "\n"
    out.write_text(body, encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()

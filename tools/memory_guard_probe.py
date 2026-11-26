"""Synthetic child that attempts to exceed the memory_guard Job Object cap."""

import argparse
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--confirm-allocation", action="store_true")
parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
options = parser.parse_args()
if not options.worker and not options.confirm_allocation:
    parser.error("run only under memory_guard.py and pass --confirm-allocation")

if not options.worker:
    # Verify that a child spawned by the supervised process inherits the job.
    child = subprocess.Popen([sys.executable, __file__, "--worker"])
    raise SystemExit(child.wait())

chunks = []
while True:
    block = bytearray(128 * 1024 * 1024)
    for offset in range(0, len(block), 4096):
        block[offset] = 1
    chunks.append(block)
    print(f"allocated={len(chunks) * len(block)}", flush=True)
    time.sleep(0.05)

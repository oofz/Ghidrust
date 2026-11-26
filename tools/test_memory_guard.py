"""Windows-only failure-path tests for memory_guard.py; run under the guard."""

from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

if os.name != "nt":
    raise SystemExit("memory_guard tests require Windows")

GUARD_PATH = pathlib.Path(__file__).with_name("memory_guard.py")
SPEC = importlib.util.spec_from_file_location("memory_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(guard)


def run_args(command: list[str], *, log: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        memory_gib=1,
        headroom_mib=128,
        timeout=10.0,
        system_commit_fraction=0.99,
        cwd=None,
        log=log,
        command=command,
    )


class MemoryGuardFailureTests(unittest.TestCase):
    def test_job_is_named_by_suspended_target_pid(self) -> None:
        kernel32 = guard.kernel32
        kernel32.OpenJobObjectW.argtypes = [
            guard.wintypes.DWORD, guard.wintypes.BOOL, guard.wintypes.LPCWSTR
        ]
        kernel32.OpenJobObjectW.restype = guard.wintypes.HANDLE
        job_name = os.environ.get("GHIDRUST_MEMORY_GUARD_JOB")
        self.assertTrue(job_name, "supervised descendants must inherit the named Job Object")
        handle = kernel32.OpenJobObjectW(
            0x0004,
            False,
            job_name,
        )
        self.assertTrue(handle, "memory_guard must publish its named hard-limit job")
        self.assertTrue(kernel32.CloseHandle(handle))

    def test_assignment_failure_terminates_suspended_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            marker = pathlib.Path(temp, "started")
            code = f"open({str(marker)!r}, 'w', encoding='utf-8').write('bad')"
            real_assign = guard.kernel32.AssignProcessToJobObject
            guard.kernel32.AssignProcessToJobObject = lambda *_args: 0
            try:
                with self.assertRaises(OSError):
                    guard.run(run_args([sys.executable, "-c", code]))
            finally:
                guard.kernel32.AssignProcessToJobObject = real_assign
            self.assertFalse(marker.exists(), "suspended child ran after failed job assignment")

    def test_log_failure_does_not_skip_handle_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            real_close = guard.kernel32.CloseHandle
            closed: list[int] = []

            def tracking_close(handle: int) -> int:
                closed.append(int(handle))
                return real_close(handle)

            guard.kernel32.CloseHandle = tracking_close
            try:
                rc = guard.run(run_args(
                    [sys.executable, "-c", "pass"], log=temp
                ))
            finally:
                guard.kernel32.CloseHandle = real_close
            self.assertEqual(rc, 0)
            self.assertEqual(len(closed), 3, "process, thread, and job handles must close")

    def test_system_commit_uses_performance_info(self) -> None:
        committed, limit = guard.system_commit()
        self.assertGreater(committed, 0)
        self.assertGreaterEqual(limit, committed)


if __name__ == "__main__":
    unittest.main()

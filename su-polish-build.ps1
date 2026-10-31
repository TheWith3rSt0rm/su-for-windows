# ================================================================
#  su polish v7.34 - run as a FILE in a FRESH elevated PowerShell
#  (the sethc trapdoor shell itself is also accepted - it IS SYSTEM):
#    powershell -NoProfile -ExecutionPolicy Bypass -File "<path>\su-fix-v7.34.ps1"
#
#  THE v7.34 STORY, corrected by field round 35 (your report: 'su user
#    works from a system shell when I launched it in a true cmd'):
#
#    ROUND 34's FIRST CLAIM IS RETRACTED. It said the su-sys gate
#    (IsInRole Administrator) rejected the SYSTEM trapdoor shell.
#    Wrong: a SYSTEM token DOES carry BUILTIN\Administrators (whoami
#    /groups as SYSTEM lists it - 'Enabled by default, Enabled group,
#    Group owner'), and your test is the behavioral proof: su ran
#    fine from a SYSTEM cmd on the interactive desktop, gate and
#    all. The gate was never the blocker. The SYSTEM-SID acceptance
#    in section 2a stays as LABELED BELT (costs nothing, covers a
#    stripped-token future), not as a fix.
#
#    THE ROOT CAUSE - and your test is the perfect control experiment:
#    SAME token (SYSTEM), DIFFERENT console -> works in a true cmd,
#    dead in the sethc shell. The only variable left is WHERE THE
#    WINDOW IS BORN:
#      - a true-cmd SYSTEM shell lives on winsta0\default (the
#        interactive desktop) -> every su spawn lands there -> visible.
#      - the sethc trapdoor cmd lives on the SECURE desktop
#        (WinSta0\Winlogon, same session 1) - and every v7.33 spawn
#        site hardcoded si.lpDesktop = "winsta0\\default" -> the
#        wrapper, the TI / user / SYSTEM windows, ALL of them were
#        born on the locked user desktop BEHIND the logon screen.
#        The routes RAN - tokens minted, attaches proven, watchdog
#        verdicts green - into windows nobody could see. 'It does
#        not work in this shell' was really 'it works, invisibly,
#        one desktop away'. Smoking gun you can check any time:
#        run su from the trapdoor shell, log back in - the orphan
#        su window (dark, 120x30) is sitting on your desktop, still
#        alive.
#
#    THE FIX: three spawn sites now LEAVE lpDesktop UNSET - the child
#    inherits the CALLER'S desktop:
#      - DLL SpawnWrapperUser (the wrapper console, born under the
#        caller's token): INHERIT. This is what makes 'su ti' and
#        'su <user>' VISIBLE at the logon screen.
#      - Su.T SpawnWithToken + SpawnAsUser (the direct spawns: every
#        fallback + the whole System route): INHERIT. 'su sys' gets a
#        window ON the login screen - SYSTEM holds the secure-desktop
#        access, so conhost-under-SYSTEM may create a window there.
#      - DLL SpawnInherit + SpawnInheritAsUser (the inner drops):
#        KEEP winsta0\default. Their clients ATTACH to the already
#        visible wrapper console without creating any window, and
#        winsta0\default is the desktop their granted ACE lives on -
#        a foreign-SID ACE on the secure desktop itself: never.
#    On a normal desktop inheritance resolves to winsta0\default -
#    the exact value hardcoded since v5 - so nothing changes there.
#    The trapdoor cmd's own window is the live proof that a console
#    can be born on the secure desktop; the 10-second pre-test below
#    proves it twice.
#
#    BY DESIGN AT THE LOGON SCREEN: the DIRECT-spawn fallbacks under
#    a FOREIGN token (TI / user) may now fail HONESTLY with 0xc0000142
#    or F:spawn - the foreign SID has no ACE on the secure desktop and
#    this kit will never add one. The wrapper route is the only window
#    path at the logon screen; a fallback failure there is one clean
#    [D] line, not a silent invisible success.
#
#    THE HONEST UNCERTAINTY (the one unproven link): the inner client
#    (TI / user cmd) connects user32 to winsta0\default (lpDesktop
#    kept - its granted ACE lives there) while ATTACHING to a wrapper
#    console whose window lives on the secure desktop. Cross-TOKEN
#    attach is field-proven since v7.21; cross-DESKTOP attach is new
#    in v7.34. If it fails, the inner writes 'WRAPPER-INHERIT-FAILED'
#    with the exact failing call, the watchdog falls back, and the
#    direct spawn reports its honest error - that [D] line is the
#    next field report.
#
#    ALSO IN THIS ROUND (labeled belt, not fixes):
#    - su.bat: all three 'net session' probes go through
#      :su_rootcheck, which also accepts the SYSTEM SID - belt for a
#      world where the probe fails while the SID still says root.
#    - the v7.33 re-run debris on the installed su-sys.ps1 (a tripled
#      verdict route-facts line, a doubled block comment) normalized.
#    - this fixer installs itself over su-polish-build.ps1, so the
#      canonical rebuild path can never recompile the DLL back to the
#      v7.33 blind-wrapper.
#
#  10-SECOND PRE-TEST (no install needed): at the logon screen, in
#    the trapdoor cmd, run:   start cmd
#    A second cmd opens right there ON the login screen = desktop
#    inheritance is proven live on this machine = the v7.34 mechanism.
#
#  EXPECTED AFTER GREEN:
#    normal desktop, elevated:  su ti / su <user> / su sys - byte-
#      identical behavior to v7.33 (run this regression check FIRST).
#    logon screen (Win+L, Shift x5, the trapdoor cmd):
#      su ti        ONE dark window ON the login screen, whoami =
#                   nt service\trustedinstaller
#      su <user>    ONE dark window ON the login screen, whoami = the
#                   user (S4U re-mint inside the wrapper; the hive
#                   even gets loaded for registry surgery)
#      su sys       a fresh SYSTEM window on the login screen
#    nothing visible + a [D] line = send that line back.
# ================================================================
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$fixerIsSystem = $false
try { $fixerIsSystem = ($id.User.Value -eq 'S-1-5-18') } catch {}
if (-not ($fixerIsSystem -or $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '[!] run this in your normal ELEVATED console, not inside a su window'; return
}

# ---- 0) preflight: this fixer upgrades an INSTALLED v7.33 kit ----
$suSys  = "$env:windir\System32\su-sys.ps1"
$suBat  = "$env:windir\System32\su.bat"
$relayP = "$env:windir\System32\su-relay.ps1"
$buildP = "$env:windir\System32\su-polish-build.ps1"
foreach ($p in @($suSys, $suBat)) {
    if (-not (Test-Path $p)) { Write-Host "[!] $p not found - v7.34 upgrades an installed v7.33 kit (run su-fix-v7.33.ps1 first on a fresh machine)"; return }
}
$raw = [IO.File]::ReadAllText($suSys)
if (-not $raw.Contains('function Invoke-SuSpawnUserV733(')) {
    Write-Host '[!] the v7.33 user-wrapper machinery is not in su-sys.ps1 (definition probe failed)'; return
}
$nl = "`r`n"
if (-not $raw.Contains("`r`n")) { $nl = "`n" }
Write-Host ('[i] target su-sys.ps1: {0} (newline: {1})' -f $suSys, $(if ($nl -eq "`r`n") { 'CRLF' } else { 'LF' }))
function Su-Join([string]$eol, [string[]]$lines) { $lines -join $eol }

# ---- 1) rebuild su-polish.dll v7.34 (the v7.33 C# verbatim except the
#      wrapper desktop inheritance + the version string) ----
$cs = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
using System.Threading;

public static class Polish {
    public struct COORD { public short X; public short Y; }
    public struct SMALL_RECT { public short Left; public short Top; public short Right; public short Bottom; }
    private struct LUID { public uint LowPart; public int HighPart; }
    private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    private struct TOKEN_PRIVILEGES { public uint Count; public LUID_AND_ATTRIBUTES Privilege; }
    // v7.20 ROOT-CAUSE FIX (kept): the native struct is 96 bytes, not 92.
    // v7.17-v7.19 omitted wPopupAttributes (2) AND bFullscreenSupported
    // (BOOL, 4); the marshaler's alignment padding before the discrete
    // uints masked the loss at "92" and the fake "(native 92)" check
    // blessed it. ct00..ct15 field names kept so all callers still work.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CONSOLE_SCREEN_BUFFER_INFOEX {
        public uint cbSize;
        public COORD dwSize; public COORD dwCursorPosition; public ushort wAttributes;
        public SMALL_RECT srWindow; public COORD dwMaximumWindowSize;
        public ushort wPopupAttributes; public uint bFullscreenSupported;
        public uint ct00, ct01, ct02, ct03, ct04, ct05, ct06, ct07;
        public uint ct08, ct09, ct10, ct11, ct12, ct13, ct14, ct15;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }
    public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int hStdHandle);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleScreenBufferInfoEx(IntPtr hConsoleOutput, ref CONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfo);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleScreenBufferInfoEx(IntPtr hConsoleOutput, ref CONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfo);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleTextAttribute(IntPtr hConsoleOutput, ushort wAttributes);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr hObject);
    // v7.27 ROOT CAUSE: kernel32.dll exports NO GetConsoleProcessIds - the
    // real API is GetConsoleProcessList (Vista+). v7.19-v7.26 called the
    // ghost name, so every attach proof threw EntryPointNotFoundException
    // AFTER the child was already spawned; the kill-on-not-attached path
    // never ran and each failed drop leaked a live stray TI console.
    [DllImport("kernel32.dll", SetLastError = false, EntryPoint = "GetConsoleProcessList")] static extern uint GetConsoleProcessList([Out] uint[] lpdwProcessList, uint dwProcessCount);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")] static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    // v7.21: in-process creation with a primary token - console inheritance
    // is plain CreateProcess semantics (unlike seclogon's WithTokenW).
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetClassNameW")] public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetWindowTextW")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpWindowText, int nMaxCount);
    [DllImport("user32.dll", SetLastError = true)] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, ref int lpdwProcessId);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
    [DllImport("user32.dll", SetLastError = true)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam, uint fuFlags, uint uTimeout, out IntPtr lpdwResult);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] public static extern int SetWindowTheme(IntPtr hwnd, string pszSubAppName, string pszSubIdList);
    [DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);
    public static string Ver() { return "su-polish 7.34"; }
    // v7.18 kept: enumerate every top-level window -> "hwnd;class;pid;vis;caption"
    public static string[] ListWindows() {
        List<string> l = new List<string>();
        EnumWindowsProc cb = delegate(IntPtr h, IntPtr lp) {
            try {
                StringBuilder c = new StringBuilder(256);
                GetClassName(h, c, 256);
                StringBuilder w = new StringBuilder(256);
                GetWindowText(h, w, 256);
                int pid = 0;
                GetWindowThreadProcessId(h, ref pid);
                int vis = IsWindowVisible(h) ? 1 : 0;
                string cap = w.ToString().Replace(";", "_").Replace("\r", " ").Replace("\n", " ");
                l.Add(h.ToInt64() + ";" + c.ToString() + ";" + pid + ";" + vis + ";" + cap);
            } catch { }
            return true;
        };
        EnumWindows(cb, IntPtr.Zero);
        return l.ToArray();
    }
    // v7.26: WM_CLOSE every top-level window owned by a pid. When a
    // cross-token child lands in its OWN console (seclogon cannot
    // inherit one), the brush TerminateProcess's it - but a TI
    // process outranks the brush and the kill can be denied. Closing
    // the windows it owns takes the whole stray down regardless of
    // privilege; the console drags its clients with it.
    public static int ClosePidWindows(int pid) {
        int n = 0;
        EnumWindowsProc cb2 = delegate(IntPtr h, IntPtr lp) {
            try {
                int wp = 0;
                GetWindowThreadProcessId(h, ref wp);
                if (wp == pid) { PostMessage(h, 0x10, IntPtr.Zero, IntPtr.Zero); n++; }
            } catch { }
            return true;
        };
        EnumWindows(cb2, IntPtr.Zero);
        return n;
    }
    // v7.21: conhost's own dark recipe, reordered. WM_THEMECHANGED goes
    // FIRST - v7.20 sent it after the paint, so the host's own theme
    // re-application ran last and could re-lighten what had just been
    // darkened. Waking the host first means our attributes always land
    // after the host's own opinion. New: DWMWA_BORDER_COLOR (34) - the
    // explicit dark border (Win11+; E_INVALIDARG on Win10 is harmless).
    public static string PaintDark(IntPtr h) {
        if (h == IntPtr.Zero) return "hwnd=0";
        IntPtr res;
        IntPtr tm = SendMessageTimeout(h, 0x1A, UIntPtr.Zero, IntPtr.Zero, 2, 1000, out res);
        int hrTheme = SetWindowTheme(h, "DarkMode_Explorer", null);
        int one = 1;
        int hr19 = DwmSetWindowAttribute(h, 19, ref one, 4);
        int hr20 = DwmSetWindowAttribute(h, 20, ref one, 4);
        int cap = 0x00202020;
        int hr35 = DwmSetWindowAttribute(h, 35, ref cap, 4);
        int txt = 0x00F0F0F0;
        int hr36 = DwmSetWindowAttribute(h, 36, ref txt, 4);
        int bd = 0x00202020;
        int hr34 = DwmSetWindowAttribute(h, 34, ref bd, 4);
        bool nudged = SetWindowPos(h, IntPtr.Zero, 0, 0, 0, 0, 0x0037);
        int rone = 0;
        DwmGetWindowAttribute(h, 20, ref rone, 4);
        return string.Format("theme=0x{0:X8} hr19=0x{1:X8} hr20=0x{2:X8} hr34=0x{3:X8} hr35=0x{4:X8} hr36=0x{5:X8} nudge={6} wmthm={7} gb20={8}",
            unchecked((uint)hrTheme), unchecked((uint)hr19), unchecked((uint)hr20), unchecked((uint)hr34), unchecked((uint)hr35), unchecked((uint)hr36), nudged, tm != IntPtr.Zero, rone);
    }
    // v7.21: read-only probe used one second AFTER the paint - if attr 20
    // flipped back to 0, the host re-applied its own light recipe after us.
    public static string CheckDark(IntPtr h) {
        if (h == IntPtr.Zero) return "hwnd=0";
        int a20 = 0;
        int hr = DwmGetWindowAttribute(h, 20, ref a20, 4);
        return string.Format("g20={0}/hr=0x{1:X8}", a20, unchecked((uint)hr));
    }
    // v7.19 kept (palette through a CONOUT$ handle opened directly -
    // immune to a redirected or piped stdout).
    public static string PalConoutGet() {
        const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
        IntPtr h = CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return "open=False/e" + Marshal.GetLastWin32Error();
        try {
            CONSOLE_SCREEN_BUFFER_INFOEX info = new CONSOLE_SCREEN_BUFFER_INFOEX();
            info.cbSize = (uint)Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFOEX));
            if (!GetConsoleScreenBufferInfoEx(h, ref info)) return "get=False/e" + Marshal.GetLastWin32Error();
            return "get=True attr=0x" + info.wAttributes.ToString("X") + " ct00=0x" + info.ct00.ToString("X8");
        } finally { CloseHandle(h); }
    }
    public static string PalConout() {
        const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
        IntPtr h = CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) return "open=False/e" + Marshal.GetLastWin32Error();
        try {
            CONSOLE_SCREEN_BUFFER_INFOEX info = new CONSOLE_SCREEN_BUFFER_INFOEX();
            info.cbSize = (uint)Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFOEX));
            if (!GetConsoleScreenBufferInfoEx(h, ref info)) return "get=False/e" + Marshal.GetLastWin32Error();
            info.ct00 = 0x000C0C0C; info.ct01 = 0x001F0FC5; info.ct02 = 0x000EA113; info.ct03 = 0x00009CC1;
            info.ct04 = 0x00DA3700; info.ct05 = 0x00981788; info.ct06 = 0x00DD963A; info.ct07 = 0x00CCCCCC;
            info.ct08 = 0x00767676; info.ct09 = 0x005648E7; info.ct10 = 0x000CC616; info.ct11 = 0x00A5F1F9;
            info.ct12 = 0x00FF783B; info.ct13 = 0x009E00B4; info.ct14 = 0x00D6D661; info.ct15 = 0x00F2F2F2;
            info.wAttributes = 7;
            if (!SetConsoleScreenBufferInfoEx(h, ref info)) return "set=False/e" + Marshal.GetLastWin32Error();
            SetConsoleTextAttribute(h, 7);
            return "get=True set=True";
        } finally { CloseHandle(h); }
    }
    // v7.21: the std-handle palette route moved INTO the DLL so the error
    // codes are captured immediately after each P/Invoke - the PS-side
    // capture sat behind PS-internal Win32 calls and reported stale junk
    // (the eternal "e203" on calls that had actually succeeded).
    public static string PalStdGet() {
        IntPtr h = GetStdHandle(-11);
        if (h == IntPtr.Zero || h == (IntPtr)(-1)) return "get=False/e" + Marshal.GetLastWin32Error();
        CONSOLE_SCREEN_BUFFER_INFOEX info = new CONSOLE_SCREEN_BUFFER_INFOEX();
        info.cbSize = (uint)Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFOEX));
        if (!GetConsoleScreenBufferInfoEx(h, ref info)) return "get=False/e" + Marshal.GetLastWin32Error();
        return "get=True/e" + Marshal.GetLastWin32Error() + " attr=0x" + info.wAttributes.ToString("X") + " ct00=0x" + info.ct00.ToString("X8");
    }
    public static string PalStd() {
        IntPtr h = GetStdHandle(-11);
        if (h == IntPtr.Zero || h == (IntPtr)(-1)) return "get=False/e" + Marshal.GetLastWin32Error();
        CONSOLE_SCREEN_BUFFER_INFOEX info = new CONSOLE_SCREEN_BUFFER_INFOEX();
        info.cbSize = (uint)Marshal.SizeOf(typeof(CONSOLE_SCREEN_BUFFER_INFOEX));
        if (!GetConsoleScreenBufferInfoEx(h, ref info)) return "get=False/e" + Marshal.GetLastWin32Error();
        int e1 = Marshal.GetLastWin32Error();
        info.ct00 = 0x000C0C0C; info.ct01 = 0x001F0FC5; info.ct02 = 0x000EA113; info.ct03 = 0x00009CC1;
        info.ct04 = 0x00DA3700; info.ct05 = 0x00981788; info.ct06 = 0x00DD963A; info.ct07 = 0x00CCCCCC;
        info.ct08 = 0x00767676; info.ct09 = 0x005648E7; info.ct10 = 0x000CC616; info.ct11 = 0x00A5F1F9;
        info.ct12 = 0x00FF783B; info.ct13 = 0x009E00B4; info.ct14 = 0x00D6D661; info.ct15 = 0x00F2F2F2;
        info.wAttributes = 7;
        if (!SetConsoleScreenBufferInfoEx(h, ref info)) return "get=True/e" + e1 + " set=False/e" + Marshal.GetLastWin32Error();
        int e2 = Marshal.GetLastWin32Error();
        SetConsoleTextAttribute(h, 7);
        return "get=True/e" + e1 + " set=True/e" + e2;
    }
    // v7.19 kept: spawn the wrapper console as the CALLING user (your elevated
    // token). Its conhost reads YOUR dark theme: dark caption BY CONSTRUCTION.
    public static string SpawnWrapperUser(string commandLine, string title) {
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
        // v7.34: lpDesktop UNSET = the wrapper console inherits the CALLER'S
        // desktop. On a normal desktop that is winsta0\default - the exact
        // value hardcoded here since v7.19 (zero behavior change). At the
        // logon screen (the sethc trapdoor shell: SYSTEM on the secure
        // Winlogon desktop) the wrapper is born ON the visible desktop
        // instead of an invisible winsta0\default - v7.33 spawned blind
        // there and the watchdog timed out into an equally blind direct
        // spawn. The inner drops (SpawnInherit / SpawnInheritAsUser) KEEP
        // winsta0\default below: their clients ATTACH to this already
        // visible console without creating a window, and winsta0\default
        // is the desktop their granted ACE lives on - a foreign-SID ACE on
        // the secure desktop itself: never.
        si.dwFlags = 0x08;
        si.dwXCountChars = 120;
        si.dwYCountChars = 30;
        if (title != null && title.Length > 0) si.lpTitle = title;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        if (!CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, 0x10u, IntPtr.Zero, null, ref si, out pi))
            return "F:spawn:" + Marshal.GetLastWin32Error();
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return "OK";
    }
    // v7.19 kept (seclogon retry): drop the foreign-token cmd into THIS
    // console (no CREATE_NEW_CONSOLE -> console inheritance). Verifies via
    // GetConsoleProcessList that the child really attached; if it did not,
    // kills it and returns F:inherit so the caller falls back. v7.27: the
    // test child spawns hidden and the proof can never throw past the kill.
    // v7.22: returns right after the attach proof (no wait) - the child
    // owns the console; waiting would pin the brush to the window as a
    // second client and keep the powershell identity on it.
    public static string SpawnInherit(IntPtr hToken, string commandLine, IntPtr env) {
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
        si.lpDesktop = "winsta0\\default";
        // v7.27: the attach-TEST child spawns HIDDEN. If it inherits THIS
        // console the flag is inert (conhost applies wShowWindow only when
        // it CREATES a console window); if it lands in its own console
        // (cross-token inheritance failure) that window is born invisible -
        // the test-then-kill limbo can never flash on the desktop again.
        si.dwFlags = 0x01;      // STARTF_USESHOWWINDOW
        si.wShowWindow = 0;     // SW_HIDE
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        uint cf = env == IntPtr.Zero ? 0u : 0x400u;
        if (!CreateProcessWithTokenW(hToken, 0, null, commandLine, cf, env, null, ref si, out pi))
            return "F:spawn:" + Marshal.GetLastWin32Error();
        CloseHandle(pi.hThread);
        bool attached = false;
        uint[] ids = new uint[64];
        // v7.27: the proof itself is wrapped - a sick proof degrades to
        // 'not attached' (kill + fallback), it can never escape and orphan
        // a child the way the v7.19-v7.26 ghost-API call did.
        try {
            for (int i = 0; i < 15 && !attached; i++) {
                Thread.Sleep(200);
                // GetConsoleProcessList: 0 = nothing attached yet; a return
                // above the array size means buffer-too-small, nothing was
                // copied - skip that poll, never index past the array.
                uint n = GetConsoleProcessList(ids, 64);
                if (n == 0 || n > 64) continue;
                for (uint j = 0; j < n; j++) {
                    if (ids[j] == pi.dwProcessId) { attached = true; break; }
                }
            }
        } catch { attached = false; }
        if (!attached) {
            TerminateProcess(pi.hProcess, 1);
            ClosePidWindows((int)pi.dwProcessId);  // v7.26: kill the stray console even when Terminate is denied
            CloseHandle(pi.hProcess);
            return "F:inherit";
        }
        // v7.22: no infinite wait - the child owns the console now. The
        // brush exits so the window becomes purely the TI cmd (cmd icon,
        // cmd title); the console survives because the child holds a
        // console handle from the attach itself.
        CloseHandle(pi.hProcess);
        return "OK";
    }
    // v7.21 PRIMARY inner drop: in-process CreateProcessAsUserW while
    // impersonating winlogon (SeTcb / SeAssignPrimaryToken /
    // SeIncreaseQuota), NO CREATE_NEW_CONSOLE - the child inherits THIS
    // console through the ordinary CreateProcess path. seclogon's
    // CreateProcessWithTokenW never proved it can inherit a console
    // cross-token; this route does not depend on it. Same live
    // GetConsoleProcessList attach proof + kill-on-F:inherit as SpawnInherit
    // (v7.27: hidden test child, proof wrapped, real API name).
    // v7.22: returns right after the attach proof - see SpawnInherit.
    public static string SpawnInheritAsUser(IntPtr hToken, int wlPid, string commandLine, IntPtr env) {
        IntPtr tokSelf;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
            return "F:opentok(self):" + Marshal.GetLastWin32Error();
        EnablePriv(tokSelf, 20);  // SeDebugPrivilege, best effort
        CloseHandle(tokSelf);
        IntPtr hWl = OpenProcess(0x0400, false, wlPid);
        if (hWl == IntPtr.Zero) return "F:open(winlogon):" + Marshal.GetLastWin32Error();
        IntPtr tokWl;
        if (!OpenProcessToken(hWl, 0x000E, out tokWl)) { CloseHandle(hWl); return "F:opentok(winlogon):" + Marshal.GetLastWin32Error(); }
        IntPtr wear;
        if (!DuplicateTokenEx(tokWl, 0x02000000, IntPtr.Zero, 2, 2, out wear)) {
            CloseHandle(tokWl); CloseHandle(hWl);
            return "F:dup(wear):" + Marshal.GetLastWin32Error();
        }
        CloseHandle(tokWl); CloseHandle(hWl);
        string miss = "";
        if (!EnablePrivChecked(wear, 7)) miss += "SeTcb ";
        if (!EnablePrivChecked(wear, 3)) miss += "SeAssignPrimaryToken ";
        if (!EnablePrivChecked(wear, 5)) miss += "SeIncreaseQuota ";
        if (miss.Length > 0) { CloseHandle(wear); return "F:privs(" + miss.Trim() + " absent from winlogon token)"; }
        if (!ImpersonateLoggedOnUser(wear)) { CloseHandle(wear); return "F:impersonate:" + Marshal.GetLastWin32Error(); }
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try {
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = "winsta0\\default";
            // v7.27: hidden test child - see SpawnInherit.
            si.dwFlags = 0x01;      // STARTF_USESHOWWINDOW
            si.wShowWindow = 0;     // SW_HIDE
            uint cf = env == IntPtr.Zero ? 0u : 0x400u;
            bool ok = CreateProcessAsUserW(hToken, null, commandLine, IntPtr.Zero, IntPtr.Zero, false, cf, env, null, ref si, out pi);
            if (!ok) return "F:spawnasuser:" + Marshal.GetLastWin32Error();
        } finally {
            RevertToSelf();
            CloseHandle(wear);
        }
        CloseHandle(pi.hThread);
        bool attached = false;
        uint[] ids = new uint[64];
        // v7.27: the proof itself is wrapped - a sick proof degrades to
        // 'not attached' (kill + fallback), it can never escape and orphan
        // a child the way the v7.19-v7.26 ghost-API call did.
        try {
            for (int i = 0; i < 15 && !attached; i++) {
                Thread.Sleep(200);
                // GetConsoleProcessList: 0 = nothing attached yet; a return
                // above the array size means buffer-too-small, nothing was
                // copied - skip that poll, never index past the array.
                uint n = GetConsoleProcessList(ids, 64);
                if (n == 0 || n > 64) continue;
                for (uint j = 0; j < n; j++) {
                    if (ids[j] == pi.dwProcessId) { attached = true; break; }
                }
            }
        } catch { attached = false; }
        if (!attached) {
            TerminateProcess(pi.hProcess, 1);
            ClosePidWindows((int)pi.dwProcessId);  // v7.26: kill the stray console even when Terminate is denied
            CloseHandle(pi.hProcess);
            return "F:inherit";
        }
        // v7.22: no infinite wait - the child owns the console now. The
        // brush exits so the window becomes purely the TI cmd (cmd icon,
        // cmd title); the console survives because the child holds a
        // console handle from the attach itself.
        CloseHandle(pi.hProcess);
        return "OK";
    }
    // Enable a privilege on a token handle; returns 1300 when the token
    // does not hold it (ERROR_NOT_ALL_ASSIGNED), else 0.
    static int EnablePriv(IntPtr tok, uint luid) {
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.Count = 1;
        tp.Privilege.Luid.LowPart = luid;
        tp.Privilege.Luid.HighPart = 0;
        tp.Privilege.Attributes = 2;  // SE_PRIVILEGE_ENABLED
        AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int e = Marshal.GetLastWin32Error();
        return e == 1300 ? 1300 : 0;
    }
    // Enable a privilege and VERIFY it was actually held by the token.
    static bool EnablePrivChecked(IntPtr tok, uint luid) {
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.Count = 1;
        tp.Privilege.Luid.LowPart = luid;
        tp.Privilege.Luid.HighPart = 0;
        tp.Privilege.Attributes = 2;  // SE_PRIVILEGE_ENABLED
        bool ok = AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return ok && Marshal.GetLastWin32Error() != 1300;
    }
}
'@
$out = "$env:windir\System32\su-polish.dll"
try {
    if (Test-Path $out) { Remove-Item $out -Force -ErrorAction Stop }
} catch {
    try { Move-Item $out "$out.old" -Force -ErrorAction Stop; Write-Host '[i] old DLL was locked (loaded by this console) - renamed to su-polish.dll.old' }
    catch { Write-Host '[!] the DLL is locked by THIS console. Open a FRESH elevated PowerShell and run this script there.'; return }
}
try { Add-Type -TypeDefinition $cs -OutputAssembly $out -OutputType Library -ErrorAction Stop; Write-Host "[+] rebuilt $out" }
catch { Write-Host "[!] build failed: $($_.Exception.Message)"; return }

# ---- 1b) verify ----
$asm = [Reflection.Assembly]::LoadFrom($out)
$t = $asm.GetType('Polish')
$need = 'GetConsoleWindow','GetClassName','GetWindowThreadProcessId','IsWindowVisible','GetStdHandle','GetConsoleScreenBufferInfoEx','SetConsoleScreenBufferInfoEx','SetConsoleTextAttribute','SetWindowPos','SendMessageTimeout','PostMessage','SetWindowTheme','DwmSetWindowAttribute','DwmGetWindowAttribute','ListWindows','PaintDark','CheckDark','GetWindowText','PalConout','PalConoutGet','PalStd','PalStdGet','SpawnWrapperUser','SpawnInherit','SpawnInheritAsUser','ClosePidWindows','Ver'
$missing = 0
foreach ($n in $need) { if ($t.GetMethod($n)) { Write-Host "    OK      $n" } else { Write-Host "    MISSING $n" -ForegroundColor Red; $missing++ } }
$exT = $t.GetNestedType('CONSOLE_SCREEN_BUFFER_INFOEX')
$sz = 0
if ($exT) { $sz = [Runtime.InteropServices.Marshal]::SizeOf([type]$exT); Write-Host "    OK      struct size $sz (native 96)" } else { Write-Host '    MISSING struct' -ForegroundColor Red; $missing++ }
if ($missing -gt 0 -or $sz -ne 96) { Write-Host '[!] DLL incomplete - do NOT test su yet'; return }
if ([Polish]::Ver() -ne 'su-polish 7.34') { Write-Host '[!] the DLL reports the wrong version - do NOT test su yet'; return }
# ---- 1c) self-test right here ----
if ($env:WT_SESSION) { Write-Host '[i] this console is Windows Terminal: conout get=False/e87 here is EXPECTED (pty)' } else { Write-Host '[i] this console is classic conhost: get=True expected everywhere' }
try {
    $wins = [Polish]::ListWindows()
    Write-Host ("[+] self-test: std {0} | stdset {1} | conout {2} | frame {3} | windows={4} | ver={5}" -f [Polish]::PalStdGet(), [Polish]::PalStd(), [Polish]::PalConoutGet(), [Polish]::CheckDark([Polish]::GetConsoleWindow()), $wins.Count, [Polish]::Ver())
    Write-Host '[i] the dark Campbell palette is now on THIS test console - harmless, it closes with the window'
} catch { Write-Host ('[!] self-test failed: ' + $_.Exception.Message) }

# ---- 2) patch su-sys.ps1: the v7.34 logon gate + desktop inheritance ----
$txt = [IO.File]::ReadAllText($suSys)
$sysChanged = $false

# --- 2a) the logon gate (SYSTEM is not in BUILTIN\Administrators) ---
$gateMark = '# --- admin check (v7.34 logon gate) ---'
if ($txt.Contains($gateMark)) {
    Write-Host '[i] 2a logon gate: v7.34 already on disk'
} else {
    $oldGate = Su-Join $nl @(
        '# --- admin check ---',
        '$id = [Security.Principal.WindowsIdentity]::GetCurrent()',
        '$pr = New-Object Security.Principal.WindowsPrincipal($id)',
        'if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {',
        '    Write-Host ''[!] su-sys.ps1 must be launched elevated'' -ForegroundColor Red',
        '    exit 1',
        '}'
    )
    if (-not $txt.Contains($oldGate)) {
        Write-Host '[!] 2a: the v7.13 admin gate is not on disk in the expected shape - refusing to patch blind'; return
    }
    $newGate = Su-Join $nl @(
        '# --- admin check (v7.34 logon gate) ---',
        '# v7.34 BELT, not a fix. Field round 35 proved the old gate already',
        '# passes for SYSTEM (a SYSTEM token carries BUILTIN\Administrators;',
        '# su ran fine from a SYSTEM cmd on the interactive desktop). The',
        '# SYSTEM-SID acceptance below is insurance for a stripped-token',
        '# context only; the Administrators check is unchanged.',
        '$id = [Security.Principal.WindowsIdentity]::GetCurrent()',
        '$pr = New-Object Security.Principal.WindowsPrincipal($id)',
        '$isuSystemToken = $false',
        'try { $isuSystemToken = ($id.User.Value -eq ''S-1-5-18'') } catch {}',
        'if (-not ($isuSystemToken -or $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {',
        '    Write-Host ''[!] su-sys.ps1 must be launched elevated'' -ForegroundColor Red',
        '    exit 1',
        '}'
    )
    $txt = $txt.Replace($oldGate, $newGate)
    $sysChanged = $true
    Write-Host '[+] 2a logon gate (belt): SYSTEM SID accepted; Administrators unchanged'
}

# --- 2b) desktop inheritance in the two Su.T direct spawns ---
$deskMark = 'v7.34: lpDesktop UNSET'
$deskOld = 'si.lpDesktop = "winsta0\\default";'
$deskHere = ([regex]::Matches($txt, [regex]::Escape($deskOld))).Count
$deskDone = ([regex]::Matches($txt, [regex]::Escape($deskMark))).Count
if ($deskDone -ge 2) {
    Write-Host '[i] 2b desktop inheritance: v7.34 already on disk'
} elseif ($deskHere -ne 2) {
    Write-Host ('[!] 2b: expected 2 desktop sites in the Su.T C#, found {0} - refusing to patch blind' -f $deskHere); return
} else {
    $old12 = $nl + '            si.lpDesktop = "winsta0\\default";'
    $old16 = $nl + '                si.lpDesktop = "winsta0\\default";'
    $new12 = $nl + (Su-Join $nl @(
        '            // v7.34: lpDesktop UNSET = the child inherits the caller''s desktop -',
        '            // identical to the old winsta0\default on a normal desktop; at the',
        '            // logon screen the child is born on the VISIBLE secure desktop.'
    ))
    $new16 = $nl + (Su-Join $nl @(
        '                // v7.34: lpDesktop UNSET = the child inherits the caller''s desktop -',
        '                // identical to the old winsta0\default on a normal desktop; at the',
        '                // logon screen the child is born on the VISIBLE secure desktop.'
    ))
    if ((([regex]::Matches($txt, [regex]::Escape($old12))).Count -ne 1) -or (([regex]::Matches($txt, [regex]::Escape($old16))).Count -ne 1)) {
        Write-Host '[!] 2b: the two desktop sites do not have the expected shapes - refusing to patch blind'; return
    }
    $txt = $txt.Replace($old12, $new12).Replace($old16, $new16)
    $sysChanged = $true
    Write-Host '[+] 2b desktop inheritance: SpawnWithToken + SpawnAsUser inherit the caller''s desktop now'
}

# --- 2c) v7.33 re-run debris heal (cosmetic, non-fatal) ---
$vLine = '    $script:SuRouteFacts += "verdict=$verdict"'
$triple = Su-Join $nl @($vLine, $vLine, $vLine)
if ($txt.Contains($triple)) { $txt = $txt.Replace($triple, $vLine); $sysChanged = $true; Write-Host '[+] 2c debris: tripled verdict route-facts line -> single' }
else { Write-Host '[i] 2c debris: triple verdict line not on this disk - skipped' }
$cLine = '# ---- v7.33 user wrapper machinery (inserted by su-fix-v7.33.ps1) ----'
$double = Su-Join $nl @($cLine, $cLine)
if ($txt.Contains($double)) { $txt = $txt.Replace($double, $cLine); $sysChanged = $true; Write-Host '[+] 2c debris: doubled block comment -> single' }
else { Write-Host '[i] 2c debris: doubled comment not on this disk - skipped' }

# --- 2d) the guarded write + on-disk verify (the v7.33 lesson: a call
#     without its function can never ship; a patch without its probe
#     can never look green) ---
if ($sysChanged) {
    Copy-Item $suSys "$suSys.bak-v7.34" -Force
    [IO.File]::WriteAllText($suSys, $txt, (New-Object System.Text.UTF8Encoding($true)))
    $chk = [IO.File]::ReadAllText($suSys)
    $bad = @()
    if (-not $chk.Contains('# --- admin check (v7.34 logon gate) ---')) { $bad += 'gate-marker' }
    if ((([regex]::Matches($chk, [regex]::Escape('v7.34: lpDesktop UNSET'))).Count) -lt 2) { $bad += 'desktop-markers' }
    if ((([regex]::Matches($chk, [regex]::Escape('si.lpDesktop = "winsta0\\default";'))).Count) -ne 0) { $bad += 'leftover-desktop-lines' }
    foreach ($fn in @('function Invoke-SuSpawn(', 'function Invoke-SuSpawnV719(', 'function Invoke-SuSpawnUserV733(')) {
        if (-not $chk.Contains($fn)) { $bad += "lost:$fn" }
    }
    if ($bad.Count -gt 0) {
        Copy-Item "$suSys.bak-v7.34" $suSys -Force
        Write-Host ('[!] 2d verify failed ({0}) - su-sys.ps1 RESTORED from su-sys.ps1.bak-v7.34' -f ($bad -join ', ')); return
    }
    Write-Host '[+] 2d su-sys.ps1 patched and VERIFIED on disk (backup: su-sys.ps1.bak-v7.34)'
} else {
    Write-Host '[i] 2d su-sys.ps1: nothing to change - already v7.34'
}

# ---- 3) patch su.bat: the elevation probe must also accept SYSTEM ----
$batTxt = [IO.File]::ReadAllText($suBat)
$batNl = "`r`n"
if (-not $batTxt.Contains("`r`n")) { $batNl = "`n" }
if ($batTxt -match '(?m)^:su_rootcheck') {
    Write-Host '[i] 3 su.bat: rootcheck already on disk'
} else {
    $netCount = ([regex]::Matches($batTxt, [regex]::Escape('net session >nul 2>&1'))).Count
    if ($netCount -ne 3) {
        Write-Host ('[i] 3 su.bat: expected 3 net-session probes, found {0} - skipped (no harm done)' -f $netCount)
    } else {
        $batTxt = $batTxt.Replace('net session >nul 2>&1', 'call :su_rootcheck')
        $sub = Su-Join $batNl @(
            ':: ==================================================================',
            '::  v7.34 :su_rootcheck - the elevation probe that also accepts SYSTEM',
            '::  (BELT: SYSTEM normally passes net session already - field round',
            '::  35 proved su works from a SYSTEM shell; the SID check is',
            '::  insurance for a context where the probe fails while the',
            '::  caller is still root).',
            ':: ==================================================================',
            ':su_rootcheck',
            'net session >nul 2>&1',
            'if %errorlevel% equ 0 exit /b 0',
            'whoami /user 2>nul | find "S-1-5-18" >nul 2>&1',
            'if %errorlevel% equ 0 exit /b 0',
            'exit /b 1'
        )
        $batTxt = $batTxt.TrimEnd([char]13, [char]10) + $batNl + $batNl + $sub + $batNl
        Copy-Item $suBat "$suBat.bak-v7.34" -Force
        [IO.File]::WriteAllText($suBat, $batTxt, (New-Object System.Text.UTF8Encoding($false)))
        $chkB = [IO.File]::ReadAllText($suBat)
        if ((([regex]::Matches($chkB, [regex]::Escape('call :su_rootcheck'))).Count -ne 3) -or ($chkB -notmatch '(?m)^:su_rootcheck')) {
            Copy-Item "$suBat.bak-v7.34" $suBat -Force
            Write-Host '[!] 3 su.bat verify failed - RESTORED from su.bat.bak-v7.34'; return
        }
        Write-Host '[+] 3 su.bat: all three probes routed through :su_rootcheck (backup: su.bat.bak-v7.34)'
    }
}

# ---- 4) relay: verify / heal (content unchanged by v7.34) ----
$relayNeeded = $true
if (Test-Path $relayP) {
    $rc = [IO.File]::ReadAllText($relayP)
    if ($rc.Contains('[D] self-polish v7.33: alive')) { $relayNeeded = $false }
}
if ($relayNeeded) {
    $relay = @'
$polishLog = '$POLISH_LOG$'
$suTitle = '$SU_TITLE$'
$ErrorActionPreference = 'SilentlyContinue'
# v7.33: -ErrorAction SilentlyContinue - the v7.29 field round showed the
# child's final write fail (parent deleted the pair mid-relay) as RED
# text splashed over the brand-new shell. Cosmetic paths never spray red.
function Su-Report([string]$m) { try { Set-Content -LiteralPath $polishLog -Value $m -Encoding Unicode -ErrorAction SilentlyContinue } catch {}; $m }
Su-Report '[D] self-polish v7.33: alive'
try { [Console]::Title = $suTitle } catch {}
try {
    $dll = "$env:SystemRoot\System32\su-polish.dll"
    if (-not (Test-Path $dll)) {
        Su-Report '[D] self-polish v7.33: su-polish.dll missing - floor color 07 active'
    } else {
        [Reflection.Assembly]::LoadFrom($dll) | Out-Null
        $mode = if ($env:WT_SESSION) { 'wt' } else { 'classic' }
        $gcw = [Polish]::GetConsoleWindow()
        $cls = ''; $gp = 0; $vis = $false
        if ($gcw -ne [IntPtr]::Zero) {
            $sb = New-Object System.Text.StringBuilder(64)
            $null = [Polish]::GetClassName($gcw, $sb, 64)
            $cls = $sb.ToString()
            $null = [Polish]::GetWindowThreadProcessId($gcw, [ref]$gp)
            $vis = [Polish]::IsWindowVisible($gcw)
        }
        $gpName = ''
        if ($gp -gt 0) { try { $gpName = (Get-Process -Id $gp -ErrorAction SilentlyContinue).ProcessName } catch {} }
        # v7.22: if this console's frame is already dark (the wrapper
        # route: conhost-under-you painted it at creation), touch NOTHING -
        # re-painting a healthy conhost frame is the suspected icon
        # corruptor. Only a light frame (direct-spawn fallback) gets the
        # best-effort paint recipe.
        $dark0 = $false
        try { $dark0 = ([Polish]::CheckDark($gcw) -like 'g20=1/*') } catch {}
        if ($dark0) { $proxyPaint = 'skip(frame already dark)' }
        else { $proxyPaint = [Polish]::PaintDark($gcw) }
        $palStd = [Polish]::PalStd()
        $conout = [Polish]::PalConout()
        $cands = @()
        foreach ($w in [Polish]::ListWindows()) {
            $p = $w -split ';', 5
            if ($p.Count -lt 5) { continue }
            if ($p[3] -ne '1') { continue }
            if (($p[1] -notlike '*Console*') -and ($p[1] -notlike '*CASCADIA*') -and ($p[4] -notlike "*$suTitle*")) { continue }
            $wpid = 0
            [void][int]::TryParse($p[2], [ref]$wpid)
            if ($wpid -eq $PID) { continue }
            $cands += ,@($p)
        }
        $titled = @($cands | Where-Object { $_[4] -like "*$suTitle*" })
        if ($titled.Count -eq 0) { $titled = @($cands) }
        $paints = @()
        if (-not $dark0) {
            foreach ($tt in $titled) {
                $r = [Polish]::PaintDark([IntPtr][int64]$tt[0])
                $cap = $tt[4]; if ($cap.Length -gt 34) { $cap = $cap.Substring(0, 34) }
                $paints += ('0x{0:X} {1} pid={2} [{3}] {4}' -f [int64]$tt[0], $tt[1], $tt[2], $cap, $r)
            }
        } else {
            $paints += 'skip: frame already dark - wrapper route, no repaint (icon-safe)'
        }
        # v7.21 stability probe: one second after the last paint, is attr 20
        # still dark? A flip to 0 means the host re-applied its own light
        # recipe after us - the frozen-frame/foreign-host behavior.
        Start-Sleep -Milliseconds 1000
        $stab = [Polish]::CheckDark($gcw)
        $candStr = ($cands | ForEach-Object { $c2 = $_[4]; if ($c2.Length -gt 24) { $c2 = $c2.Substring(0, 24) }; '{0}/pid{1}/[{2}]' -f $_[1], $_[2], $c2 }) -join ' | '
        if (-not $candStr) { $candStr = 'NONE' }
        $paintStr = $paints -join ' || '
        if (-not $paintStr) { $paintStr = 'none' }
        $hkcuT = 'x'; $defT = 'x'; $sysT = 'x'; $tiT = 'x'
        try { $hkcuT = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme } catch {}
        try { $defT = (Get-ItemProperty 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme } catch {}
        try { $sysT = (Get-ItemProperty 'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme } catch {}
        try { $tiT = (Get-ItemProperty 'Registry::HKEY_USERS\S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme } catch {}
        $ds = 'none'
        try { $d = Get-ItemProperty 'HKCU:\Console\%%Startup' -ErrorAction Stop; $ds = 'dc={0} dt={1}' -f $d.DelegationConsole, $d.DelegationTerminal } catch {}
        Su-Report ('[D] self-polish v7.33: mode={0} gcw=0x{1:X} cls={2} vis={3} owner={4}({5}) | pal std {6} | conout {7} | HKCU={8} DEF={9} SYS={10} TI={11} | deleg {12} | cands: {13} | painted: {14} | proxy: {15} | stab: {16}' -f $mode, $gcw.ToInt64(), $cls, $vis, $gpName, $gp, $palStd, $conout, $hkcuT, $defT, $sysT, $tiT, $ds, $candStr, $paintStr, $proxyPaint, $stab)
        Write-Host ("[D] self-polish v7.33: owner={0}({1}) cls={2} vis={3} - full line relayed home" -f $gpName, $gp, $cls, $vis)
    }
} catch { Su-Report ('[D] self-polish v7.33: ' + $_.Exception.Message) }
'@
    try { [IO.File]::WriteAllText($relayP, $relay, (New-Object System.Text.UTF8Encoding($true))); Write-Host "[+] 4 relay: $relayP healed" }
    catch { Write-Host "[!] could not write $relayP : $($_.Exception.Message)" }
} else {
    Write-Host '[i] 4 relay: present and v7.33-shaped - untouched'
}

# ---- 5) self-install over su-polish-build.ps1 (the old v7.33 self-copy
#      would REBUILD the DLL without the v7.34 wrapper fix - the
#      canonical rebuild path must stay current) ----
if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
    if ([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($buildP)) {
        Copy-Item $PSCommandPath $buildP -Force
        Write-Host "[+] 5 self-installed as $buildP (re-run it any time to rebuild + re-verify)"
    } else {
        Write-Host '[i] 5 already running as su-polish-build.ps1'
    }
}

# ---- 6) final on-disk verification ----
$fin = [IO.File]::ReadAllText($suSys)
$fbat = [IO.File]::ReadAllText($suBat)
$okGate = $fin.Contains('# --- admin check (v7.34 logon gate) ---')
$okDesk = ((([regex]::Matches($fin, [regex]::Escape('v7.34: lpDesktop UNSET'))).Count -ge 2) -and (([regex]::Matches($fin, [regex]::Escape('si.lpDesktop = "winsta0\\default";'))).Count -eq 0))
$okFns = ($fin.Contains('function Invoke-SuSpawn(')) -and ($fin.Contains('function Invoke-SuSpawnV719(')) -and ($fin.Contains('function Invoke-SuSpawnUserV733('))
$okBat = ((([regex]::Matches($fbat, [regex]::Escape('call :su_rootcheck'))).Count -eq 3) -and ($fbat -match '(?m)^:su_rootcheck'))
$okDll = (Test-Path "$env:windir\System32\su-polish.dll") -and ([Polish]::Ver() -eq 'su-polish 7.34')
if ($okGate -and $okDesk -and $okFns -and $okBat -and $okDll) {
    Write-Host ''
    Write-Host '[+] VERIFIED ON DISK: logon-gate (belt), desktop-inherit x2 (Su.T), wrapper-inherit (DLL), rootcheck x3 (su.bat, belt), relay ok + DLL su-polish 7.34' -ForegroundColor Green
    Write-Host '[+] FIELD ASKS ON DISK: su ti / su <user> / su sys from the sethc shell - every window born on the SECURE desktop' -ForegroundColor Green
} else {
    Write-Host ''
    Write-Host ('[!] final verify: gate={0} desk={1} fns={2} bat={3} dll={4} - see the section messages above' -f $okGate, $okDesk, $okFns, $okBat, $okDll)
}
Write-Host ''
Write-Host 'TEST ORDER:'
Write-Host '  0) zero-install pre-test, BEFORE this fixer: Win+L, Shift x5, and in the'
Write-Host '     trapdoor cmd run:  start cmd'
Write-Host '     -> a second cmd opens right ON the login screen = desktop inheritance'
Write-Host '        proven live on this machine = the v7.34 mechanism itself.'
Write-Host '     -> bonus forensic: after an old v7.33 su run from the trapdoor shell,'
Write-Host '        log back in - the orphan su window is sitting on your desktop.'
Write-Host '  1) normal elevated desktop FIRST (regression check): su ti - must look'
Write-Host '     and behave exactly like v7.33 (same one dark window, same whoami).'
Write-Host '  2) Win+L -> Shift x5 -> in the trapdoor cmd:'
Write-Host '       su ti          whoami must print nt service\trustedinstaller - window ON the login screen'
Write-Host '       su <your-user> whoami must print the user (S4U re-mint inside the wrapper)'
Write-Host '       su sys         a fresh SYSTEM window on the login screen'
Write-Host '  3) a window never appears + a [D] line shows: send that exact line back -'
Write-Host '     WRAPPER-INHERIT-FAILED names the failing call (the one unproven link:'
Write-Host '     cross-desktop attach); 0xc0000142 / F:spawn on a direct spawn at the'
Write-Host '     logon screen is the honest no-ACE-by-design failure of a fallback.'

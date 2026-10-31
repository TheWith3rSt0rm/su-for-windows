# su-sys.ps1 - passwordless user switcher for Windows (production, v7.13)
#
# Invoked by su.bat:
#   powershell -NoProfile -ExecutionPolicy Bypass -File su-sys.ps1 -Account User -TargetUser "<user>"
#   powershell -NoProfile -ExecutionPolicy Bypass -File su-sys.ps1 -Account System
#   powershell -NoProfile -ExecutionPolicy Bypass -File su-sys.ps1 -Account TrustedInstaller
#
# Implementation:
#   User  : passwordless chain (elevation required, NO passwords anywhere):
#     1) target has a live session  -> steal their primary token (explorer.exe
#        preferred), rewrite SessionId to the caller's session -> spawn
#     2) direct LsaLogonUser S4U (MSV1_0_S4U_LOGON) - WORKS on this build:
#        NetBIOS machine name as domain, Flags=0, logon type 3 (Network);
#        field-proven on 26200.9711 (genuine LSASS logon session of the
#        target, real SAM identity). The v4 'known broken' verdict came from
#        runs that only ever tried dom='' and/or Flags=1.
#     3) crafted token via NtCreateToken with the target's SID (works for ANY
#        local account; no network credentials, local identity only)
#     4) S4U scheduled task (LAST resort) -> registration is denied even to
#        SYSTEM on build 26200 ('Acces refuse' on the XML form; the /RU+/NP
#        form prompts for the target's password and fails) - kept only
#        because its diagnostics are now self-explanatory
#   System           : DuplicateTokenEx from winlogon.exe (runs as SYSTEM in
#                      caller's session) -> CreateProcessWithTokenW -> cmd
#   TrustedInstaller : TRUE TI primary token - TokenUser SID
#                      S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
#                      (NT SERVICE\TrustedInstaller) crafted in-process with
#                      NtCreateToken while impersonating a full-privilege
#                      SYSTEM token (lsass.exe - the SeCreateTokenPrivilege
#                      holder), SessionId rewritten to the
#                      caller's session, then spawned:
#                        -> whoami /user prints "nt service\trustedinstaller"
#                        -> takeown /f <file> assigns the COMPUTER account
#                           (WORKGROUP\<machine>$) - normal for a virtual
#                           account (machine-account-backed). To set the
#                           owner literally to TI: icacls <file> /setowner
#                           "NT SERVICE\TrustedInstaller" (works from the TI
#                           shell: SeTakeOwnership + SeRestore are enabled
#                           in the minted token)
#                      Fallback: if a live TI-PRIMARY process exists
#                      (pre-23H2 style), steal and verify its token instead.
#
#                      Why the classic TI tricks are dead on Win 11 24H2:
#                       - TrustedInstaller.exe itself runs as SYSTEM with the
#                         TI service SID enabled as a *GROUP* (the service SID
#                         feature) - stealing its token yields a SYSTEM shell,
#                         NOT a TI shell (whoami shows nt authority\system).
#                       - schtasks /ru "NT SERVICE\TrustedInstaller" silently
#                         runs as SYSTEM since Win 11 23H2.
#                       - SCM rejects new services with TI as ObjectName
#                         (error 22 / 1057), and the TrustedInstaller service
#                         runs as LocalSystem, so even repointing its binPath
#                         mints a SYSTEM+TI-group process.
#                      => Token crafting (NtCreateToken + SeCreateTokenPrivilege)
#                         is the only route to TokenUser == TI on 24H2.
#
# Requirements:
#   - Elevated (Administrator). su.bat handles the UAC re-launch.
#   - Winlogon.exe running in caller's session (always true interactively).
#   - SeDebugPrivilege (admin has it; we enable it on our own token).
#   - For the NtCreateToken paths: a SYSTEM process whose token holds
#     SeCreateTokenPrivilege. lsass.exe is the canonical holder (LSASS
#     itself calls NtCreateToken for every logon); winlogon.exe holds only
#     SeTcbPrivilege on 24H2-class builds (verified on 26200.9711), so the
#     script scans candidates and uses the first token that REALLY has
#     both privileges.
#   - LSA functions are resolved dynamically (sspicli -> secur32 ->
#     advapi32): build 26200's secur32.dll no longer exports LsaClose.
#
# v5 (fixes from the third live run on build 26200.9711):
#   - NtCreateToken 0xC0000005 root cause: v4 passed the raw user PSID where
#     the syscall wants PTOKEN_USER (a SID_AND_ATTRIBUTES wrapper). The kernel
#     read the SID's own first bytes as an embedded PSID pointer and AV'd on
#     EVERY craft attempt, TI and user alike. A proper TOKEN_USER buffer is
#     now built and passed; Owner/PrimaryGroup/DefaultDacl stay raw (v3 fix).
#   - Integrity-label group attributes "fixed": 0x60 -> 0xC020. That was a
#     REGRESSION (0x40 IS SE_GROUP_INTEGRITY_ENABLED; 0xC020 sets undefined
#     bits 0x4000|0x8000) - reverted to 0x60 in v7.
#   - Direct-S4U spawn died with 0xc0000142: that path never granted
#     winsta0\default to the token user, so conhost could not open the
#     desktop during DLL init. New GrantDesktopAsSystem (SYSTEM-impersonated,
#     winsta/desktop opened BY NAME with READ_CONTROL|WRITE_DAC) is now called
#     on every path; every user spawn also loads the profile (best effort)
#     and passes a per-user environment block with lpDesktop set explicitly.
#   - schtasks task-registration failures now capture the SYSTEM child's
#     stderr into a [D] line instead of a bare exit code.
#
# v6 (fixes from the fourth live run on build 26200.9711):
#   - su <user> is WORKING via direct S4U (field-confirmed: window spawned,
#     identity Alexandre\alexa, no 0xc0000142). The user chain is reordered:
#     live-session steal -> direct S4U -> crafted token -> scheduled task.
#   - NtCreateToken moved from 0xC0000005 (v4) to 0xC000000D (v5): the
#     PTOKEN_USER fix landed, the kernel now dies inside parameter
#     VALIDATION. v6 mirrors the two field-proven public implementations
#     (Wh04m1001/NtCreateToken - a TrustedInstaller crafter - and
#     3gstudent/EnableSeCreateTokenPrivilege) plus the ntdoc ZwCreateToken
#     declaration exactly:
#       * Owner / PrimaryGroup / DefaultDacl are the PTOKEN_OWNER /
#         PTOKEN_PRIMARY_GROUP / PTOKEN_DEFAULT_DACL WRAPPER structs (v4-v5
#         passed raw PSID/PSID/PACL; the kernel then read the SID's own
#         first 8 bytes as a pointer - 0x0500000000000501 - and rejected it;
#         v3 had the right form all along, masked by its broken User param)
#       * AuthenticationId = SYSTEM_LUID (0x3E7): must reference an EXISTING
#         logon session (ntdoc: a bogus LUID -> STATUS_NO_SUCH_LOGON_SESSION);
#         the fresh AllocateLocallyUniqueId value used through v5 references
#         no session at all
#       * ExpirationTime = -1; OBJECT_ATTRIBUTES carries a static-tracking
#         SecurityImpersonation QoS; TOKEN_SOURCE.SourceIdentifier = fresh
#         NtAllocateLocallyUniqueId value
#   - the label-group claim below was WRONG: Wh04m1001 actually passes
#     SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED = 0x60, not 0xC020 -
#     v5/v6 both died with 0xC000000D on it (see v7).
#   - schtasks stderr is read with the OEM codepage (no more mojibake in the
#     '[D] schtasks said:' lines on French systems).
#
# v7.1 (fixes from the fifth live run on build 26200.9711 - su ti still
#     0xC000000D with a healthy craft-source):
#   - TWO parameters were invalid, both introduced by the v5/v6 rewrites,
#     which is why v5 and v6 returned the identical NTSTATUS:
#       * integrity-label group attributes 0xC020 - sets the UNDEFINED bits
#         0x4000|0x8000 (SE_GROUP_INTEGRITY_ENABLED 0x40 was confused with
#         the high half of SE_GROUP_LOGON_ID 0xC0000000). Correct: 0x60 =
#         SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED, the exact form
#         Wh04m1001/NtCreateToken passes for S-1-16-16384. The kernel's
#         group-attribute mask check answers undefined bits with
#         STATUS_INVALID_PARAMETER.
#       * SECURITY_QUALITY_OF_SERVICE marshalled as 16 bytes (uint
#         ContextTrackingMode + 4-byte BOOL) where the native struct is 12
#         (DWORD + enum + BYTE + BOOLEAN); the object manager validates
#         QoS.Length == 12 and answers 16 with STATUS_INVALID_PARAMETER.
#   - v7.1 REGRESSION REVERT: the original v7 patch also switched the
#     session rewrite to class 11, claiming the session class was 11 - wrong
#     (winnt.h: TokenRestrictedSids = 11, TokenSessionId = 12,
#     TokenGroupsAndPrivileges = 13; v6's class 12 was correct all along).
#     Class 11 = TokenRestrictedSids would have failed with
#     ERROR_INVALID_PARAMETER right after the FIRST successful craft.
#     Restored to 12 in CreateTokenForSid, StealTokenWithSession and
#     RewriteTokenSession (live-session steal never field-exercised).
#   - the TI identity gate now verifies the kernel TokenUser SID directly
#     (TokenUserIs) instead of trusting the WindowsIdentity display name,
#     which can legitimately print the bare SID or "(unreadable)" for a
#     kernel-minted service-SID token.
#
# v7.2 (field feedback from the sixth live run - su ti WORKING on
#       26200.9711: TI token minted, SID-verified, spawned; whoami /user
#       prints nt service\trustedinstaller):
#   - every spawned shell (user / SYSTEM / TI) now runs ONLY whoami /user;
#     the whoami /priv (and /groups on TI) recap is gone - field feedback:
#     annoying, the identity line is all that matters.
#   - takeown from the TI shell assigns the file owner to the COMPUTER
#     account (WORKGROUP\<machine>$) - observed in the field, and it is
#     takeown semantics, not a token defect: takeown can only assign "the
#     current user" or the Administrators group, and a virtual account
#     (NT SERVICE\*) is machine-account-backed by design (MS docs:
#     services running as virtual accounts use the computer account
#     <domain>\<machine>$ identity). To set the owner LITERALLY to
#     TrustedInstaller, run from the TI shell:
#         icacls <file> /setowner "NT SERVICE\TrustedInstaller"
#     (the minted TI token carries SeTakeOwnershipPrivilege and
#     SeRestorePrivilege enabled - exactly what the arbitrary-owner
#     WriteOwner path requires). Verify with (Get-Acl <file>).Owner or
#     dir /q. Header comment, printed TI guidance, README and su.bat help
#     updated to match the field-tested reality.
#
# v7.3 (field feedback, same session):
#   - window titles cleaned: 'julie' / 'SYSTEM' / 'TrustedInstaller'
#     (was '[user] julie', '[SYSTEM]', '[TRUE TrustedInstaller]').
#   - spawned consoles now open at 120x30 characters via STARTUPINFO
#     STARTF_USECOUNTCHARS (both spawn paths; CREATE_NEW_CONSOLE is already
#     set). Why they looked 'old': the modern console is Windows Terminal,
#     which only attaches through the default-terminal handoff for consoles
#     launched by the SAME user; a shell spawned under a foreign token
#     (user / SYSTEM / TI) always falls back to the classic conhost window,
#     and Windows Terminal itself cannot run under another user's token
#     (microsoft/terminal #3534 / #4217). Nothing su can change - but the
#     window can at least open at a sane size.
#
# v7.4 (field feedback, same session):
#   - the spawned windows still showed the old frame (square corners, light
#     title bar - plus the classic cmd icon). What is and is not fixable: the
#     ICON is cmd.exe's own (conhost takes the console window icon from the
#     client executable - the same icon every conhost console shows; it cannot
#     be swapped from outside without injection). The FRAME can be modernized:
#     both spawn paths now take a title argument that lands in
#     STARTUPINFO.lpTitle (title present from the very first frame) and
#     snapshot the console windows that already exist just before spawning.
#     Right after a successful spawn, the new Polish-Console helper calls
#     PolishConsoleWindow, which finds the NEW console window (class
#     ConsoleWindowClass + title, skipping the pre-spawn snapshot) and asks
#     DWM for the modern frame: DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND
#     (attr 33, value 2) always, DWMWA_USE_IMMERSIVE_DARK_MODE (attr 20) when
#     the caller's app theme is dark. DWM applies these attributes per
#     top-level window regardless of which process calls the API, so this
#     works even though the window belongs to conhost under the foreign
#     token. Best effort, cosmetic only - failure prints one [D] line and the
#     default conhost frame stays.
#
# v7.5 (field feedback from the seventh live run - the v7.4 polish never
#       attached: '[D] window polish: skip: no new console window titled
#       TrustedInstaller within 4000 ms', while the window itself was up and
#       visible the whole time):
#   - root cause: the matcher required the caption to EQUAL the title
#     exactly. The live caption never is the bare title: the spawn runs
#     cmd /k 'title TrustedInstaller && whoami /user', and cmd's title
#     command takes everything up to the && - trailing space included - so
#     the caption reads 'TrustedInstaller ' (an elevated conhost on a
#     localized Windows can also show an 'Administrateur : ' prefix for a
#     moment). v7.4's exact == therefore missed every single time and the
#     polisher timed out without ever touching the window.
#   - fix: captions are now matched trimmed, case-insensitive and by
#     CONTAINS; and if no caption ever matches but exactly ONE new
#     ConsoleWindowClass window appeared since the pre-spawn snapshot,
#     that window is polished anyway - the snapshot makes it ours.
#   - diagnostics: a skip now reports the caption(s) actually observed,
#     and a success reports the caption it polished plus both DWM
#     HRESULTs - no more guessing from the outside.
#
# v7.6 (field feedback from the eighth live run - v7.5 FOUND the window
#       (caption 'Administrateur :  TrustedInstaller ', elevated prefix +
#       trailing space and all) but DWM refused both attribute calls with
#       0x80070006 E_HANDLE):
#   - corner preference DROPPED: Windows 11 already rounds the corners of
#     inbox top-level windows automatically (MS Learn, 'Apply rounded
#     corners' - exceptions are maximized/snapped/VM/AVD/WDAG only), and
#     conhost is an inbox app. The corner attribute chased nothing.
#   - the visible 'old' tell on a dark-themed desktop is the LIGHT title
#     bar: TI has no HKCU profile, so conhost falls back to light. The
#     dark title bar is now applied from INSIDE the new window:
#     New-SuCmdLine prepends a fail-safe 'powershell -EncodedCommand'
#     self-polish - the shell runs on the same token as the window owner
#     (conhost), which is the caller DWM accepts; the parent-side call
#     from a High-integrity process on a SYSTEM/TI-owned window is what
#     the E_HANDLE refusal was. Chained with '&' not '&&' so a failure
#     never blocks the shell; prints one '[D] self-polish:' line in the
#     new window before whoami runs.
#   - the parent-side PolishConsoleWindow stays as a dark-only fallback
#     with a 3-attempt retry (young-window race theory) and now reports
#     ok/refused instead of a bare ok.
#
# v7.7 (field feedback from the ninth live run - two v7.6 regressions
#       and one repaint gap, all fixed):
#   - su sys DIED at spawn with 87/0x80070057 (delivered as an HRESULT):
#     the System route was the only spawn site still passing a NULL
#     environment together with CREATE_UNICODE_ENVIRONMENT, and the only
#     one without a SpawnAsUser fallback. The C# cores now carry the
#     UNICODE flag only with a real env block; the System route builds a
#     SYSTEM env block and falls back to CreateProcessAsUserW exactly
#     like the TI route. (Same run: the S4U route with a real env block
#     spawned fine - that contrast pinned the cause in one shot.)
#   - su <user> sprayed an Add-Type compiler error storm across the new
#     window: the v7.6 self-polish hardcoded TEMP=C:\Windows\Temp, which
#     the spawned user token cannot use (csc CS2001 'cannot find source
#     file'). The self-polish now probes for a temp dir that token can
#     create+read+delete in (its own GetTempPath() first, then
#     C:\Windows\Temp), skips silently when none works, and any failure
#     is one gray [D] line - never a red error display.
#   - dark=0x0 was reported yet the bar still looked light: setting the
#     attribute alone does not always repaint. Both polish paths now
#     nudge the window with SetWindowPos(SWP_FRAMECHANGED) right after
#     the attribute set, and the self-polish clears the base64 title-bar
#     flash too.
#
# v7.8 (field feedback from the tenth live run: su sys spawns again and
#       its window has looked right since v1; su alexa's window still
#       looked wrong and printed '[D] self-polish: ... point d'entree
#       GetConsoleWindow introuvable dans user32.dll'):
#   - GetConsoleWindow is a KERNEL32.DLL export, not user32. The v7.6/
#     v7.7 self-polish DllImported it from user32.dll, so the first call
#     threw EntryPointNotFoundException - visible only after v7.7's temp
#     probe fixed the Add-Type compile: the wrong-DLL layer sat hidden
#     underneath the TEMP layer. Two field runs, one bug per run.
#   - fix: the import now reads kernel32.dll. SetWindowPos (user32.dll)
#     and DwmSetWindowAttribute (dwmapi.dll) were already correct.
#   - next-run tell: '[D] self-polish: dark=0x0 hwnd=0x...' and the title
#     bar visibly darkening ~1s after open. If dark=0x0 prints but the bar
#     stays light, conhost captions do not honor the attribute from ANY
#     caller - the honest end of the console-cosmetics road.
#
# v7.9 (field feedback from the eleventh live run: 'still looks terrible',
#       pasted alongside the parent-side 'window polish: refused ...
#       dark=0x80070006' line - that refusal is EXPECTED for TI-owned
#       windows and says nothing about the child; the v7.8 bytes had not
#       reached that machine, so the child was still crashing at
#       GetConsoleWindow):
#   - the kernel32 import fix ships in the delivered bytes now - check the
#     first line of this file says v7.9 before retesting.
#   - the self-polish skip path is no longer silent: when no temp dir
#     passes the probe, the new window prints '[D] self-polish: skipped
#     (no temp dir usable by this token)'. Every dark-theme spawn now
#     reports exactly one status line (dark=0x... / exception / skipped),
#     so the next field report cannot be ambiguous.
#
# v7.10 (field feedback from the twelfth live run: 'its v 7.9 but it
#       still looks old' - the line-1 check confirmed the v7.9 bytes were
#       on the machine, but no child [D] line was pasted):
#   - escalation: the in-window polish now also sets DWMWA_CAPTION_COLOR
#     (35) = 0x202020 and DWMWA_TEXT_COLOR (36) = 0xF0F0F0 after the
#     immersive-dark flag (20), because a caption color pinned explicitly
#     by the console host OVERRIDES the theme flag - 'dark=0x0' can
#     coexist with a still-light bar. One frame nudge after all three.
#   - the status line carries its version ('self-polish v7.10:') and all
#     three HRESULTs; txt=0xFFFFFFFF = not attempted (both colors
#     refused, caption stays light and black text stays readable).
#   - the parent-side 'window polish:' line now prints only on 'ok': the
#     'refused ... E_HANDLE' outcome is designed for SYSTEM/TI-owned
#     windows (the child self-polishes and reports there) and kept being
#     pasted back as if it were the bug.
#   - honest end condition unchanged: a run reporting dark=0 cap=0 txt=0
#     with the bar STILL light means DWM will not theme that window at
#     all - and the rest of the look (icon, font, scrollbar, no tabs) is
#     conhost architecture, not fixable from the spawn side.
#
# v7.11 (field feedback from the thirteenth live run: v7.10 confirmed
#       active by its own silence - no 'window polish:' line in the
#       paste - yet 'still doesnt work'; the third consecutive report
#       with NO child-window output pasted at all):
#   - the child's status line is RELAYED home now: New-SuCmdLine drops
#     su-<32hex>.polish in the caller's temp (per-file Users:Modify
#     grant via SID S-1-5-32-545, locale-proof; medium-integrity dir so
#     foreign medium tokens can write), the self-polish writes its line
#     there, and Wait-SuChildPolish (hooked into Polish-Console, so all
#     routes) polls 6s and prints '[D] child polish relay: ...' in the
#     console the user actually pastes. Every dark-theme spawn reports.
#   - read-backs: the child reads attrs 20/35 back (gb20/gb35).
#     gb20=1 with a light bar = DWM stored dark but the frame never
#     used it; FFFFFFFF = unreadable. That split decides the next move.
#   - no relay line in 6s = the polish chain never ran (broken b64
#     chain / powershell failed under that token) - previously
#     indistinguishable from silence.
#   - honest end condition unchanged from v7.10.
#
# v7.12 (root cause CLOSED on the fourteenth round: the watchdog field
#       line 'hwnd=0xB05BE owner=cmd pid=17180 set20=0x0' named the
#       real bug - GetConsoleWindow inside the spawned shell returns a
#       HIDDEN PROXY WINDOW OWNED BY CMD.EXE ITSELF, the pseudoconsole
#       signature. The default-terminal delegation (Windows Terminal)
#       DOES capture foreign-token consoles on 26200.9711, disproving
#       the v7.3 'always falls back to classic conhost' assumption:
#       every paint since v7.6 colored an invisible window - hence
#       'dark=0x0' plus a light bar, thirteen times):
#   - forced classic hosting: New-SuCmdLine prefixes conhost.exe to the
#     child line. Starting conhost.exe directly with the client command
#     line is the documented escape hatch from default-terminal
#     delegation (verified technique - cplusplus.com forum 285415:
#     "you can start the 'old' conhost.exe directly!"). The child gets
#     a real classic ConsoleWindowClass window the relay can paint.
#   - the relay ships as a granted temp .ps1 via -File, not a 6.5KB
#     EncodedCommand: the child line drops to ~160 chars (the v7.12
#     relay would have broken the 8191-char cmd ceiling) and the script
#     is readable in temp for audit. Relay file + polish log carry
#     explicit Modify ACEs for Users, SYSTEM, Administrators AND the
#     target SID (TI is not even in Users; SeRestore's DACL bypass was
#     unproven).
#   - the relay reports its hosting mode home: heartbeat first ('alive'),
#     then gcw forensics (class/owner/visibility - the census nobody
#     pasted, self-carrying now). owner=conhost -> classic path paints
#     the REAL window. Anything else -> rehost path: paint gcw anyway,
#     open a classic replacement window, paint THAT dark, print a note
#     in the old window, report mode=rehost home.
#   - liveness fallback (Invoke-SuSpawn, all 7 routes): up to 5s for the
#     heartbeat or a title-matching console window after the forced
#     spawn; if neither shows, retry with the plain v7.11-style line -
#     worst case is the previous known-good behavior, never a dead
#     spawn.
#   - Wait-SuChildPolish: waits for the FINAL line (heartbeat keeps it
#     polling), 'started but never finished' if only the heartbeat
#     landed, reports a missing relay file instead of silence, cleans
#     up both relay temp files.
#
# v7.13 (fifteenth round: the v7.12 field line finally named the REAL
#       reason the bar never darkens - and it was never a DWM problem.
#       'mode=classic owner=cmd class=ConsoleWindowClass vis=True
#       dark=0x0 cap=0x0 txt=0x0 gb20=0x1' on a window that STAYED
#       light means: right window, same token, attributes stored - and
#       never rendered. conhost draws the console's own title bar and
#       decides dark vs light ITSELF (microsoft/terminal #299, merged
#       19H1): uxtheme ordinal 132 ShouldAppsUseDarkMode reads HKCU of
#       the console-hosting process, and only conhost's own recipe
#       (SetWindowTheme "DarkMode_Explorer" + the immersive-dark
#       attribute) renders. TI/SYSTEM tokens have no profile, so their
#       HKCU resolves to HKU\.DEFAULT - which says LIGHT. Every su
#       console read a light .DEFAULT and painted itself light;
#       fourteen rounds of foreign DWM calls changed nothing because
#       conhost redraws the bar from its own reading):
#   - Initialize-SuServiceTheme: one-time write of HKU\.DEFAULT\...
#     Themes\Personalize\AppsUseLightTheme=0 when the caller's theme
#     is dark, then a WM_SETTINGCHANGE("AppsUseLightTheme") +
#     WM_THEMECHANGED broadcast. The minted TI token carries the
#     SYSTEM logon-session LUID (0x3E7), so conhost-under-TI resolves
#     HKCU the same way conhost-under-SYSTEM does: after this DWORD
#     both paint themselves dark at creation, and an already-open
#     light su window repaints dark within a second of the next run.
#     One notice + the revert one-liner printed once; the logon
#     screen follows .DEFAULT too - documented, easily reverted.
#   - relay v7.13 belt-and-braces: replicates conhost's own recipe on
#     the live window anyway - SetWindowTheme "DarkMode_Explorer"
#     (the piece fourteen rounds never tried), DWM attr 19 AND 20,
#     caption/text colors, WM_THEMECHANGED sent straight to the
#     window so the owner re-runs its own theme code with .DEFAULT
#     now dark. Status line gains thm=/a19= and drops gb35
#     (field-proven unreadable).
#   - user routes: a real user's console reads HER hive (mounted
#     since v7.5 by LoadUserProfileAsSystem) - her own theme wins,
#     which is the honest behavior for su <user>.
#

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('User','System','TrustedInstaller')]
    [string]$Account,

    [string]$TargetUser,

    [switch]$InnerDrop,
    [string]$InnerSpec,
    [switch]$InnerUserDrop
)

$ErrorActionPreference = 'Stop'

# --- admin check (v7.34 logon gate) ---
# v7.34 BELT, not a fix. Field round 35 proved the old gate already
# passes for SYSTEM (a SYSTEM token carries BUILTIN\Administrators;
# su ran fine from a SYSTEM cmd on the interactive desktop). The
# SYSTEM-SID acceptance below is insurance for a stripped-token
# context only; the Administrators check is unchanged.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$isuSystemToken = $false
try { $isuSystemToken = ($id.User.Value -eq 'S-1-5-18') } catch {}
if (-not ($isuSystemToken -or $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host '[!] su-sys.ps1 must be launched elevated' -ForegroundColor Red
    exit 1
}

# --- embedded C# for token ops + process spawn ---
Add-Type -TypeDefinition @'
namespace Su {
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Collections.Generic;

    public static class T {
        // ---------------- structures ----------------
        [StructLayout(LayoutKind.Sequential)]
        struct LSA_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)]
        struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)]
        struct QUOTA_LIMITS {
            public ulong PagedPoolLimit, NonPagedPoolLimit;
            public ulong MinimumWorkingSetSize, MaximumWorkingSetSize;
            public ulong PagefileLimit;
            public long TimeLimit;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_SOURCE {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] SourceName;
            public long SourceContext;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES { public uint Count; public LUID_AND_ATTRIBUTES Privilege; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }

        // MSV1_0_S4U_LOGON - the S4U logon structure (diagnostics only; see S4ULogon)
        [StructLayout(LayoutKind.Sequential)]
        struct MSV1_0_S4U_LOGON {
            public uint MessageType;   // 12 = MsV1_0S4ULogon
            public uint Flags;
            public LSA_UNICODE_STRING UserPrincipalName;
            public LSA_UNICODE_STRING DomainName;
        }

        // ---- token-crafting structures (NtCreateToken) ----
        [StructLayout(LayoutKind.Sequential)]
        struct OBJECT_ATTRIBUTES {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_PRIVILEGES_FIXED {
            public uint Count;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public LUID_AND_ATTRIBUTES[] Items;
        }

        // PROFILEINFO for LoadUserProfile (v5)
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct PROFILEINFO {
            public int dwSize;
            public int dwFlags;          // PI_NOUI = 1
            public string lpUserName;    // required
            public string lpProfilePath; // null = let profmap resolve it
            public string lpDefaultPath;
            public string lpServerName;
            public string lpPolicyPath;
            public IntPtr hProfile;      // out: HKEY of the loaded hive
        }

        // SECURITY_QUALITY_OF_SERVICE for the NtCreateToken object
        // attributes (v6 - both field-proven implementations pass one).
        // v7: the NATIVE struct is 12 bytes (DWORD + enum + BYTE + BOOLEAN)
        // and the object manager validates QoS.Length == 12. The v6 C# form
        // marshalled 16 bytes (uint ContextTrackingMode + 4-byte BOOL) and
        // set Length = 16 -> STATUS_INVALID_PARAMETER. Fixed: byte +
        // 1-byte BOOL -> Marshal.SizeOf = 12.
        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_QUALITY_OF_SERVICE {
            public uint Length;
            public uint ImpersonationLevel;    // 2 = SecurityImpersonation
            public byte ContextTrackingMode;    // 0 = SECURITY_STATIC_TRACKING
            [MarshalAs(UnmanagedType.U1)] public bool EffectiveOnly;
        }

        // NOTE - the NtCreateToken parameter contract, settled in v6 by
        // mirroring the two field-proven public implementations
        // (Wh04m1001/NtCreateToken, 3gstudent/EnableSeCreateTokenPrivilege)
        // and the ntdoc ZwCreateToken declaration:
        //   User          -> PTOKEN_USER          (TOKEN_USER wrapper struct)
        //   Groups        -> PTOKEN_GROUPS        (count + SID_AND_ATTRIBUTES[])
        //   Privileges    -> PTOKEN_PRIVILEGES    (count + LUID_AND_ATTRIBUTES[])
        //   Owner         -> PTOKEN_OWNER         (TOKEN_OWNER wrapper struct!)
        //   PrimaryGroup  -> PTOKEN_PRIMARY_GROUP (TOKEN_PRIMARY_GROUP wrapper!)
        //   DefaultDacl   -> PTOKEN_DEFAULT_DACL  (TOKEN_DEFAULT_DACL wrapper!)
        //   AuthenticationId must reference an EXISTING logon session - use
        //   SYSTEM_LUID (0x3E7); a fresh NtAllocateLocallyUniqueId value mints
        //   a LUID with no session behind it (ntdoc: STATUS_NO_SUCH_LOGON_SESSION).
        // Field history: v3 passed the three wrappers correctly but a bare
        // PSID as User -> 0xC0000005. v4/v5 "fixed" the three to raw pointers
        // (phnt style) and kept the broken User -> still 0xC0000005. v5 fixed
        // User but kept the raw three -> 0xC000000D in parameter validation
        // (the kernel read each SID's first 8 bytes - 0x0500000000000501 - as
        // an embedded pointer). v6: wrappers everywhere + SYSTEM_LUID + QoS
        // + ExpirationTime -1, byte-for-byte the proven form.
        // v7: the residual 0xC000000D was never a pointer FORM - it was two
        // content defects: label attributes 0xC020 (undefined bits 0x4000/
        // 0x8000; correct is SE_GROUP_INTEGRITY|SE_GROUP_INTEGRITY_ENABLED
        // = 0x60) and a 16-byte SECURITY_QUALITY_OF_SERVICE (native is 12;
        // the object manager validates QoS.Length == 12).

        // ---------------- P/Invokes ----------------
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr hMem);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr e, uint a, IntPtr z, int l, int ty, out IntPtr n);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TOKEN_PRIVILEGES s, int l, IntPtr p, IntPtr r);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr t);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        // LSA client functions are NOT DllImported: build 26200's secur32.dll
        // no longer exports LsaClose (EntryPointNotFoundException in the field).
        // They are resolved dynamically by the LsaNative class below
        // (sspicli.dll -> secur32.dll -> advapi32.dll).

        // Hidden synchronous SYSTEM child (used to drive schtasks.exe)
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);

        // SetTokenInformation - TokenSessionId = 12 (requires SeTcbPrivilege).
        // v7.1: v7 briefly switched this to class 11 - a REGRESSION, reverted;
        // winnt.h TOKEN_INFORMATION_CLASS: TokenRestrictedSids = 11,
        // TokenSessionId = 12, TokenGroupsAndPrivileges = 13.
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetTokenInformation(IntPtr hToken, int tokenClass, ref uint tokenInfo, int infoLen);

        // GetTokenInformation - TokenUser = 1 (TOKEN_USER { PSID UserSid; ... })
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // ---- SID utilities ----
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);
        [DllImport("advapi32.dll")] static extern bool IsValidSid(IntPtr pSid);

        // ---- token crafting ----
        [DllImport("advapi32.dll")] static extern bool AllocateLocallyUniqueId(out LUID Luid);
        [DllImport("advapi32.dll")] static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);
        [DllImport("advapi32.dll")] static extern bool AddAccessAllowedAce(IntPtr pAcl, uint dwAceRevision, uint AccessMask, IntPtr pSid);

        // ---- window-station / desktop access for spawned shells ----
        [DllImport("user32.dll", SetLastError = true)] static extern IntPtr GetProcessWindowStation();
        [DllImport("user32.dll", SetLastError = true)] static extern IntPtr GetThreadDesktop(IntPtr dwThread);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint GetSecurityInfo(IntPtr handle, int ObjectType, uint SecurityInfo,
            out IntPtr pSidOwner, out IntPtr pSidGroup, out IntPtr pDacl, out IntPtr pSacl, out IntPtr pSecurityDescriptor);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint SetSecurityInfo(IntPtr handle, int ObjectType, uint SecurityInfo,
            IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr psidSacl);

        // ---- v5: window station / desktop by name, user profile, environment ----
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenWindowStationW")]
        static extern IntPtr OpenWindowStationW(string lpszWinSta, bool fInherit, uint dwDesiredAccess);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetProcessWindowStation(IntPtr hWinSta);
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "OpenDesktopW")]
        static extern IntPtr OpenDesktopW(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool CloseDesktop(IntPtr hDesktop);
        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        // NtCreateToken - the classic (semi-obsolete but fully functional) token
        // creation syscall. Needs SeCreateTokenPrivilege on the calling thread.
        // Still the mechanism behind the NSudo/WinSudo/NanaRun family of tools.
        // Marshalling rules that cost a whole round trip (see also the struct
        // note above): Owner and PrimaryGroup are PSIDs and DefaultDacl is a
        // PACL, all passed directly - NOT via SetTokenInformation-style wrappers.
        [DllImport("ntdll.dll")]
        static extern uint NtCreateToken(
            out IntPtr TokenHandle,
            uint DesiredAccess,                 // TOKEN_ALL_ACCESS = 0xF01FF
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            int TokenType,                      // TokenPrimary = 1
            ref LUID AuthenticationId,
            ref long ExpirationTime,
            IntPtr TokenUser,                   // PTOKEN_USER (SID_AND_ATTRIBUTES wrapper) - NOT a bare PSID
            IntPtr Groups,                      // PTOKEN_GROUPS
            IntPtr Privileges,                  // PTOKEN_PRIVILEGES
            IntPtr Owner,                       // PTOKEN_OWNER wrapper - NOT a raw PSID (v6)
            IntPtr PrimaryGroup,                // PTOKEN_PRIMARY_GROUP wrapper - NOT a raw PSID (v6)
            IntPtr DefaultDacl,                 // PTOKEN_DEFAULT_DACL wrapper - NOT a raw PACL (v6)
            ref TOKEN_SOURCE Source);

        // ---------------- small helpers ----------------

        // Build an LSA_STRING (managed struct) pointing at an ASCII buffer.
        // The caller must free the buffer via Marshal.FreeHGlobal when done.
        static LSA_STRING MakeLsaString(string s, out IntPtr bufferOut) {
            byte[] b = Encoding.ASCII.GetBytes(s);
            IntPtr chars = Marshal.AllocHGlobal(b.Length + 1);
            Marshal.Copy(b, 0, chars, b.Length);
            Marshal.WriteByte(chars, b.Length, 0);
            bufferOut = chars;
            LSA_STRING ls;
            ls.Length = (ushort)b.Length;
            ls.MaximumLength = (ushort)(b.Length + 1);
            ls.Buffer = chars;
            return ls;
        }

        // Build MSV1_0_S4U_LOGON with wide-char user/domain appended after the
        // header. 'flags' passes through verbatim: no bits are publicly defined
        // for this struct, so 0 is tried first and 1 second (v3 always sent 1,
        // which coincided with STATUS_INVALID_PARAMETER_MIX on lt 3/4).
        static IntPtr BuildMsv(string user, string domain, uint flags, out int len) {
            byte[] ub = Encoding.Unicode.GetBytes(user + "\0");
            int hdr = Marshal.SizeOf(typeof(MSV1_0_S4U_LOGON));
            bool hasDomain = domain.Length > 0;
            byte[] db = hasDomain ? Encoding.Unicode.GetBytes(domain + "\0") : new byte[0];
            len = hdr + ub.Length + db.Length;
            IntPtr buf = Marshal.AllocHGlobal(len);
            for (int i = 0; i < len; i++) Marshal.WriteByte(buf, i, 0);
            IntPtr uPtr = new IntPtr(buf.ToInt64() + hdr);
            Marshal.Copy(ub, 0, uPtr, ub.Length);
            IntPtr dPtr = hasDomain ? new IntPtr(buf.ToInt64() + hdr + ub.Length) : IntPtr.Zero;
            if (hasDomain) Marshal.Copy(db, 0, dPtr, db.Length);
            MSV1_0_S4U_LOGON s = new MSV1_0_S4U_LOGON();
            s.MessageType = 12;  // MsV1_0S4ULogon
            s.Flags = flags;
            s.UserPrincipalName.Length = (ushort)(ub.Length - 2);
            s.UserPrincipalName.MaximumLength = (ushort)ub.Length;
            s.UserPrincipalName.Buffer = uPtr;
            if (hasDomain) {
                s.DomainName.Length = (ushort)(db.Length - 2);
                s.DomainName.MaximumLength = (ushort)db.Length;
                s.DomainName.Buffer = dPtr;
            } else {
                s.DomainName.Length = 0;
                s.DomainName.MaximumLength = 0;
                s.DomainName.Buffer = IntPtr.Zero;
            }
            Marshal.StructureToPtr(s, buf, false);
            return buf;
        }

        static TOKEN_SOURCE Src() {
            TOKEN_SOURCE t = new TOKEN_SOURCE();
            t.SourceName = new byte[8];
            byte[] n = Encoding.ASCII.GetBytes("SuS4U   ");
            Array.Copy(n, t.SourceName, 8);
            return t;
        }

        // Enable a privilege on a token handle; returns Win32 error (1300 =
        // ERROR_NOT_ALL_ASSIGNED when the token does not hold the privilege).
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

        // Append items to a list, skipping null/empty/duplicates.
        static void AddUnique(List<string> l, string[] items) {
            if (items == null) return;
            for (int i = 0; i < items.Length; i++)
                if (items[i] != null && items[i].Length > 0 && !l.Contains(items[i])) l.Add(items[i]);
        }

        // Convert "S-1-..." to a SID (LocalAlloc'd; freed via LocalFree later).
        // IsValidSid guards against a malformed string minting a broken SID the
        // kernel would choke on inside NtCreateToken.
        static IntPtr SidFromString(string s, List<IntPtr> localFreer) {
            IntPtr sid;
            if (!ConvertStringSidToSid(s, out sid)) return IntPtr.Zero;
            if (!IsValidSid(sid)) { LocalFree(sid); return IntPtr.Zero; }
            localFreer.Add(sid);
            return sid;
        }

        // ---------------- process token inspection ----------------

        // TokenUser SID string (S-1-...) of a process, or null on failure.
        public static string GetProcessTokenUser(int pid) {
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf)) return null;
            EnablePriv(tokSelf, 20);  // SeDebugPrivilege
            CloseHandle(tokSelf);
            IntPtr h = OpenProcess(0x0400, false, pid);  // PROCESS_QUERY_INFORMATION
            if (h == IntPtr.Zero) return null;
            IntPtr tok;
            if (!OpenProcessToken(h, 0x0008, out tok)) { CloseHandle(h); return null; }  // TOKEN_QUERY
            try {
                uint need = 0;
                GetTokenInformation(tok, 1, IntPtr.Zero, 0, out need);  // TokenUser
                if (need == 0) return null;
                IntPtr buf = Marshal.AllocHGlobal((int)need);
                try {
                    if (!GetTokenInformation(tok, 1, buf, need, out need)) return null;
                    IntPtr sid = Marshal.ReadIntPtr(buf);  // TOKEN_USER.UserSid
                    IntPtr s;
                    if (!ConvertSidToStringSid(sid, out s)) return null;
                    try { return Marshal.PtrToStringUni(s); } finally { LocalFree(s); }
                } finally { Marshal.FreeHGlobal(buf); }
            } finally { CloseHandle(tok); CloseHandle(h); }
        }

        // ---------------- token crafting (NtCreateToken) ----------------

        // Craft a primary token with an arbitrary TokenUser SID while impersonating
        // a full-privilege SYSTEM token (SeCreateTokenPrivilege + SeTcbPrivilege).
        // Presets:
        //   "TI"       - TrustedInstaller virtual account (NT SERVICE\TrustedInstaller)
        //   "Admin"    - elevated local admin user
        //   "Standard" - standard local user
        // candPids are candidate SYSTEM process PIDs to steal the craft token
        // from (lsass.exe first - see GetCraftableSystemToken). groupSidsIn can
        // supply the target's REAL SAM group SIDs (merged over the preset base).
        // The token's SessionId is rewritten to mySession (needs SeTcbPrivilege,
        // still impersonating at that point). Returns "OK" or "F:<reason>".
        public static string CreateTokenForSid(string userSidString, string[] groupSidsIn, string preset, int[] candPids, uint mySession, out IntPtr tokenOut) {
            tokenOut = IntPtr.Zero;

            // self: SeDebugPrivilege to open SYSTEM processes
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);
            CloseHandle(tokSelf);

            // Full-privilege SYSTEM impersonation token. NOTE: winlogon.exe on
            // 24H2-class builds holds SeTcbPrivilege but NOT SeCreateTokenPrivilege
            // (verified on build 26200.9711 - that is exactly why v1 failed with
            // F:no-priv:SeCreateTokenPrivilege). lsass.exe is the canonical holder.
            IntPtr wear;
            string srcDesc;
            string gres = GetCraftableSystemToken(candPids, out wear, out srcDesc);
            if (gres != "OK") return gres;
            if (!EnablePrivChecked(wear, 7)) { CloseHandle(wear); return "F:no-priv:SeTcbPrivilege(" + srcDesc + ")"; }
            if (!EnablePrivChecked(wear, 2)) { CloseHandle(wear); return "F:no-priv:SeCreateTokenPrivilege(" + srcDesc + ")"; }
            if (!ImpersonateLoggedOnUser(wear)) { CloseHandle(wear); return "F:impersonate:" + Marshal.GetLastWin32Error(); }

            List<IntPtr> hg = new List<IntPtr>();  // Marshal.FreeHGlobal
            List<IntPtr> lf = new List<IntPtr>();  // LocalFree
            try {
                bool ti = (preset == "TI");
                bool admin = (preset == "Admin");

                IntPtr sidUser = SidFromString(userSidString, lf);
                if (sidUser == IntPtr.Zero) return "F:sid(user)";

                // TOKEN_USER buffer - the syscall's User parameter is PTOKEN_USER,
                // a SID_AND_ATTRIBUTES wrapper around the PSID, not the bare SID
                // (see the marshalling NOTE above; passing the bare SID here was
                // v4's 0xC0000005, reported on both the TI and user routes).
                SID_AND_ATTRIBUTES tua = new SID_AND_ATTRIBUTES();
                tua.Sid = sidUser;
                tua.Attributes = 0;
                IntPtr pUser = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
                hg.Add(pUser);
                Marshal.StructureToPtr(tua, pUser, false);

                // --- groups: base well-knowns + preset extras + the target's real
                //     SAM groups (when supplied) + integrity label as the LAST entry.
                //     INTERACTIVE (S-1-5-4) is included so the spawned window can
                //     reach winsta0\default. NO logon-session SID is added on
                //     purpose: the kernel rejects S-1-5-5-* groups that do not
                //     carry SE_GROUP_LOGON_ID matching the token's fresh
                //     AuthenticationId. The buffer is sized dynamically (a real
                //     SAM group list can exceed the old fixed 8 slots).
                List<string> gset = new List<string>();
                AddUnique(gset, new string[] { "S-1-1-0", "S-1-5-11", "S-1-5-4" });
                string[] presetGroups;
                string primaryGroupSid;
                string labelSid;
                if (ti) {
                    // mirror the real TI token: Everyone, Authenticated Users,
                    // Administrators, Users, NT SERVICE\All Services + System label
                    presetGroups = new string[] { "S-1-5-32-544", "S-1-5-32-545", "S-1-5-80-0" };
                    primaryGroupSid = "S-1-5-80-0";    // NT SERVICE\All Services
                    labelSid = "S-1-16-16384";          // System mandatory level
                } else if (admin) {
                    presetGroups = new string[] { "S-1-5-32-544", "S-1-5-32-545" };
                    primaryGroupSid = "S-1-5-32-544";  // Administrators
                    labelSid = "S-1-16-12288";          // High
                } else {
                    presetGroups = new string[] { "S-1-5-32-545" };
                    primaryGroupSid = "S-1-5-32-545";  // Users
                    labelSid = "S-1-16-8192";           // Medium
                }
                AddUnique(gset, presetGroups);
                if (groupSidsIn != null) AddUnique(gset, groupSidsIn);
                gset.Add(labelSid);
                int nGroups = gset.Count;
                int grpHdr = IntPtr.Size;   // ULONG Count + padding to pointer alignment
                int grpElem = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                IntPtr pGroups = Marshal.AllocHGlobal(grpHdr + nGroups * grpElem);
                hg.Add(pGroups);
                Marshal.WriteInt32(pGroups, 0, nGroups);
                for (int i = 0; i < nGroups; i++) {
                    IntPtr g = SidFromString(gset[i], lf);
                    if (g == IntPtr.Zero) return "F:sid(group " + gset[i] + ")";
                    SID_AND_ATTRIBUTES saa = new SID_AND_ATTRIBUTES();
                    saa.Sid = g;
                    // label: SE_GROUP_INTEGRITY (0x20) | SE_GROUP_INTEGRITY_ENABLED
                    // (0x40) = 0x60 - the exact attributes Wh04m1001/NtCreateToken
                    // passes for S-1-16-16384. v5/v6 used 0xC020, whose bits
                    // 0x4000|0x8000 are NOT defined SE_GROUP flags (a confusion
                    // between SE_GROUP_INTEGRITY_ENABLED and the high half of
                    // SE_GROUP_LOGON_ID 0xC0000000) - the kernel's group-attribute
                    // mask check answers that with STATUS_INVALID_PARAMETER, the
                    // exact 0xC000000D of live runs 4 and 5. All other groups:
                    // MANDATORY|ENABLED_BY_DEFAULT|ENABLED (0x7).
                    saa.Attributes = (i == nGroups - 1) ? 0x60u : 0x7u;
                    Marshal.StructureToPtr(saa, new IntPtr(pGroups.ToInt64() + grpHdr + (long)i * grpElem), false);
                }

                // --- privileges (LUIDs: 2=CreateToken 3=AssignPrimaryToken 5=IncreaseQuota
                //     7=Tcb 8=Security 9=TakeOwnership 10=LoadDriver 13=ProfileSingleProcess
                //     17=Backup 18=Restore 19=Shutdown 20=Debug 21=Audit 22=SystemEnvironment
                //     23=ChangeNotify 29=Impersonate 30=CreateGlobal) ---
                uint[] privLuids;
                if (ti) {
                    // superset of the real TI service token privileges (the real one
                    // carries Audit/SystemEnvironment/ChangeNotify/Impersonate) -
                    // TakeOwnership + Restore make takeown/icacls fully functional
                    privLuids = new uint[] { 2, 3, 5, 7, 8, 9, 10, 13, 17, 18, 20, 21, 22, 23, 29, 30 };
                } else if (admin) {
                    privLuids = new uint[] { 5, 9, 13, 17, 18, 19, 20, 22, 23, 29, 30 };
                } else {
                    privLuids = new uint[] { 5, 19, 23, 29, 30 };
                }
                if (privLuids.Length > 16) return "F:privcount:" + privLuids.Length;
                TOKEN_PRIVILEGES_FIXED tp = new TOKEN_PRIVILEGES_FIXED();
                tp.Items = new LUID_AND_ATTRIBUTES[16];
                for (int i = 0; i < privLuids.Length; i++) {
                    tp.Items[i].Luid.LowPart = privLuids[i];
                    tp.Items[i].Luid.HighPart = 0;
                    tp.Items[i].Attributes = 3;  // SE_PRIVILEGE_ENABLED_BY_DEFAULT|SE_PRIVILEGE_ENABLED
                }
                tp.Count = (uint)privLuids.Length;
                IntPtr pPrivs = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TOKEN_PRIVILEGES_FIXED)));
                hg.Add(pPrivs);
                Marshal.StructureToPtr(tp, pPrivs, false);

                // --- owner / primary group / default DACL ---
                // All three go as the SetTokenInformation-style WRAPPER structs
                // (PTOKEN_OWNER / PTOKEN_PRIMARY_GROUP / PTOKEN_DEFAULT_DACL -
                // see the marshalling NOTE above; that is the form ntdoc
                // declares and both field-proven implementations pass).
                // Owner = the user SID, so takeown assigns file ownership to
                // the minted identity (the TI acceptance test); the ACL below
                // becomes the token's DefaultDacl.
                IntPtr sidPrimary = SidFromString(primaryGroupSid, lf);
                if (sidPrimary == IntPtr.Zero) return "F:sid(primary)";
                IntPtr acl = Marshal.AllocHGlobal(160);
                hg.Add(acl);
                if (!InitializeAcl(acl, 160, 2))  // ACL_REVISION
                    return "F:initacl:" + Marshal.GetLastWin32Error();
                string[] daclSids = ti
                    ? new string[] { "S-1-5-18", "S-1-5-32-544", userSidString, "S-1-5-80-0" }
                    : new string[] { "S-1-5-18", "S-1-5-32-544", userSidString };
                foreach (string ds in daclSids) {
                    IntPtr dsid = SidFromString(ds, lf);
                    if (dsid == IntPtr.Zero) return "F:sid(dacl)";
                    if (!AddAccessAllowedAce(acl, 2, 0x10000000, dsid))  // GENERIC_ALL
                        return "F:addace:" + Marshal.GetLastWin32Error();
                }
                IntPtr pOwnerW = Marshal.AllocHGlobal(IntPtr.Size); hg.Add(pOwnerW);
                Marshal.WriteIntPtr(pOwnerW, 0, sidUser);
                IntPtr pGroupW = Marshal.AllocHGlobal(IntPtr.Size); hg.Add(pGroupW);
                Marshal.WriteIntPtr(pGroupW, 0, sidPrimary);
                IntPtr pDaclW = Marshal.AllocHGlobal(IntPtr.Size); hg.Add(pDaclW);
                Marshal.WriteIntPtr(pDaclW, 0, acl);

                // --- authentication id / expiration / source ---
                // AuthenticationId MUST reference an existing logon session:
                // SYSTEM_LUID (0x3E7) is the one every LocalSystem service
                // token lives on (both proven implementations pass it; a fresh
                // AllocateLocallyUniqueId references no session - ntdoc lists
                // STATUS_NO_SUCH_LOGON_SESSION for exactly that mistake).
                LUID authLuid;
                authLuid.LowPart = 0x3E7;
                authLuid.HighPart = 0;
                LUID srcLuid;
                if (!AllocateLocallyUniqueId(out srcLuid))
                    return "F:allocluid:" + Marshal.GetLastWin32Error();
                long exp = -1;  // the proven form (v4/v5 used long.MaxValue)
                TOKEN_SOURCE src = new TOKEN_SOURCE();
                src.SourceName = new byte[8];
                byte[] sn = Encoding.ASCII.GetBytes(ti ? "SuTI    " : "SuUsr   ");
                Array.Copy(sn, src.SourceName, 8);
                src.SourceContext = ((long)srcLuid.HighPart << 32) | (long)srcLuid.LowPart;

                SECURITY_QUALITY_OF_SERVICE qos = new SECURITY_QUALITY_OF_SERVICE();
                qos.Length = (uint)Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE));
                qos.ImpersonationLevel = 2;   // SecurityImpersonation
                qos.ContextTrackingMode = 0;  // SECURITY_STATIC_TRACKING
                qos.EffectiveOnly = false;
                IntPtr pQos = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_QUALITY_OF_SERVICE)));
                hg.Add(pQos);
                Marshal.StructureToPtr(qos, pQos, false);

                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
                oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
                oa.SecurityQualityOfService = pQos;

                IntPtr hTok;
                uint st = NtCreateToken(out hTok, 0xF01FF, ref oa, 1, ref authLuid, ref exp,
                    pUser, pGroups, pPrivs, pOwnerW, pGroupW, pDaclW, ref src);
                Console.Error.WriteLine("[D] NtCreateToken returned 0x" + st.ToString("X"));
                if (st != 0) {
                    string extra = (st == 0xC0000061) ? " (STATUS_PRIVILEGE_NOT_HELD - SeCreateTokenPrivilege missing)" :
                        (st == 0xC0000065) ? " (STATUS_NO_SUCH_LOGON_SESSION - auth LUID has no logon session)" : "";
                    return "F:ntcreatetoken:0x" + st.ToString("X") + extra;
                }

                // rewrite SessionId to the caller's interactive session (TCB -
                // still impersonating). TokenSessionId = information class 12
                // (winnt.h: TokenRestrictedSids = 11, TokenSessionId = 12,
                // TokenGroupsAndPrivileges = 13 - the brief v7 switch to 11
                // was a mis-fit, reverted in v7.1; class 11 would have failed
                // with ERROR_INVALID_PARAMETER right after the first craft).
                uint sess = mySession;
                if (!SetTokenInformation(hTok, 12, ref sess, 4)) {
                    int e = Marshal.GetLastWin32Error();
                    CloseHandle(hTok);
                    return "F:setsession:" + e;
                }

                tokenOut = hTok;
                return "OK";
            } finally {
                RevertToSelf();
                foreach (IntPtr p in hg) Marshal.FreeHGlobal(p);
                foreach (IntPtr p in lf) LocalFree(p);
                CloseHandle(wear);
            }
        }

        // ---------------- desktop access ----------------

        // Grant a SID full access to the caller's window station and desktop so
        // CreateProcessWithTokenW / CreateProcessAsUserW can start an
        // interactive process with a token whose user has no rights there (a
        // crafted standard-user or TI token, an S4U token, or one stolen from
        // another session - their logon SIDs are not in this session's
        // winsta/desktop DACL, and INTERACTIVE alone is not reliable).
        // v5: the spawn paths now call GrantDesktopAsSystem below instead
        // (SYSTEM-impersonated, objects opened by name); this plain-admin
        // variant is kept as a small, dependency-free fallback utility.
        // Idempotent (a repeat call appends a duplicate allow-ACE, which is
        // harmless). The ACE survives until sign-out.
        // SE_WINDOW_OBJECT = 7, DACL_SECURITY_INFORMATION = 4.
        public static string GrantSidDesktop(string sidString) {
            IntPtr sid;
            if (!ConvertStringSidToSid(sidString, out sid)) return "F:sid";
            try {
                string r1 = GrantOnObject(GetProcessWindowStation(), sid);
                string r2 = GrantOnObject(GetThreadDesktop(GetCurrentThread()), sid);
                return r1 == "OK" ? r2 : r1;
            } finally { LocalFree(sid); }
        }

        // Append a GENERIC_ALL allow-ACE for sid to the object's DACL.
        static string GrantOnObject(IntPtr hObj, IntPtr sid) {
            if (hObj == IntPtr.Zero) return "F:obj-handle:" + Marshal.GetLastWin32Error();
            IntPtr pOwner, pGroup, pDacl, pSacl, pSD;
            uint rc = GetSecurityInfo(hObj, 7, 4, out pOwner, out pGroup, out pDacl, out pSacl, out pSD);
            if (rc != 0) return "F:getsecinfo:" + rc;
            try {
                if (pDacl == IntPtr.Zero) return "F:no-dacl";
                int oldSize = Marshal.ReadByte(pDacl, 2) | (Marshal.ReadByte(pDacl, 3) << 8);
                int cnt = Marshal.ReadByte(pDacl, 4) | (Marshal.ReadByte(pDacl, 5) << 8);
                int sidLen = 8 + Marshal.ReadByte(sid, 1) * 4;
                int aceSize = 8 + sidLen;
                IntPtr newDacl = Marshal.AllocHGlobal(oldSize + aceSize);
                try {
                    for (int i = 0; i < oldSize; i++) Marshal.WriteByte(newDacl, i, Marshal.ReadByte(pDacl, i));
                    int off = oldSize;
                    Marshal.WriteByte(newDacl, off, 0);                                // ACCESS_ALLOWED_ACE_TYPE
                    Marshal.WriteByte(newDacl, off + 1, 0);                            // ACE flags
                    Marshal.WriteByte(newDacl, off + 2, (byte)(aceSize & 0xFF));
                    Marshal.WriteByte(newDacl, off + 3, (byte)((aceSize >> 8) & 0xFF));
                    Marshal.WriteInt32(newDacl, off + 4, unchecked((int)0x10000000)); // GENERIC_ALL
                    for (int i = 0; i < sidLen; i++) Marshal.WriteByte(newDacl, off + 8 + i, Marshal.ReadByte(sid, i));
                    int newSize = oldSize + aceSize;
                    Marshal.WriteByte(newDacl, 2, (byte)(newSize & 0xFF));
                    Marshal.WriteByte(newDacl, 3, (byte)((newSize >> 8) & 0xFF));
                    Marshal.WriteByte(newDacl, 4, (byte)((cnt + 1) & 0xFF));
                    Marshal.WriteByte(newDacl, 5, (byte)(((cnt + 1) >> 8) & 0xFF));
                    uint rc2 = SetSecurityInfo(hObj, 7, 4, IntPtr.Zero, IntPtr.Zero, newDacl, IntPtr.Zero);
                    if (rc2 != 0) return "F:setsecinfo:" + rc2;
                    return "OK";
                } finally { Marshal.FreeHGlobal(newDacl); }
            } finally { if (pSD != IntPtr.Zero) LocalFree(pSD); }
        }

        // ---------------- v5: SYSTEM-impersonated desktop grant / profile / env ----------------

        // Grant a SID GENERIC_ALL on this session's WinSta0 and its Default
        // desktop while impersonating SYSTEM (winlogon), so the WRITE_DAC edit
        // is permitted even where the plain elevated-admin token would be
        // denied, with handles opened BY NAME using READ_CONTROL|WRITE_DAC
        // (0x00060000) instead of trusting the access rights of whatever
        // handle GetProcessWindowStation happens to return. This is the fix
        // for the field-observed 0xc0000142: a token whose user SID has no ACE
        // on winsta0\default cannot connect to the desktop, so the child dies
        // inside DLL init (conhost cannot open the desktop) even though
        // CreateProcess* itself returned success.
        public static string GrantDesktopAsSystem(int wlPid, string sidString) {
            IntPtr sid;
            if (!ConvertStringSidToSid(sidString, out sid)) return "F:sid";
            try {
                IntPtr tokSelf;
                if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                    return "F:opentok(self):" + Marshal.GetLastWin32Error();
                EnablePriv(tokSelf, 20);
                CloseHandle(tokSelf);
                IntPtr hWl = OpenProcess(0x0400, false, wlPid);
                if (hWl == IntPtr.Zero) return "F:open(winlogon):" + Marshal.GetLastWin32Error();
                IntPtr tokWl;
                if (!OpenProcessToken(hWl, 0x000E, out tokWl)) { int e = Marshal.GetLastWin32Error(); CloseHandle(hWl); return "F:opentok(winlogon):" + e; }
                IntPtr wear;
                if (!DuplicateTokenEx(tokWl, 0x02000000, IntPtr.Zero, 2, 2, out wear)) { int e2 = Marshal.GetLastWin32Error(); CloseHandle(tokWl); CloseHandle(hWl); return "F:dup(wear):" + e2; }
                CloseHandle(tokWl); CloseHandle(hWl);
                if (!ImpersonateLoggedOnUser(wear)) { int e3 = Marshal.GetLastWin32Error(); CloseHandle(wear); return "F:impersonate:" + e3; }
                try {
                    IntPtr hw = OpenWindowStationW("winsta0", false, 0x00060000);
                    if (hw == IntPtr.Zero) return "F:openwinsta:" + Marshal.GetLastWin32Error();
                    string r1 = GrantOnObject(hw, sid);
                    // the desktop object lives inside this station: make it ours
                    // before OpenDesktopW, otherwise the open lands in the
                    // process's original station and the grant misses.
                    SetProcessWindowStation(hw);
                    IntPtr hd = OpenDesktopW("default", 0, false, 0x00060000);
                    string r2;
                    if (hd == IntPtr.Zero) r2 = "F:opendesktop:" + Marshal.GetLastWin32Error();
                    else { r2 = GrantOnObject(hd, sid); CloseDesktop(hd); }
                    return r1 == "OK" ? r2 : r1;
                } finally { RevertToSelf(); CloseHandle(wear); }
            } finally { LocalFree(sid); }
        }

        // Load the target user's profile hive under HKU\<sid> while impersonating
        // SYSTEM (SeBackup + SeRestore are required; winlogon's token holds
        // both). The hive stays mounted for the spawned shell (never unloaded
        // here). Works for genuine logon tokens (live-session steal, S4U);
        // crafted tokens may be refused - callers treat that as non-fatal and
        // the shell then falls back to the .DEFAULT hive.
        public static string LoadUserProfileAsSystem(int wlPid, IntPtr hToken, string userName) {
            if (userName == null || userName.Length == 0) return "F:no-user";
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);
            CloseHandle(tokSelf);
            IntPtr hWl = OpenProcess(0x0400, false, wlPid);
            if (hWl == IntPtr.Zero) return "F:open(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr tokWl;
            if (!OpenProcessToken(hWl, 0x000E, out tokWl)) { int e = Marshal.GetLastWin32Error(); CloseHandle(hWl); return "F:opentok(winlogon):" + e; }
            IntPtr wear;
            if (!DuplicateTokenEx(tokWl, 0x02000000, IntPtr.Zero, 2, 2, out wear)) { int e2 = Marshal.GetLastWin32Error(); CloseHandle(tokWl); CloseHandle(hWl); return "F:dup(wear):" + e2; }
            CloseHandle(tokWl); CloseHandle(hWl);
            EnablePriv(wear, 17);  // SeBackupPrivilege
            EnablePriv(wear, 18);  // SeRestorePrivilege
            if (!ImpersonateLoggedOnUser(wear)) { int e3 = Marshal.GetLastWin32Error(); CloseHandle(wear); return "F:impersonate:" + e3; }
            try {
                PROFILEINFO pi = new PROFILEINFO();
                pi.dwSize = Marshal.SizeOf(typeof(PROFILEINFO));
                pi.dwFlags = 1;  // PI_NOUI
                pi.lpUserName = userName;
                if (!LoadUserProfile(hToken, ref pi))
                    return "F:loadprofile:" + Marshal.GetLastWin32Error();
                return "OK";
            } finally { RevertToSelf(); CloseHandle(wear); }
        }

        // Per-user unicode environment block for a token (userenv). The block
        // must stay alive until the CreateProcess* call returns; free it with
        // FreeEnvBlock afterwards.
        public static string MakeEnvBlock(IntPtr hToken, out IntPtr envOut) {
            envOut = IntPtr.Zero;
            if (!CreateEnvironmentBlock(out envOut, hToken, false))
                return "F:envblock:" + Marshal.GetLastWin32Error();
            return envOut != IntPtr.Zero ? "OK" : "F:envblock:empty";
        }

        public static void FreeEnvBlock(IntPtr env) {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
        }

        // ---------------- process spawning ----------------

        // Spawn a process with a given primary token (visible window in caller's
        // session) - CreateProcessWithTokenW (caller needs SeImpersonatePrivilege,
        // which elevated admins have).
        public static string SpawnWithToken(IntPtr hToken, string commandLine) {
            return SpawnWithToken(hToken, commandLine, null, IntPtr.Zero);
        }

        // v7.4: titled form without an env block.
        public static string SpawnWithToken(IntPtr hToken, string commandLine, string title) {
            return SpawnWithToken(hToken, commandLine, title, IntPtr.Zero);
        }

        // v5: explicit lpDesktop (a foreign token resolving its desktop from
        // the parent is exactly how 0xc0000142 shells die) + optional per-user
        // environment block; with no block the child inherits the caller's env.
        public static string SpawnWithToken(IntPtr hToken, string commandLine, IntPtr env) {
            return SpawnWithToken(hToken, commandLine, null, env);
        }

        // v7.4: title -> STARTUPINFO.lpTitle (the console carries it from the
        // first frame; cmd's own `title` command re-sets the same text), plus
        // a pre-spawn snapshot of existing console windows so the DWM frame
        // polish only ever touches THIS spawn's window.
        public static string SpawnWithToken(IntPtr hToken, string commandLine, string title, IntPtr env) {
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            // v7.34: lpDesktop UNSET = the child inherits the caller's desktop -
            // identical to the old winsta0\default on a normal desktop; at the
            // logon screen the child is born on the VISIBLE secure desktop.
            // v7.3: open the new console at 120x30 instead of the cramped
            // default (STARTF_USECOUNTCHARS = 0x08; honored on the plain
            // line; the conhost.exe prefix may ignore it - harmless).
            // v7.12 CORRECTION of the old claim below: the default-terminal
            // delegation DOES capture foreign-token consoles on this build
            // (the fourteenth-round watchdog caught GetConsoleWindow
            // returning a hidden cmd-owned proxy). New-SuCmdLine therefore
            // prefixes conhost.exe as the explicit host so the child gets a
            // real classic window the in-window relay can paint; the title,
            // colors and fallback are handled there and in Invoke-SuSpawn.
            si.dwFlags = 0x08;
            si.dwXCountChars = 120;
            si.dwYCountChars = 30;
            if (title != null) {
                si.lpTitle = title;
                SnapshotConsoles();
            }
            PROCESS_INFORMATION pi;
            // CREATE_NEW_CONSOLE=0x10, CREATE_UNICODE_ENVIRONMENT=0x400.
            // v7.7: the UNICODE flag goes ONLY with a real env block - the
            // ninth live run had 'su sys' die right here with 87/0x80070057
            // (delivered as an HRESULT) on a NULL env, while the same spawn
            // with a CreateEnvironmentBlock-built block worked seconds later.
            uint cf = env == IntPtr.Zero ? 0x10u : 0x410u;
            bool ok = CreateProcessWithTokenW(hToken, 0, null, commandLine,
                cf, env, null, ref si, out pi);
            if (!ok) return "F:spawn:" + Marshal.GetLastWin32Error();
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return "OK";
        }

        // Spawn with CreateProcessAsUserW while impersonating SYSTEM
        // (SeAssignPrimaryTokenPrivilege) - more robust for crafted tokens.
        // Uses an explicit desktop so the window shows up in the target session.
        public static string SpawnAsUser(IntPtr hToken, int wlPid, string commandLine) {
            return SpawnAsUser(hToken, wlPid, commandLine, null, IntPtr.Zero);
        }

        // v7.4: titled form without an env block.
        public static string SpawnAsUser(IntPtr hToken, int wlPid, string commandLine, string title) {
            return SpawnAsUser(hToken, wlPid, commandLine, title, IntPtr.Zero);
        }

        public static string SpawnAsUser(IntPtr hToken, int wlPid, string commandLine, IntPtr env) {
            return SpawnAsUser(hToken, wlPid, commandLine, null, env);
        }

        // v7.4: title -> STARTUPINFO.lpTitle + pre-spawn console snapshot
        // (see SpawnWithToken).
        public static string SpawnAsUser(IntPtr hToken, int wlPid, string commandLine, string title, IntPtr env) {
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);  // SeDebugPrivilege
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
            // CreateProcessAsUserW needs SeAssignPrimaryTokenPrivilege and
            // SeIncreaseQuotaPrivilege on the calling thread (winlogon's token
            // holds both - it launches every user session). Checked, so a
            // missing privilege reports itself instead of surfacing as 1314.
            string miss = "";
            if (!EnablePrivChecked(wear, 7)) miss += "SeTcb ";
            if (!EnablePrivChecked(wear, 3)) miss += "SeAssignPrimaryToken ";
            if (!EnablePrivChecked(wear, 5)) miss += "SeIncreaseQuota ";
            if (miss.Length > 0) { CloseHandle(wear); return "F:spawn-privs(" + miss.Trim() + " absent from winlogon token)"; }
            if (!ImpersonateLoggedOnUser(wear)) { CloseHandle(wear); return "F:impersonate:" + Marshal.GetLastWin32Error(); }
            try {
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                // v7.34: lpDesktop UNSET = the child inherits the caller's desktop -
                // identical to the old winsta0\default on a normal desktop; at the
                // logon screen the child is born on the VISIBLE secure desktop.
                    // v7.3: open the new console at 120x30 instead of the cramped
                // default (STARTF_USECOUNTCHARS = 0x08; honored on the plain
                // line; the conhost.exe prefix may ignore it - harmless).
                // v7.12 CORRECTION of the old claim below: the default-terminal
                // delegation DOES capture foreign-token consoles on this build
                // (the fourteenth-round watchdog caught GetConsoleWindow
                // returning a hidden cmd-owned proxy). New-SuCmdLine therefore
                // prefixes conhost.exe as the explicit host so the child gets a
                // real classic window the in-window relay can paint; the title,
                // colors and fallback are handled there and in Invoke-SuSpawn.
                si.dwFlags = 0x08;
                si.dwXCountChars = 120;
                si.dwYCountChars = 30;
                if (title != null) {
                    si.lpTitle = title;
                    SnapshotConsoles();
                }
                PROCESS_INFORMATION pi;
                // v7.7: same NULL-env guard as SpawnWithToken (see its comment).
                uint cf = env == IntPtr.Zero ? 0x10u : 0x410u;
                bool ok = CreateProcessAsUserW(hToken, null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                    cf, env, null, ref si, out pi);
                if (!ok) return "F:spawnasuser:" + Marshal.GetLastWin32Error();
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return "OK";
            } finally {
                RevertToSelf();
                CloseHandle(wear);
            }
        }

        // ---------------- console window frame polish (v7.4) ----------------
        // The spawned console is hosted by conhost.exe (Windows Terminal only
        // ever attaches through the same-user default-terminal handoff), and a
        // conhost frame minted for a foreign token does not reliably get the
        // Win11 corner rounding / dark title bar the caller's theme implies.
        // v7.13 CORRECTION of the claim directly below: DWM *stores* frame
        // attributes set by any process (field-proven: read-back gb20=0x1)
        // but only ever renders them when the window's own conhost code
        // applies them - conhost reads the theme from HKCU of the hosting
        // process (TI/SYSTEM -> HKU\.DEFAULT) via uxtheme #132 and applies
        // its own recipe. The real fix is Initialize-SuServiceTheme; this
        // parent-side pass remains a best-effort fallback + diagnostic.
        // DWM stores these two frame attributes per top-level window no matter
        // which process asks, so the host sets them right after the spawn:
        // DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND always, and
        // DWMWA_USE_IMMERSIVE_DARK_MODE when the caller's app theme is dark.
        // The window ICON is deliberately untouched: conhost takes it from the
        // client executable (cmd.exe) - the same icon every conhost console
        // shows, and not changeable from outside without injection. Best
        // effort: any failure prints one [D] line and the frame stays exactly
        // as conhost drew it.
        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int cb);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool EnumWindows(EnumWinProc cb, IntPtr l);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool IsWindowVisible(IntPtr h);
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetClassNameW")]
        static extern int GetClassName(IntPtr h, StringBuilder s, int max);
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetWindowTextW")]
        static extern int GetWindowText(IntPtr h, StringBuilder s, int max);
        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
        delegate bool EnumWinProc(IntPtr h, IntPtr l);
        [DllImport("user32.dll", SetLastError = true, ExactSpelling = true, EntryPoint = "SendMessageTimeoutW")]
        static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);

        // v7.13: broadcast WM_SETTINGCHANGE("AppsUseLightTheme") + WM_THEMECHANGED
        // after the .DEFAULT write. Service-context consoles re-run their own
        // theme code (conhost reads HKCU = HKU\.DEFAULT for TI/SYSTEM tokens),
        // so an already-open light su window repaints dark without any
        // foreign DWM painting at all. Returns a short diagnostic.
        public static string BroadcastThemeChange() {
            try {
                IntPtr res = IntPtr.Zero;
                IntPtr lp = Marshal.StringToHGlobalUni("AppsUseLightTheme");
                IntPtr r1 = SendMessageTimeout((IntPtr)0xFFFF, 0x1A, IntPtr.Zero, lp, 2, 1000, out res);
                IntPtr r2 = SendMessageTimeout((IntPtr)0xFFFF, 0x31A, IntPtr.Zero, IntPtr.Zero, 2, 1000, out res);
                Marshal.FreeHGlobal(lp);
                return "ok 0x" + r1.ToInt64().ToString("X") + " 0x" + r2.ToInt64().ToString("X");
            } catch (Exception e) { return "err " + e.Message; }
        }

        static List<IntPtr> conBefore = new List<IntPtr>();

        // Called by the titled spawn overloads just before CreateProcess:
        // remembers every console window that already exists, so the polish
        // pass below only ever touches the window THIS spawn created (an
        // earlier 'su system' window can carry the same title).
        static void SnapshotConsoles() {
            List<IntPtr> l = new List<IntPtr>();
            EnumWinProc grab = delegate(IntPtr h, IntPtr p) {
                StringBuilder c = new StringBuilder(64);
                if (GetClassName(h, c, 64) > 0 && c.ToString() == "ConsoleWindowClass") l.Add(h);
                return true;
            };
            EnumWindows(grab, IntPtr.Zero);
            conBefore = l;
        }

        // Find this spawn's new console window (class ConsoleWindowClass,
        // title = what STARTUPINFO.lpTitle planted and cmd's `title` command
        // re-set; v7.5: caption matched by trimmed case-insensitive CONTAINS, with a single-new-window fallback) and given a dark title bar (v7.6: corners are automatic; dark is applied here as fallback, primarily by the in-window self-polish). Returns a diagnostic.
        public static string PolishConsoleWindow(string title, bool dark, int timeoutMs) {
            IntPtr found = IntPtr.Zero;
            List<IntPtr> fresh = new List<IntPtr>();  // distinct new console windows
            string want = title.Trim();
            int t0 = Environment.TickCount;
            while (found == IntPtr.Zero && (Environment.TickCount - t0) < timeoutMs) {
                EnumWinProc find = delegate(IntPtr h, IntPtr p) {
                    if (found != IntPtr.Zero) return false;
                    if (!IsWindowVisible(h)) return true;
                    StringBuilder c = new StringBuilder(64);
                    if (GetClassName(h, c, 64) == 0 || c.ToString() != "ConsoleWindowClass") return true;
                    if (conBefore.Contains(h)) return true;
                    StringBuilder t = new StringBuilder(256);
                    string cap = GetWindowText(h, t, 256) > 0 ? t.ToString() : "";
                    if (!fresh.Contains(h)) fresh.Add(h);
                    // v7.5: the live caption is rarely the bare title - cmd's
                    // `title X && ...` leaves a trailing space and an elevated
                    // conhost can prefix it - so match trimmed, case-insensitive,
                    // by CONTAINS instead of v7.4's exact ==.
                    if (cap.Trim().IndexOf(want, StringComparison.OrdinalIgnoreCase) >= 0) found = h;
                    return found == IntPtr.Zero;
                };
                EnumWindows(find, IntPtr.Zero);
                if (found == IntPtr.Zero) System.Threading.Thread.Sleep(200);
            }
            // v7.5 fallback: if no caption ever matched but exactly ONE new
            // ConsoleWindowClass window appeared, it is ours - the snapshot
            // taken right before CreateProcess guarantees that.
            if (found == IntPtr.Zero && fresh.Count == 1) found = fresh[0];
            if (found == IntPtr.Zero) {
                StringBuilder d = new StringBuilder("skip: no new console window matching '");
                d.Append(title).Append("' within ").Append(timeoutMs).Append(" ms");
                if (fresh.Count == 0) d.Append("; no new console window appeared at all");
                else {
                    d.Append("; new console caption(s): ");
                    foreach (IntPtr h2 in fresh) {
                        StringBuilder t2 = new StringBuilder(256);
                        d.Append("'").Append(GetWindowText(h2, t2, 256) > 0 ? t2.ToString() : "").Append("' ");
                    }
                }
                return d.ToString();
            }
            StringBuilder tc = new StringBuilder(256);
            string got = GetWindowText(found, tc, 256) > 0 ? tc.ToString() : "";
            if (!dark)
                return "ok hwnd=0x" + found.ToString("X") + " title='" + got + "' (caller theme is light: nothing to apply)";
            // v7.6: dark title bar only - Windows 11 already rounds the corners
            // of every inbox top-level window (conhost included), so the corner
            // attribute was dropped. E_HANDLE (0x80070006) is what DWM returns
            // when this parent-side call targets a window owned by a
            // higher-integrity token (SYSTEM/TI conhost) - the spawned shell
            // applies the attribute itself via the self-polish prepended to its
            // command line. The retry below covers the young-window race too.
            int hr = -1;
            for (int i = 0; i < 3; i++) {
                int dv = 1;
                hr = DwmSetWindowAttribute(found, 20, ref dv, 4);  // DWMWA_USE_IMMERSIVE_DARK_MODE
                if (hr == 0) break;
                System.Threading.Thread.Sleep(400);
            }
            // v7.7: a successful attribute set does not always repaint the
            // frame on its own - nudge it once so the recolored title bar
            // shows immediately (SWP_NOSIZE|SWP_NOMOVE|SWP_NOZORDER|
            // SWP_NOACTIVATE|SWP_FRAMECHANGED = 0x37).
            if (hr == 0) SetWindowPos(found, IntPtr.Zero, 0, 0, 0, 0, 0x37u);
            string res = (hr == 0 ? "ok" : "refused") + " hwnd=0x" + found.ToString("X")
                + " dark=0x" + hr.ToString("X") + " title='" + got + "'";
            if (hr != 0) res += " (expected for SYSTEM/TI-owned windows; the new window self-polishes)";
            return res;
        }

        // ---------------- full-privilege SYSTEM source + hidden child runner ----------------

        // True when tok's privilege list contains the given LUID (presence only,
        // enabled state irrelevant). TOKEN_PRIVILEGES layout: ULONG count at 0,
        // LUID_AND_ATTRIBUTES[] at offset 4 (4-byte alignment on both arches).
        static bool TokenHasPriv(IntPtr tok, uint luid) {
            uint need = 0;
            GetTokenInformation(tok, 3, IntPtr.Zero, 0, out need);
            if (need < 4) return false;
            IntPtr buf = Marshal.AllocHGlobal((int)need);
            try {
                if (!GetTokenInformation(tok, 3, buf, need, out need)) return false;
                int cnt = Marshal.ReadInt32(buf, 0);
                int elem = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                for (int i = 0; i < cnt; i++) {
                    IntPtr e = new IntPtr(buf.ToInt64() + 4 + (long)i * elem);
                    if ((uint)Marshal.ReadInt32(e, 0) == luid && Marshal.ReadInt32(e, 4) == 0) return true;
                }
                return false;
            } finally { Marshal.FreeHGlobal(buf); }
        }

        // True when tok's TokenUser equals the given SID string.
        // v7: public - the TI branch verifies the kernel TokenUser SID of
        // the crafted token directly instead of trusting the display name.
        public static bool TokenUserIs(IntPtr tok, string sidString) {
            uint need = 0;
            GetTokenInformation(tok, 1, IntPtr.Zero, 0, out need);
            if (need == 0) return false;
            IntPtr buf = Marshal.AllocHGlobal((int)need);
            try {
                if (!GetTokenInformation(tok, 1, buf, need, out need)) return false;
                IntPtr sid = Marshal.ReadIntPtr(buf);
                IntPtr s;
                if (!ConvertSidToStringSid(sid, out s)) return false;
                try { return Marshal.PtrToStringUni(s) == sidString; } finally { LocalFree(s); }
            } finally { Marshal.FreeHGlobal(buf); }
        }

        // Scan candidate PIDs and duplicate (as an impersonation token) the first
        // token that is LocalSystem AND actually holds SeCreateTokenPrivilege +
        // SeTcbPrivilege. lsass.exe is the canonical holder (LSASS calls
        // NtCreateToken for every logon); on 24H2-class builds winlogon.exe holds
        // only SeTcbPrivilege, which is why the v1 craft attempt failed.
        public static string GetCraftableSystemToken(int[] candPids, out IntPtr wear, out string usedDesc) {
            wear = IntPtr.Zero;
            usedDesc = "";
            if (candPids == null || candPids.Length == 0) return "F:no-candidates";
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);  // SeDebugPrivilege
            CloseHandle(tokSelf);
            StringBuilder tried = new StringBuilder();
            for (int ci = 0; ci < candPids.Length; ci++) {
                int pid = candPids[ci];
                IntPtr h = OpenProcess(0x0400, false, pid);
                if (h == IntPtr.Zero) { tried.Append("pid").Append(pid).Append(":open").Append(Marshal.GetLastWin32Error()).Append(" "); continue; }
                IntPtr tok;
                if (!OpenProcessToken(h, 0x000E, out tok)) { int e = Marshal.GetLastWin32Error(); CloseHandle(h); tried.Append("pid").Append(pid).Append(":tok").Append(e).Append(" "); continue; }
                IntPtr w;
                if (!DuplicateTokenEx(tok, 0x02000000, IntPtr.Zero, 2, 2, out w)) { int e2 = Marshal.GetLastWin32Error(); CloseHandle(tok); CloseHandle(h); tried.Append("pid").Append(pid).Append(":dup").Append(e2).Append(" "); continue; }
                CloseHandle(tok);
                CloseHandle(h);
                bool isSys = TokenUserIs(w, "S-1-5-18");
                bool hasCt = TokenHasPriv(w, 2);
                bool hasTcb = TokenHasPriv(w, 7);
                Console.Error.WriteLine("[D] craft-source pid " + pid + ": system=" + isSys + " SeCreateTokenPrivilege=" + hasCt + " SeTcbPrivilege=" + hasTcb);
                if (isSys && hasCt && hasTcb) { wear = w; usedDesc = "pid " + pid; return "OK"; }
                CloseHandle(w);
                tried.Append("pid").Append(pid).Append(":").Append(isSys ? "sys" : "user").Append(hasCt ? "+ct" : "").Append(hasTcb ? "+tcb" : "").Append(" ");
            }
            return "F:no-full-priv-source (PPL on lsass? tried: " + tried.ToString() + ")";
        }

        // Run one command line AS SYSTEM in a hidden child, wait for it, map
        // exit code 0 to "OK". Used to drive schtasks.exe: registering/
        // starting/deleting an S4U task FOR ANOTHER USER is denied to plain
        // admins - only a SYSTEM caller is allowed.
        public static string RunHiddenAsSystem(int wlPid, string commandLine, int timeoutMs) {
            IntPtr tok;
            string d = DupPrimaryToken(wlPid, out tok);
            if (d != "OK") return "F:duptoken:" + d;
            try {
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                PROCESS_INFORMATION pi;
                // CREATE_NO_WINDOW = 0x08000000
                if (!CreateProcessWithTokenW(tok, 0, null, commandLine, 0x08000000, IntPtr.Zero, null, ref si, out pi))
                    return "F:spawn:" + Marshal.GetLastWin32Error();
                try {
                    uint w = WaitForSingleObject(pi.hProcess, (uint)timeoutMs);
                    if (w != 0) return "F:wait:" + w;
                    uint code;
                    if (!GetExitCodeProcess(pi.hProcess, out code)) return "F:exitcode:" + Marshal.GetLastWin32Error();
                    return code == 0 ? "OK" : "F:exit:" + code;
                } finally { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
            } finally { CloseHandle(tok); }
        }

        // ---------------- SYSTEM helpers (kept from original) ----------------

        // Duplicate SYSTEM token from a target process (winlogon.exe by default)
        // TokenPrimary=1, SecurityImpersonation=2
        public static string DupPrimaryToken(int targetPid, out IntPtr tokenOut) {
            tokenOut = IntPtr.Zero;
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            try { EnablePriv(tokSelf, 20); } finally { CloseHandle(tokSelf); }  // SeDebugPrivilege

            IntPtr hTgt = OpenProcess(0x0400, false, targetPid);
            if (hTgt == IntPtr.Zero) return "F:open(target):" + Marshal.GetLastWin32Error();
            IntPtr tokTgt;
            if (!OpenProcessToken(hTgt, 0x000E, out tokTgt)) {
                int e = Marshal.GetLastWin32Error();
                CloseHandle(hTgt);
                return "F:opentok(target):" + e;
            }
            try {
                if (!DuplicateTokenEx(tokTgt, 0x02000000, IntPtr.Zero, 2, 1, out tokenOut))
                    return "F:dup:" + Marshal.GetLastWin32Error();
                return "OK";
            } finally { CloseHandle(tokTgt); CloseHandle(hTgt); }
        }

        // Steal a primary token from a (possibly session-0) process AND rewrite its
        // session ID to match the caller's session. Requires SeTcbPrivilege
        // (impersonating SYSTEM via winlogon).
        public static string StealTokenWithSession(int targetPid, int wlPid, uint targetSessionId, out IntPtr tokenOut) {
            tokenOut = IntPtr.Zero;
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);  // SeDebugPrivilege

            IntPtr hWl = OpenProcess(0x0400, false, wlPid);
            if (hWl == IntPtr.Zero) return "F:open(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr tokWl;
            if (!OpenProcessToken(hWl, 0x000E, out tokWl))
                return "F:opentok(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr wear;
            if (!DuplicateTokenEx(tokWl, 0x02000000, IntPtr.Zero, 2, 2, out wear))
                return "F:dup(wear):" + Marshal.GetLastWin32Error();
            EnablePriv(wear, 7);  // SeTcbPrivilege
            if (!ImpersonateLoggedOnUser(wear))
                return "F:impersonate:" + Marshal.GetLastWin32Error();

            try {
                IntPtr hTgt = OpenProcess(0x0400, false, targetPid);
                if (hTgt == IntPtr.Zero) return "F:open(target):" + Marshal.GetLastWin32Error();
                IntPtr tokTgt;
                if (!OpenProcessToken(hTgt, 0x000E, out tokTgt))
                    return "F:opentok(target):" + Marshal.GetLastWin32Error();
                if (!DuplicateTokenEx(tokTgt, 0x02000000, IntPtr.Zero, 2, 1, out tokenOut))
                    return "F:dup:" + Marshal.GetLastWin32Error();

                uint sid = targetSessionId;
                if (!SetTokenInformation(tokenOut, 12, ref sid, Marshal.SizeOf(typeof(uint))))
                    return "F:settokeninfo:" + Marshal.GetLastWin32Error();

                return "OK";
            } finally {
                RevertToSelf();
            }
        }

        // Rewrite an existing primary token's session ID to the caller's session.
        // Requires SeTcbPrivilege (impersonate SYSTEM via winlogon).
        public static string RewriteTokenSession(IntPtr hToken, int wlPid, uint targetSessionId, out IntPtr tokenOut) {
            tokenOut = IntPtr.Zero;
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);  // SeDebugPrivilege

            IntPtr hWl = OpenProcess(0x0400, false, wlPid);
            if (hWl == IntPtr.Zero) return "F:open(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr tokWl;
            if (!OpenProcessToken(hWl, 0x000E, out tokWl))
                return "F:opentok(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr wear;
            if (!DuplicateTokenEx(tokWl, 0x02000000, IntPtr.Zero, 2, 2, out wear))
                return "F:dup(wear):" + Marshal.GetLastWin32Error();
            EnablePriv(wear, 7);  // SeTcbPrivilege
            if (!ImpersonateLoggedOnUser(wear))
                return "F:impersonate:" + Marshal.GetLastWin32Error();

            try {
                if (!DuplicateTokenEx(hToken, 0x02000000, IntPtr.Zero, 2, 1, out tokenOut))
                    return "F:dup:" + Marshal.GetLastWin32Error();
                uint sid = targetSessionId;
                if (!SetTokenInformation(tokenOut, 12, ref sid, Marshal.SizeOf(typeof(uint))))
                    return "F:settokeninfo:" + Marshal.GetLastWin32Error();
                return "OK";
            } finally {
                RevertToSelf();
            }
        }

        // ---------------- LSA entry points (dynamic) ----------------
        // Build 26200's secur32.dll no longer exports LsaClose (verified in the
        // field: EntryPointNotFoundException), so every Lsa* function we need
        // is resolved manually: sspicli.dll (the real implementation since
        // Vista) first, then secur32.dll, then advapi32.dll.
        static class LsaNative {
            public delegate uint D_ConnectUntrusted(out IntPtr h);
            public delegate uint D_RegisterLogonProcess(ref LSA_STRING name, out IntPtr h, out uint mode);
            public delegate uint D_LookupAuthPackage(IntPtr lsa, ref LSA_STRING name, out uint id);
            public delegate uint D_LogonUser(IntPtr lsa, ref LSA_STRING origin, uint lt, uint pkg, IntPtr info, uint len, IntPtr groups, ref TOKEN_SOURCE src, out IntPtr profile, out uint plen, out long lid, out IntPtr token, ref QUOTA_LIMITS q, out uint sub);
            public delegate uint D_FreeReturnBuffer(IntPtr b);
            public delegate uint D_Close(IntPtr h);

            [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr LoadLibrary(string fileName);
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr module, string procName);

            public static readonly D_ConnectUntrusted LsaConnectUntrusted;
            public static readonly D_RegisterLogonProcess LsaRegisterLogonProcess;
            public static readonly D_LookupAuthPackage LsaLookupAuthenticationPackage;
            public static readonly D_LogonUser LsaLogonUser;
            public static readonly D_FreeReturnBuffer LsaFreeReturnBuffer;
            public static readonly D_Close LsaClose;
            public static readonly string Missing;

            static LsaNative() {
                StringBuilder miss = new StringBuilder();
                LsaConnectUntrusted = (D_ConnectUntrusted)Try("LsaConnectUntrusted", typeof(D_ConnectUntrusted), miss);
                LsaRegisterLogonProcess = (D_RegisterLogonProcess)Try("LsaRegisterLogonProcess", typeof(D_RegisterLogonProcess), miss);
                LsaLookupAuthenticationPackage = (D_LookupAuthPackage)Try("LsaLookupAuthenticationPackage", typeof(D_LookupAuthPackage), miss);
                LsaLogonUser = (D_LogonUser)Try("LsaLogonUser", typeof(D_LogonUser), miss);
                LsaFreeReturnBuffer = (D_FreeReturnBuffer)Try("LsaFreeReturnBuffer", typeof(D_FreeReturnBuffer), miss);
                LsaClose = (D_Close)Try("LsaClose", typeof(D_Close), miss);
                Missing = miss.ToString();
            }

            static Delegate Try(string fn, Type t, StringBuilder miss) {
                Delegate d = null;
                string[] dlls = new string[] { "sspicli.dll", "secur32.dll", "advapi32.dll" };
                for (int i = 0; i < dlls.Length; i++) {
                    IntPtr lib = LoadLibrary(dlls[i]);
                    if (lib == IntPtr.Zero) continue;
                    IntPtr p = GetProcAddress(lib, fn);
                    if (p != IntPtr.Zero) { d = Marshal.GetDelegateForFunctionPointer(p, t); break; }
                }
                if (d == null) miss.Append(fn).Append(" ");
                return d;
            }

            public static bool Ready() { return Missing.Length == 0; }
        }

        // ---------------- S4U logon (WORKING ROUTE since v5) ----------------
        //
        // Field-proven on build 26200.9711 (third live run):
        //  - lt=3 (Network) + domain = NetBIOS machine name + Flags=0 returns
        //    STATUS_SUCCESS with a usable primary token for a real SAM user.
        //    The v4 'known broken' verdict was wrong - those runs only ever
        //    tried dom='' and/or Flags=1 (0xC00000BB / 0xC000000D). The token
        //    is a NETWORK logon token: genuine LSASS logon session, real SAM
        //    identity, correct for a local shell once the desktop grant +
        //    profile + env bundle is applied (the v4 child died 0xc0000142
        //    because that bundle was missing on this path, not because of
        //    the token class).
        //  - lt=4 (Batch) with the same user/domain returns 0xC000015B
        //    (account-restriction class): direct batch S4U is refused for a
        //    plain SAM user. Task Scheduler S4U tasks still work - they go
        //    through the scheduler's own LSA path, not this public one.
        //  - lt=2/5/8 return STATUS_INVALID_PARAMETER (0xC000000D): msv1_0's
        //    S4U path only validates Network(3)/Batch(4).
        //  - The package name must be "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
        //    the short forms have never resolved (STATUS_NO_SUCH_PACKAGE).
        //  - For "NT SERVICE\TrustedInstaller": 0xC00000A7 / 0xC00000BB.
        //    Virtual service accounts are NOT SAM principals and can NEVER be
        //    resolved by the public S4U path - their tokens are minted by SCM
        //    through a private LSASS interface. This is why the TI branch now
        //    crafts tokens.
        //  - The D_LogonUser delegate below is field-proven exactly as
        //    declared (correct statuses, substatus and token handles across
        //    three live runs). Do NOT rewrite it to the 16-parameter SDK
        //    form without a Windows box to retest on.
        public static string S4ULogon(int wlPid, string user, string domain, out IntPtr tokenOut) {
            tokenOut = IntPtr.Zero;
            if (!LsaNative.Ready()) return "F:lsaresolve:" + LsaNative.Missing;
            IntPtr tokSelf;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tokSelf))
                return "F:opentok(self):" + Marshal.GetLastWin32Error();
            EnablePriv(tokSelf, 20);  // SeDebugPrivilege

            IntPtr hWl = OpenProcess(0x0400, false, wlPid);
            if (hWl == IntPtr.Zero) return "F:open(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr tokWl;
            if (!OpenProcessToken(hWl, 0x000E, out tokWl))
                return "F:opentok(winlogon):" + Marshal.GetLastWin32Error();
            IntPtr wear;
            if (!DuplicateTokenEx(tokWl, 0x02000000, IntPtr.Zero, 2, 2, out wear))
                return "F:dup(wear):" + Marshal.GetLastWin32Error();
            EnablePriv(wear, 7);  // SeTcbPrivilege
            EnablePriv(wear, 3);  // SeAssignPrimaryTokenPrivilege
            EnablePriv(wear, 13); // SeProfileSingleProcessPrivilege

            // Step 1: LsaConnectUntrusted to look up the package ID (as admin).
            IntPtr untrustedLsa = IntPtr.Zero;
            uint mid = 0;
            {
                uint rs = LsaNative.LsaConnectUntrusted(out untrustedLsa);
                if (rs != 0) return "F:connect:0x" + rs.ToString("X");
                if (untrustedLsa == IntPtr.Zero) return "F:connect:zero_handle";
                Console.Error.WriteLine("[D] LSA untrusted handle: 0x" + untrustedLsa.ToInt64().ToString("X"));

                string[] pkgNames = new string[] { "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", "MSV1_0", "msv1_0" };
                bool pkgFound = false;
                string lastLookupErr = "";
                foreach (string pkgName in pkgNames) {
                    IntPtr mnBuf;
                    LSA_STRING mn = MakeLsaString(pkgName, out mnBuf);
                    try {
                        uint lu = LsaNative.LsaLookupAuthenticationPackage(untrustedLsa, ref mn, out mid);
                        Console.Error.WriteLine("[D] LsaLookupAuthenticationPackage('" + pkgName + "') returned: 0x" + lu.ToString("X") + " mid=" + mid);
                        if (lu == 0 && mid != 0) {
                            pkgFound = true;
                            Console.Error.WriteLine("[D] package found with name: " + pkgName + " (mid=" + mid + ")");
                            break;
                        }
                        lastLookupErr = "0x" + lu.ToString("X");
                    } finally {
                        Marshal.FreeHGlobal(mnBuf);
                    }
                }
                LsaNative.LsaClose(untrustedLsa);
                untrustedLsa = IntPtr.Zero;

                if (!pkgFound) return "F:msvlookup:" + lastLookupErr;
            }

            // Step 2: impersonate SYSTEM (TCB).
            if (!ImpersonateLoggedOnUser(wear))
                return "F:impersonate:" + Marshal.GetLastWin32Error();
            bool impersonating = true;

            // Step 3: LsaRegisterLogonProcess for a trusted LSA handle.
            IntPtr trustedLsa = IntPtr.Zero;
            try {
                IntPtr pnBuf;
                LSA_STRING pn = MakeLsaString("SuS4U", out pnBuf);
                uint mode;
                uint rs2;
                try {
                    rs2 = LsaNative.LsaRegisterLogonProcess(ref pn, out trustedLsa, out mode);
                } finally {
                    Marshal.FreeHGlobal(pnBuf);
                }
                Console.Error.WriteLine("[D] LsaRegisterLogonProcess returned: 0x" + rs2.ToString("X") + " trustedHandle=0x" + trustedLsa.ToInt64().ToString("X") + " mode=" + mode);
                if (rs2 != 0) return "F:register:0x" + rs2.ToString("X");
                if (trustedLsa == IntPtr.Zero) return "F:register:zero_handle";

                // Step 4: LsaLogonUser with the trusted handle. Domain order:
                // the target domain, then the machine name (local S4U accounts
                // resolve against the computer name), then "". Flags 0 then 1.
                // Logon types: 3 (Network) first - the field-proven combo on
                // 26200.9711 is machine-domain + flags 0 + lt 3 - then 4
                // (Batch); 2/5/8 are rejected by msv1_0 itself with
                // STATUS_INVALID_PARAMETER.
                string machine = Environment.MachineName;
                List<string> doms = new List<string>();
                if (domain.Length > 0) doms.Add(domain);
                if (machine.Length > 0 && !doms.Contains(machine)) doms.Add(machine);
                if (!doms.Contains("")) doms.Add("");
                foreach (string d in doms) {
                    foreach (uint fl in new uint[] { 0, 1 }) {
                        foreach (uint lt in new uint[] { 3, 4 }) {
                            int len; IntPtr info = BuildMsv(user, d, fl, out len);
                            Console.Error.Write("[D] MSV1_0_S4U_LOGON (len=" + len + " dom='" + d + "' flags=" + fl + " lt=" + lt + ") bytes:");
                            int printLen = Math.Min(len, 64);
                            for (int i = 0; i < printLen; i++) {
                                byte bb = Marshal.ReadByte(info, i);
                                Console.Error.Write(" " + bb.ToString("X2"));
                            }
                            Console.Error.WriteLine();

                            IntPtr originBuf;
                            LSA_STRING origin = MakeLsaString("SuS4U", out originBuf);
                            TOKEN_SOURCE src = Src();
                            QUOTA_LIMITS q = new QUOTA_LIMITS();
                            IntPtr profile, token; uint plen, sub; long lid;
                            uint st;
                            try {
                                st = LsaNative.LsaLogonUser(trustedLsa, ref origin, lt, mid, info, (uint)len,
                                    IntPtr.Zero, ref src, out profile, out plen, out lid, out token,
                                    ref q, out sub);
                            } finally {
                                Marshal.FreeHGlobal(info);
                                Marshal.FreeHGlobal(originBuf);
                            }
                            if (profile != IntPtr.Zero) LsaNative.LsaFreeReturnBuffer(profile);
                            Console.Error.WriteLine("[D] LsaLogonUser lt=" + lt + " dom='" + d + "' flags=" + fl + " returned: 0x" + st.ToString("X") + " sub=0x" + sub.ToString("X"));
                            if (st == 0 && token != IntPtr.Zero) {
                                tokenOut = token;
                                return "OK:" + (d.Length > 0 ? d : "no-dom") + ":lt" + lt + ":flags" + fl;
                            }
                        }
                    }
                }
                return "F:all-combos-failed";
            } finally {
                if (impersonating) RevertToSelf();
                if (trustedLsa != IntPtr.Zero) LsaNative.LsaClose(trustedLsa);
            }
        }
    }
}
'@

# --- helpers ---

function Get-WinlogonInMySession {
    $mySession = (Get-Process -Id $PID).SessionId
    Get-CimInstance Win32_Process -Filter "Name='winlogon.exe'" |
        Where-Object SessionId -eq $mySession |
        Select-Object -First 1
}

# Candidate SYSTEM processes for the NtCreateToken craft source, best first:
# lsass.exe is the canonical SeCreateTokenPrivilege holder (LSASS itself calls
# NtCreateToken for every logon); winlogon.exe on 24H2-class builds only holds
# SeTcbPrivilege. services/wininit/svchost are extra fallbacks, winlogon last.
# The C# side verifies the privileges on every candidate before using it.
function Get-CraftSourcePids {
    param([object]$Winlogon)
    $list = New-Object System.Collections.Generic.List[int]
    foreach ($n in @('lsass.exe','services.exe','wininit.exe','svchost.exe')) {
        try {
            $pl = @(Get-CimInstance Win32_Process -Filter "Name='$n'" -ErrorAction SilentlyContinue)
            foreach ($p in $pl) {
                $ip = [int]$p.ProcessId
                if (-not $list.Contains($ip)) { $list.Add($ip) }
            }
        } catch {}
    }
    if ($Winlogon) {
        $wp = [int]$Winlogon.ProcessId
        if (-not $list.Contains($wp)) { $list.Add($wp) }
    }
    return $list.ToArray()
}

function Format-Identity([IntPtr]$tok) {
    try {
        $wi = New-Object Security.Principal.WindowsIdentity -ArgumentList $tok
        return $wi.Name
    } catch { return "(unreadable)" }
}

# Find a process owned by the given SID that we can steal a token from.
# Prefers explorer.exe (full interactive token of the logged-on user).
function Find-TargetProcess([string]$TargetSid) {
    $explorers = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)
    foreach ($e in $explorers) {
        if ($e.ProcessId -eq $PID) { continue }
        $u = [Su.T]::GetProcessTokenUser([int]$e.ProcessId)
        if ($u -eq $TargetSid) { return $e }
    }
    # no explorer match - widen the scan to user-session processes
    $procs = @(Get-CimInstance Win32_Process -Filter "SessionId > 0" -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        if ($p.ProcessId -eq $PID) { continue }
        if ($p.Name -eq 'winlogon.exe' -or $p.Name -eq 'LogonUI.exe' -or $p.Name -eq 'csrss.exe' -or $p.Name -eq 'smss.exe') { continue }
        $u = [Su.T]::GetProcessTokenUser([int]$p.ProcessId)
        if ($u -eq $TargetSid) { return $p }
    }
    return $null
}

# v7.4: best-effort modern frame for the console window su just opened -
# v7.6: dark title bar only (Windows 11 rounds conhost corners by itself).
# The parent-side DWM call is refused with E_HANDLE for windows owned by
# SYSTEM/TI-integrity conhost processes, so the real application happens
# INSIDE the new window - see $selfPolishScript / New-SuCmdLine below; this
# parent-side pass stays as a fallback (with a retry) and as diagnostics.
# The icon stays cmd.exe's own: conhost takes it from the client executable.
$script:DarkTheme = $false
$script:RelayScript = $null
$script:PolishLog = $null
try {
    $al = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name AppsUseLightTheme -ErrorAction SilentlyContinue).AppsUseLightTheme
    $script:DarkTheme = $true
} catch {}

# v7.13: the REAL theme fix. conhost draws the console's own title bar
# and decides dark vs light through uxtheme's ShouldAppsUseDarkMode -
# which reads HKCU of the console-hosting process (microsoft/terminal
# #299). TI and SYSTEM tokens have no profile of their own, so their
# HKCU resolves to HKU\.DEFAULT - which says LIGHT. That is why every
# su console painted itself light no matter what DWM attributes were
# set, by any process, for fourteen rounds. One DWORD fixes it at the
# source. Written once, only when the caller's own theme is dark;
# later runs see 0 and stay silent. Side effect (documented, easily
# reverted - the one-liner is printed once): the logon screen follows
# .DEFAULT too.
function Initialize-SuServiceTheme {
    $k = 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $cur = $null
    try { $cur = (Get-ItemProperty -Path $k -Name AppsUseLightTheme -ErrorAction Stop).AppsUseLightTheme } catch {}
    if ($cur -eq 0) { return }
    try {
        if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
        New-ItemProperty -Path $k -Name AppsUseLightTheme -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Host '[+] one-time fix: TI and SYSTEM consoles now follow your dark theme (HKU\.DEFAULT AppsUseLightTheme=0)' -ForegroundColor DarkGray
        Write-Host '    the logon screen also follows it. revert: Set-ItemProperty "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Value 1' -ForegroundColor DarkGray
        $r = [Su.T]::BroadcastThemeChange()
        Write-Host "[D] theme broadcast: $r - any su console already on screen repaints dark within a second" -ForegroundColor DarkGray
    } catch { Write-Host "[D] service-theme write failed: $($_.Exception.Message)" -ForegroundColor DarkGray }
}
if ($script:DarkTheme) { Initialize-SuServiceTheme }

# v7.11: the child's polish status, relayed home. Three field rounds
# came back with no child-window output at all; the report now travels
# through a temp file and lands in THIS console, which is the one that
# gets pasted.
# v7.12: the relay now writes a heartbeat ('...: alive') before
# anything can fail, so this waiter polls until the FINAL status line
# lands (the heartbeat alone reads as 'started but never finished'), a
# missing relay file reports itself instead of returning silently, and
# both relay temp files are cleaned up afterwards.
function Wait-SuChildPolish {
    if (-not $script:DarkTheme) { return }
    if (-not $script:PolishLog) {
        Write-Host '[D] child polish relay: no relay file (temp setup failed) - child cannot report home' -ForegroundColor DarkGray
        return
    }
    $msg = $null
    $sawAlive = $false
    $deadline = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $deadline) {
        try { $msg = @(Get-Content -LiteralPath $script:PolishLog -TotalCount 1 -ErrorAction Stop)[0] } catch { $msg = $null }
        if ($msg) {
            $sawAlive = $true
            if ($msg -notmatch ': alive$') { break }
        }
        Start-Sleep -Milliseconds 250
    }
    if ($msg -and $msg -notmatch ': alive$') { Write-Host "[D] child polish relay: $msg" -ForegroundColor DarkGray }
    elseif ($sawAlive) { Write-Host '[D] child polish relay: started but never finished (compile died under that token?)' -ForegroundColor DarkGray }
    else { Write-Host '[D] child polish relay: no report in 8s (chain broken or token cannot write)' -ForegroundColor DarkGray }
    # v7.25 janitor: leave ONE TI window standing, and the tail tells the truth.
    try {
        $suDllJ = Join-Path $env:SystemRoot 'System32\su-polish.dll'
        if (Test-Path $suDllJ) {
            [Reflection.Assembly]::LoadFrom($suDllJ) | Out-Null
            $myHwndJ = [Polish]::GetConsoleWindow()
            $cwJ = @()
            foreach ($wJ in [Polish]::ListWindows()) {
                $pJ = $wJ -split ';', 5
                if ($pJ.Count -lt 5) { continue }
                if ($pJ[1] -notlike '*Console*') { continue }
                $cwJ += ,@($pJ)
            }
            $censJ = ($cwJ | ForEach-Object { $tJ = $_[4]; if ($tJ.Length -gt 20) { $tJ = $tJ.Substring(0, 20) }; '{0}/pid{1}/[{2}]' -f $_[1], $_[2], $tJ }) -join ' | '
            Write-Host "[D] v7.33 route census: $censJ" -ForegroundColor DarkGray
            $factsJ = @($script:SuRouteFacts | Where-Object { $_ })
            if ($factsJ.Count -gt 0) { Write-Host "[D] v7.33 route facts: $($factsJ -join '; ')" -ForegroundColor DarkGray }
            else { Write-Host '[D] v7.33 route facts: none collected (non-TI routes keep no facts - normal)' -ForegroundColor DarkGray }
            $tiJ = @($cwJ | Where-Object { $_[4] -like '*TrustedInstaller*' -and $_[3] -eq '1' -and ([IntPtr][int64]$_[0]) -ne $myHwndJ })
            # v7.26 janitor v2: AGE-GATED, never first-born. The v7.25 field
            # round proved the first-born rule inverted: it ranks
            # window-OWNER pids, so the wrapper always outdates the
            # inner TI cmd - the janitor closed the very console the
            # TI cmd lived in and kept the wrapper, which then
            # self-closed (brush exit -> wrapper cmd exit -> nobody
            # left). Rule now: a TI window whose owner process was
            # born BEFORE this route started is a leftover - close
            # it. A window born DURING this route is NEVER touched.
            $closedJ = 0
            $keptPidsJ = @()
            foreach ($t2J in $tiJ) {
                $owJ = 0
                $stJ2 = $null
                if ([int]::TryParse([string]$t2J[2], [ref]$owJ)) {
                    try { $stJ2 = (Get-Process -Id $owJ -ErrorAction Stop).StartTime } catch {}
                }
                if ($stJ2 -and $script:SuRouteStart -and ($stJ2 -lt $script:SuRouteStart)) {
                    $null = [Polish]::PostMessage([IntPtr][int64]$t2J[0], 0x10, [IntPtr]::Zero, [IntPtr]::Zero)
                    $closedJ++
                    $ageJ = [int]((Get-Date) - $stJ2).TotalSeconds
                    Write-Host "[i] v7.33: leftover TI window closed (pid $($t2J[2]), age ${ageJ}s - born before this route)" -ForegroundColor DarkGray
                } else {
                    $keptPidsJ += [string]$t2J[2]
                }
            }
            if ((-not $script:SuRouteStart) -and ($tiJ.Count -gt 0)) {
                Write-Host "[i] v7.33: route-start stamp missing - nothing closed (safe mode)" -ForegroundColor DarkGray
            }
            if ($keptPidsJ.Count -gt 0) {
                Write-Host "[i] v7.33: kept $($keptPidsJ.Count) this-route TI window(s) (pid $($keptPidsJ -join ',')) - never janitored" -ForegroundColor DarkGray
            }
        }
    } catch { Write-Host "[D] v7.33 route census failed: $($_.Exception.Message)" -ForegroundColor DarkGray }
    # v7.25 machinery self-report: what is ACTUALLY on disk decides the route.
    try {
        $selfJ = $PSCommandPath
        if ($selfJ -and (Test-Path $selfJ)) {
            $selfTxtJ = [IO.File]::ReadAllText($selfJ)
            $verJ = 'unknown'
            foreach ($vJ in @('v7.33','v7.33','v7.33','v7.33','v7.33','v7.26','v7.25','v7.24','v7.23','v7.22','v7.21','v7.20','v7.19','v7.18')) { if ($selfTxtJ.Contains($vJ)) { $verJ = $vJ; break } }
            $featJ = @()
            if ($selfTxtJ.Contains('Test-SuTitledWindow')) { $featJ += 'retry-gate' }
            if ($selfTxtJ.Contains('$spec.attached')) { $featJ += 'marker-file' }
            if ($selfTxtJ.Contains('v7.25 route census')) { $featJ += 'janitor' }
            if ($selfTxtJ.Contains('leftover TrustedInstaller window(s) before spawning')) { $featJ += 'sweep' }
            if ($selfTxtJ.Contains('GetConsoleProcessList')) { $featJ += 'proof-fix' }
            if ($selfTxtJ.Contains('launcher console retires')) { $featJ += 'launcher-retire' }
            if ($selfTxtJ.Contains('type cls to clean the shell')) { $featJ += 'cls-hint' }
            if ($selfTxtJ.Contains('Invoke-SuSpawnUserV733')) { $featJ += 'user-wrapper' }
            $dllVerJ = 'missing'
            try { $suDllV = Join-Path $env:SystemRoot 'System32\su-polish.dll'; if (Test-Path $suDllV) { [Reflection.Assembly]::LoadFrom($suDllV) | Out-Null; $dllVerJ = [Polish]::Ver() } } catch {}
            Write-Host "[D] v7.33 machinery: on-disk=$verJ dll=$dllVerJ features=$($featJ -join ',')" -ForegroundColor DarkGray
        }
    } catch {}
    foreach ($f in @($script:PolishLog, $script:RelayScript)) {
        try { if ($f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } } catch {}
    }
}

function Polish-Console([string]$Title) {
    try {
        $r = [Su.T]::PolishConsoleWindow($Title, $script:DarkTheme, 4000)
        # v7.10: 'refused ... E_HANDLE' is the DESIGNED outcome for
        # SYSTEM/TI-owned windows (the child self-polishes and reports
        # there), so the parent stays quiet about it instead of printing
        # a line that reads like a failure. Only a real 'ok' is news.
        if ($r -like 'ok*') { Write-Host "[D] window polish: $r" -ForegroundColor DarkGray }
    } catch { Write-Host "[D] window polish: $_" -ForegroundColor DarkGray }
    Wait-SuChildPolish
    # v7.33 LAUNCHER RETIRE: green route -> the console su was typed in
    # closes itself; the shell window stays the only window on the desktop.
    # Census first: a live VISIBLE classic console carrying this route
    # title that is NOT this window. No proof / this console is not a real
    # conhost window (Windows Terminal tab, hidden host) / SU_KEEP_LAUNCHER
    # is 1 -> it stays open and says why. 3s grace so the tail can be read.
    try {
        $suDllR = Join-Path $env:SystemRoot 'System32\su-polish.dll'
        if (Test-Path $suDllR) {
            [Reflection.Assembly]::LoadFrom($suDllR) | Out-Null
            $myR = [Polish]::GetConsoleWindow()
            $shellLiveR = $false
            foreach ($wR in [Polish]::ListWindows()) {
                $pR = $wR -split ';', 5
                if ($pR.Count -lt 5) { continue }
                if ($pR[3] -ne '1') { continue }
                if ($pR[1] -notlike '*Console*') { continue }
                if ($pR[4] -notlike "*$Title*") { continue }
                if ([IntPtr][int64]$pR[0] -eq $myR) { continue }
                $shellLiveR = $true
                break
            }
            $keepR = $false
            try { $keepR = ($env:SU_KEEP_LAUNCHER -eq '1') } catch {}
            if ($keepR) {
                Write-Host '[i] v7.33: SU_KEEP_LAUNCHER=1 - this launcher console stays open' -ForegroundColor DarkGray
            } elseif (-not $shellLiveR) {
                Write-Host '[i] v7.33: shell window not confirmed live - this launcher console stays open' -ForegroundColor DarkGray
            } else {
                $clsR = ''
                $visR = $false
                if ($myR -ne [IntPtr]::Zero) {
                    $sbR = New-Object System.Text.StringBuilder(64)
                    $null = [Polish]::GetClassName($myR, $sbR, 64)
                    $clsR = $sbR.ToString()
                    $visR = [Polish]::IsWindowVisible($myR)
                }
                if ($clsR -eq 'ConsoleWindowClass' -and $visR) {
                    Write-Host '[i] v7.33: shell is live - this launcher console retires in 3s (the shell window is the only window left)' -ForegroundColor DarkGray
                    Start-Sleep -Seconds 3
                    $null = [Polish]::PostMessage($myR, 0x10, [IntPtr]::Zero, [IntPtr]::Zero)
                } else {
                    Write-Host "[i] v7.33: shell is live - close this console yourself (class=$clsR vis=$visR - not a classic conhost window)" -ForegroundColor DarkGray
                }
            }
        }
    } catch {}
}

# v7.6: the self-polish runs as the first command inside the new window,
# on the same token as the console window's owner (conhost) - the one DWM
# accepts attribute calls from. Base64-encoded to dodge every cmd/PS
# quoting rule, chained with '&' (not '&&') so a failure never blocks the
# shell, wrapped in try/catch so the worst case is one extra [D] line.
# v7.7 hardening - the ninth live run caught the v7.6 form redirecting
# TEMP to C:\Windows\Temp, which the spawned user token could not use
# (csc died with CS2001 'cannot find source file' and sprayed red errors
# into the brand-new shell): the polish now PROBES for a temp dir this
# very token can create+read+delete in (its own GetTempPath() first, then
# C:\Windows\Temp - csc needs all three rights), runs with a Silently-
# Continue error preference plus -ErrorAction Stop so a failure is ONE
# gray [D] line instead of a red error display, skips silently when no
# dir works (it is cosmetic - it must never get in the shell's way),
# clears the base64 title-bar flash, and nudges the frame with SetWindow-
# Pos so the recolored title bar repaints immediately.
# v7.8: GetConsoleWindow lives in kernel32.dll, NOT user32.dll - the
# v7.6/v7.7 form imported it from user32 and the first call died with
# EntryPointNotFoundException ('Impossible de trouver le point d'entree')
# as soon as the v7.7 temp probe let Add-Type compile at all. The import
# now points at kernel32; SetWindowPos (user32) and DwmSetWindowAttribute
# (dwmapi) were already right.
# v7.9: the skip path reports itself too now - a dark-theme spawn always
# prints exactly one self-polish status line (dark= / exception / skipped),
# so one paste of the new window's first line settles any report.
# v7.10: caption AND title-text color are set explicitly now too (attrs
# 35/36): an explicit caption color pinned by the console host overrides
# the immersive-dark flag, which is exactly how 'dark=0x0' can coexist
# with a still-light bar. The status line reports all three HRESULTs and
# carries the version, so a stale-bytes report outs itself in one glance
# (txt=0xFFFFFFFF means 'not attempted' - both color sets were refused).
# v7.11: the status line is RELAYED to the parent console too - the child
# writes it to a temp file (Users:Modify grant so any token can write)
# and the parent prints it as '[D] child polish relay: ...' after the
# spawn. Read-backs gb20/gb35 tell whether DWM even stored the values
# when the bar still paints light; FFFFFFFF = not readable/not set.
# v7.12: the relay runs from a granted temp .ps1 via -File (not b64),
# heartbeats before anything can fail, fingerprints its host window
# (class/owner/visible), paints the REAL window on the classic path
# (the conhost.exe prefix makes that the normal case), rehosts into a
# classic dark window when the console still got delegated, and every
# outcome reports home through the relay file.
# v7.13: with .DEFAULT now dark, conhost paints the bar itself at window
# creation - the relay is belt-and-braces: it replicates conhost's own
# recipe on the live window (SetWindowTheme 'DarkMode_Explorer' - the
# piece fourteen rounds never tried - plus attr 19/20 and the caption
# colors) and sends WM_THEMECHANGED straight to the window so the owner
# re-runs its theming code. Status line gains thm=/a19=; gb35 is dropped
# (field-proven unreadable).
$selfPolishScript = @'
$polishLog = '$POLISH_LOG$'
$suTitle = '$SU_TITLE$'
function Su-Report([string]$m) { try { Set-Content -LiteralPath $polishLog -Value $m -Encoding Unicode } catch {}; $m }
Su-Report '[D] self-polish v7.33: alive'
try { [Console]::Title = $suTitle } catch {}
# NOTE: no $ErrorActionPreference='SilentlyContinue' here - v7.13's silent
# preference is exactly how the Add-Type death went unreported for 3 rounds.
# cmd /c color 07 already ran (spawn-line floor); this layer adds Campbell.
try {
    $h = [IntPtr]::Zero
    $own = ''; $cls = ''; $vis = $false
    $dll = "$env:SystemRoot\System32\su-polish.dll"
    if (-not (Test-Path $dll)) {
        Su-Report '[D] self-polish v7.33: su-polish.dll missing - floor color 07 active (run su-polish-build.ps1 elevated)'
    } else {
        [Reflection.Assembly]::LoadFrom($dll) | Out-Null
        $h = [Polish]::GetConsoleWindow()
        if ($h -ne [IntPtr]::Zero) {
            $sb = New-Object System.Text.StringBuilder(64)
            $null = [Polish]::GetClassName($h, $sb, 64)
            $cls = $sb.ToString()
            $opid = 0
            $null = [Polish]::GetWindowThreadProcessId($h, [ref]$opid)
            $vis = [Polish]::IsWindowVisible($h)
            if ($opid -gt 0) { try { $own = (Get-Process -Id $opid -ErrorAction SilentlyContinue).ProcessName } catch {} }
        }
        $stdout = [Polish]::GetStdHandle(-11)
        $campbell = [uint32[]]@(0x0C0C0C,0xDA3700,0x0EA113,0xDD963A,0x1F0FC5,0x981788,0x009CC1,0xCCCCCC,
                                 0x767676,0xFF783B,0x0CC616,0xD6D661,0x5648E7,0x9E00B4,0xA5F1F9,0xF2F2F2)
        $info = New-Object Polish+CONSOLE_SCREEN_BUFFER_INFOEX
        $info.cbSize = [uint32][Runtime.InteropServices.Marshal]::SizeOf([type][Polish+CONSOLE_SCREEN_BUFFER_INFOEX])
        $okGet = [Polish]::GetConsoleScreenBufferInfoEx($stdout, [ref]$info)
        $okSet = $false
        if ($okGet) {
            for ($i = 0; $i -lt 16; $i++) { $info.ColorTable[$i] = $campbell[$i] }
            $info.wAttributes = 0x07
            $info.srWindow.Right  = [int16]($info.srWindow.Right  + 1)
            $info.srWindow.Bottom = [int16]($info.srWindow.Bottom + 1)
            $okSet = [Polish]::SetConsoleScreenBufferInfoEx($stdout, [ref]$info)
        }
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [void][Polish]::SetConsoleTextAttribute($stdout, 0x07)
        $dark0 = $false
        try { $dark0 = ([Polish]::CheckDark($h) -like 'g20=1/*') } catch {}
        if ($dark0) {
            $hr20 = 0
        } else {
            $one = 1
            $hr20 = [Polish]::DwmSetWindowAttribute($h, 20, [ref]$one, 4)
        }
        Su-Report ('[D] self-polish v7.33: owner={0} class={1} vis={2} hwnd=0x{3:X} get={4} set={5} err={6} dwm20=0x{7:X8} dark0={8}' -f $own, $cls, $vis, $h.ToInt64(), $okGet, $okSet, $err, $hr20, $dark0)
    }
} catch { Su-Report ('[D] self-polish v7.33: ' + $_.Exception.Message) }
'@
function New-SuCmdLine([string]$Title, [string]$TargetSid, [switch]$Plain) {
    # v7.12: two changes. First, the child line is 'conhost.exe cmd.exe
    # /k ...' (unless -Plain) - starting conhost.exe directly with the
    # client command line forces a CLASSIC ConsoleWindowClass window even
    # when the default terminal is Windows Terminal. That delegation was
    # the fourteenth-round root cause: GetConsoleWindow inside the spawned
    # shell returned a hidden proxy window owned by cmd.exe itself (the
    # pseudoconsole signature - 'owner=cmd' in the watchdog field line),
    # so every DWM paint since v7.6 colored an invisible window while the
    # real one stayed light. Second, the polish relay ships as a granted
    # temp .ps1 run via -File, not a 6.5KB -EncodedCommand blob: the child
    # line drops to ~160 chars, the relay is readable in temp for audit,
    # and the 8191-char cmd ceiling the v7.12 relay would have broken is
    # gone. Called once per route (plus the -Plain retry inside
    # Invoke-SuSpawn); the relay pair is created on the first call only.
    $self = ''
    if ($script:DarkTheme -and -not $script:RelayScript) {
        # v7.11/v7.12 relay pair: su-<32hex>.relay.ps1 (the polish script
        # the child READS) + su-<32hex>.polish (the status line the child
        # WRITES and Wait-SuChildPolish reads home). Both in the caller's
        # temp, each with explicit Modify ACEs for Users (S-1-5-32-545),
        # SYSTEM (S-1-5-18), Administrators (S-1-5-32-544) and the target
        # SID - a foreign token is in none of the inherited ACEs (TI is
        # not even a member of Users), and counting on SeRestore's DACL
        # bypass was unproven in the field.
        try {
            $base = 'su-' + [Guid]::NewGuid().ToString('N')
            $script:RelayScript = Join-Path ([IO.Path]::GetTempPath()) ($base + '.relay.ps1')
            $script:PolishLog = Join-Path ([IO.Path]::GetTempPath()) ($base + '.polish')
            $grants = @('S-1-5-32-545', 'S-1-5-18', 'S-1-5-32-544')
            if ($TargetSid) { $grants += $TargetSid }
            foreach ($f in @($script:RelayScript, $script:PolishLog)) {
                New-Item -ItemType File -Path $f -Force | Out-Null
                $acl = Get-Acl $f
                foreach ($sid in $grants) {
                    $rule = New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), 'Modify', 'Allow')
                    $acl.AddAccessRule($rule)
                }
                Set-Acl -Path $f -AclObject $acl
            }
            $safeTitle = $Title.Replace("'", "''")
             $centralRelay = Join-Path $env:windir 'System32\su-relay.ps1'
            if (Test-Path $centralRelay) { $selfPolishScript = [IO.File]::ReadAllText($centralRelay) }
            [IO.File]::WriteAllText($script:RelayScript, $selfPolishScript.Replace('$POLISH_LOG$', $script:PolishLog).Replace('$SU_TITLE$', $safeTitle), (New-Object System.Text.UTF8Encoding($true)))
        } catch { $script:RelayScript = $null; $script:PolishLog = $null }
    }
    if ($script:DarkTheme -and $script:RelayScript) {
        $self = 'powershell -NoProfile -ExecutionPolicy Bypass -File "' + $script:RelayScript + '" & '
    }
    $prefix = ''
    if (-not $Plain) { $prefix = 'conhost.exe ' }
    return "$($prefix)cmd.exe /k color 07 & $($self)title $Title && whoami /user & echo. & echo [i] type cls to clean the shell"
}

function Test-SuShellAlive([string]$Title) {
    # v7.12: liveness proof for the forced-classic spawn. The relay
    # heartbeat (the first thing the relay writes) shows the whole
    # conhost+cmd+powershell chain ran under the target token; a console
    # window whose caption carries the title covers the light-theme case
    # (no relay then). A fresh ConsoleWindowClass with the WRONG caption -
    # a conhost that ignored its argv - proves nothing and must not block
    # the plain-line fallback inside Invoke-SuSpawn.
    if ($script:PolishLog) {
        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline) {
            $m = $null
            try { $m = @(Get-Content -LiteralPath $script:PolishLog -TotalCount 1 -ErrorAction Stop)[0] } catch { $m = $null }
            if ($m) { return $true }
            Start-Sleep -Milliseconds 200
        }
    }
    $r = [Su.T]::PolishConsoleWindow($Title, $script:DarkTheme, 2000)
    if (($r -like 'ok*' -or $r -like 'refused*') -and $r -match [regex]::Escape($Title)) { return $true }
    return $false
}

function Test-SuTitledWindow([string]$Title) {
    # v7.24 census helper: a VISIBLE top-level window already carrying
    # this route title (the shell sets it with its own title command,
    # the relay with [Console]::Title) proves the shell is alive -
    # independent of the relay write-home timing.
    try {
        $suDll = "$env:SystemRoot\System32\su-polish.dll"
        if (Test-Path $suDll) { [Reflection.Assembly]::LoadFrom($suDll) | Out-Null }
        foreach ($w in [Polish]::ListWindows()) {
            $p = $w -split ';', 5
            if ($p.Count -lt 5) { continue }
            if ($p[3] -ne '1') { continue }
            if ($p[4] -like "*$Title*") { return $true }
        }
    } catch {}
    return $false
}

function Invoke-SuSpawn([IntPtr]$Token, [int]$WlPid, [string]$Title, [string]$TargetSid, [IntPtr]$Env) {
    # v7.12: forced-classic spawn with a self-healing fallback. Try the
    # conhost.exe-forced line first; if the CreateProcess fails, or if no
    # shell shows life within the liveness window (a conhost.exe quirk
    # would leave NO shell at all), retry once with the plain v7.11-style
    # line - worst case is the previous known-good behavior, never a
    # dead spawn. All 7 spawn routes go through here.
    $forced = New-SuCmdLine $Title $TargetSid
    $spawn = [Su.T]::SpawnWithToken($Token, $forced, $Title, $Env)
    if ($spawn -ne 'OK') { $spawn = [Su.T]::SpawnAsUser($Token, $WlPid, $forced, $Title, $Env) }
    if ($spawn -eq 'OK' -and (Test-SuShellAlive $Title)) { return 'OK' }
    if ($spawn -eq 'OK') {
        # v7.24: the relay heartbeat is not the only proof of life. cmd sets
        # the title UNCONDITIONALLY after the relay ('&' never blocks on
        # it), so a visible window already carrying this route title IS
        # the live shell. Poll up to 15s before ever considering a second
        # window - the plain retry was the OLD window in every
        # double-window report (owner=cmd: the plain-line signature).
        $cens = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $cens) {
            if (Test-SuTitledWindow $Title) {
                $script:SuRouteFacts += 'retry-gate=skipped'
                Write-Host '[D] v7.33: census - a console titled like this route is already alive - plain retry skipped' -ForegroundColor DarkGray
                return 'OK'
            }
            Start-Sleep -Milliseconds 500
        }
    }
    if ($spawn -eq 'OK') {
        Write-Host '[D] forced-console spawn showed no life - retrying with the plain console line' -ForegroundColor DarkGray
    } else {
        Write-Host "[D] forced-console spawn failed: $spawn - retrying with the plain console line" -ForegroundColor DarkGray
    }
    $plain = New-SuCmdLine $Title $TargetSid -Plain
    $spawn2 = [Su.T]::SpawnWithToken($Token, $plain, $Title, $Env)
    if ($spawn2 -ne 'OK') { $spawn2 = [Su.T]::SpawnAsUser($Token, $WlPid, $plain, $Title, $Env) }
    if ($spawn2 -ne 'OK') {
        foreach ($f in @($script:RelayScript, $script:PolishLog)) {
            try { if ($f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } } catch {}
        }
        return $spawn2
    }
    return 'OK'
}

# --- main dispatch ---

# ---- v7.19 wrapper/inner-drop machinery (inserted by su-fix-v7.19.ps1) ----
# Seventeen rounds proved conhost-under-a-foreign-token custom-draws a LIGHT
# caption no matter what anyone sets on its window: DWM attributes return
# S_OK and read back stored (gb20=1) yet never render, SetWindowTheme,
# frame nudges and WM_THEMECHANGED change nothing, and the .DEFAULT /
# S-1-5-18 theme bakes never reached the host's own reading. v7.19 stops
# asking and changes the OWNER instead: the TI cmd is dropped INTO a
# wrapper console created under YOUR elevated token - conhost-under-you
# reads YOUR dark theme, so the window is dark BY CONSTRUCTION. Outer
# route: spawn 'conhost.exe powershell su-sys.ps1 -InnerDrop -InnerSpec
# <file>' as you (a new console); the inner run re-mints the TI token and
# CreateProcessWithTokenW's the TI cmd WITHOUT CREATE_NEW_CONSOLE so it
# inherits that console (verified live via GetConsoleProcessList). Every
# failure falls back to the classic direct spawn - never a dead spawn.
function Invoke-SuSpawnV719([IntPtr]$Token, [int]$WlPid, [string]$Title, [string]$TargetSid, [IntPtr]$Env) {
    # v7.21 ROOT CAUSE: the v7.19/v7.20 gate tested $script:RelayScript before
    # anything created it (New-SuCmdLine is what makes the relay pair), so every
    # run silently took the direct-spawn fallback - the wrapper never ran once.
    # v7.21: payload first, gate on the theme only.
    $plain = New-SuCmdLine $Title $TargetSid -Plain
    if (-not $script:DarkTheme -or -not $script:RelayScript) {
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    $spec = $null
    try {
        $spec = Join-Path ([IO.Path]::GetTempPath()) ('su-' + [Guid]::NewGuid().ToString('N') + '.inner')
        [IO.File]::WriteAllText($spec, $plain + "`r`n" + $script:PolishLog)
    } catch { $spec = $null }
    $dll = Join-Path $env:SystemRoot 'System32\su-polish.dll'
    if (-not $spec -or -not (Test-Path $dll)) {
        if ($spec) { try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {} }
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    $loaded = $false
    try { [Reflection.Assembly]::LoadFrom($dll) | Out-Null; $loaded = $true } catch {}
    if (-not $loaded) {
        try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {}
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    $suSys = $PSCommandPath
    if (-not $suSys) { $suSys = Join-Path $env:SystemRoot 'System32\su-sys.ps1' }
    $wrapper = 'conhost.exe cmd.exe /d /k powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $suSys + '" -Account TrustedInstaller -InnerDrop -InnerSpec "' + $spec + '" & exit'
    $w = $null
    try { $w = [Polish]::SpawnWrapperUser($wrapper, $Title) } catch { $w = 'F:call:' + $_.Exception.Message }
    $script:SuRouteFacts += "wrapper=$w"
    if ($w -ne 'OK') {
        Write-Host "[D] v7.33 wrapper spawn: $w - using the direct spawn" -ForegroundColor DarkGray
        try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {}
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    Write-Host '[*] v7.33: wrapper console open (born a cmd window, dark by construction) - the TI cmd will land inside it' -ForegroundColor DarkGray
    $verdict = $null
    $saw = '(nothing)'
    $marker = "$spec.attached"
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not $verdict) {
        if (Test-Path -LiteralPath $marker) { $verdict = 'ok' }
        $m = $null
        try { $m = @(Get-Content -LiteralPath $script:PolishLog -TotalCount 1 -ErrorAction Stop)[0] } catch { $m = $null }
        if ($m) {
            $saw = $m
            if ($m -like '*WRAPPER-INHERIT-FAILED*') { $verdict = 'failed' }
            elseif ($m -ne '[D] self-polish v7.33: alive') {
                Start-Sleep -Seconds 2
                $m2 = $null
                try { $m2 = @(Get-Content -LiteralPath $script:PolishLog -TotalCount 1 -ErrorAction Stop)[0] } catch {}
                if ($m2 -like '*WRAPPER-INHERIT-FAILED*') { $verdict = 'failed' }
                # v7.26: only the marker may say ok - a relay line alone is
                # not success (the log is last-writer-wins; a stray console
                # wrote it in the v7.25 field round while the TI cmd had
                # never attached to the wrapper). Keep polling; the marker
                # or the 30s timeout decides.
            }
        }
        if (-not $verdict) { Start-Sleep -Milliseconds 250 }
    }
    try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {}
    if (-not $verdict -and (Test-Path -LiteralPath $marker)) { $verdict = 'ok' }
    if (-not $verdict) {
        $evid = ""
        try {
            foreach ($w2 in [Polish]::ListWindows()) {
                $p2 = $w2 -split ';', 5
                if ($p2.Count -lt 5) { continue }
                if ($p2[3] -ne '1') { continue }
                if ($p2[4] -like '*TrustedInstaller*') { $evid = $w2; break }
            }
        } catch {}
        if ($evid) {
            Write-Host "[D] v7.33: relay silent but the TI window is ALIVE (evid: $evid) - no direct spawn" -ForegroundColor DarkGray
            $verdict = 'ok'
        }
    }
    try { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue } catch {}
    $script:SuRouteFacts += "verdict=$verdict"
    if ($verdict -eq 'ok') { return 'OK' }
    if ($verdict -eq 'failed') {
        Write-Host '[D] v7.33: the TI cmd could not attach to the wrapper console - direct spawn instead' -ForegroundColor DarkGray
    } else {
        Write-Host "[D] v7.33: wrapper route silent for 30s (last seen: $saw) - direct spawn instead" -ForegroundColor DarkGray
    }
    foreach ($f in @($script:PolishLog, $script:RelayScript)) {
        try { if ($f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } } catch {}
    }
    $script:PolishLog = $null
    $script:RelayScript = $null
    return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
}

if ($InnerDrop) {
    try {
        if (-not $InnerSpec -or -not (Test-Path $InnerSpec)) { Write-Host '[!] inner: spec file missing'; exit 1 }
        $specLines = [IO.File]::ReadAllLines($InnerSpec)
        $innerCmd = $specLines[0]
        $innerLog = $specLines[1]
        $wl2 = Get-WinlogonInMySession
        if (-not $wl2) { try { Set-Content -LiteralPath $innerLog -Value '[D] self-polish v7.33: WRAPPER-INHERIT-FAILED (no winlogon in this session)' -Encoding Unicode } catch {}; Write-Host '[!] inner: no winlogon.exe in this session'; exit 1 }
        $mySession2 = [uint32]((Get-Process -Id $PID).SessionId)
        $TISID2 = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        $craftPids2 = Get-CraftSourcePids $wl2
        $tok2 = [IntPtr]::Zero
        $res2 = [Su.T]::CreateTokenForSid($TISID2, $null, 'TI', $craftPids2, $mySession2, [ref]$tok2)
        $okIdent = $false
        if ($res2 -eq 'OK') { try { $okIdent = [Su.T]::TokenUserIs($tok2, $TISID2) } catch {} }
        if (-not $okIdent) {
            try { Set-Content -LiteralPath $innerLog -Value '[D] self-polish v7.33: WRAPPER-INHERIT-FAILED (craft)' -Encoding Unicode } catch {}
            Write-Host "[!] inner: TI craft failed: $res2"
            exit 1
        }
        $null = [Su.T]::GrantDesktopAsSystem($wl2.ProcessId, $TISID2)
        $env2 = [IntPtr]::Zero
        $null = [Su.T]::MakeEnvBlock($tok2, [ref]$env2)
        $dll2 = Join-Path $env:SystemRoot 'System32\su-polish.dll'
        [Reflection.Assembly]::LoadFrom($dll2) | Out-Null
        Write-Host '[*] inner: TI token minted - dropping the TI cmd into THIS console...'
        # v7.22: no frame paint on the wrapper console - dark by construction (icon-safe).
        $r2 = $null
        try { $r2 = [Polish]::SpawnInheritAsUser($tok2, $wl2.ProcessId, $innerCmd, $env2) } catch { $r2 = 'F:call:' + $_.Exception.Message }
        if ($r2 -like 'F:*') {
            Write-Host "[D] inner: as-user drop failed ($r2) - retrying via seclogon"
            try { $r2 = [Polish]::SpawnInherit($tok2, $innerCmd, $env2) } catch { $r2 = 'F:call:' + $_.Exception.Message }
        }
        if ($env2 -ne [IntPtr]::Zero) { [void][Su.T]::FreeEnvBlock($env2) }
        try { Remove-Item -LiteralPath $InnerSpec -Force -ErrorAction SilentlyContinue } catch {}
        if ($r2 -like 'F:*') {
            try { Set-Content -LiteralPath $innerLog -Value '[D] self-polish v7.33: WRAPPER-INHERIT-FAILED' -Encoding Unicode } catch {}
            Write-Host "[!] inner drop failed: $r2"
            exit 1
        }
        try { Set-Content -LiteralPath $innerLog -Value '[D] inner: attached' -Encoding Unicode } catch {}
        try { Set-Content -LiteralPath ($InnerSpec + '.attached') -Value 'attached' -Encoding Ascii } catch {}
        Write-Host '[i] inner: TI cmd attached to this console - the window is now the TI cmd; brush exits'
        exit 0
    } catch {
        try { if ($innerLog) { Set-Content -LiteralPath $innerLog -Value ('[D] self-polish v7.33: WRAPPER-INHERIT-FAILED (crash: ' + $_.Exception.Message + ')') -Encoding Unicode } } catch {}
        Write-Host "[!] inner drop crashed: $($_.Exception.Message)"
        exit 1
    }
}
# ---- v7.33 user wrapper machinery (inserted by su-fix-v7.33.ps1) ----
# The field rounds proved the look follows the token that CREATES the
# console: TI windows are born under YOUR dark admin token (the wrapper)
# and stay dark; sys windows are born under SYSTEM (the baked dark hive)
# and stay dark; user windows were born under the TARGET user's token -
# and a light-theme user (HKCU=1 in the relay line) got an old-looking
# window every time, because no after-paint survives conhost re-rendering
# its frame on the 'title' command. Same machinery as TI now: a console
# born under YOUR token (dark by construction, real cmd icon), the user
# cmd dropped INSIDE it via an inner S4U re-mint. Any failure falls back
# to the classic direct spawn - never a dead spawn, never a regression.
function Invoke-SuSpawnUserV733([IntPtr]$Token, [int]$WlPid, [string]$Title, [string]$TargetSid, [IntPtr]$Env, [string]$UserName, [string]$UserDomain) {
    # v7.33: payload first, gate on the theme only (the v7.21 lesson).
    $plain = New-SuCmdLine $Title $TargetSid -Plain
    if (-not $script:DarkTheme -or -not $script:RelayScript) {
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    $spec = $null
    try {
        $spec = Join-Path ([IO.Path]::GetTempPath()) ('su-' + [Guid]::NewGuid().ToString('N') + '.inneru')
        $domU = $UserDomain
        if (-not $domU) { $domU = $env:COMPUTERNAME }
        [IO.File]::WriteAllText($spec, $plain + "`r`n" + $script:PolishLog + "`r`n" + $UserName + "`r`n" + $domU + "`r`n" + $TargetSid)
    } catch { $spec = $null }
    $dll = Join-Path $env:SystemRoot 'System32\su-polish.dll'
    if (-not $spec -or -not (Test-Path $dll)) {
        if ($spec) { try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {} }
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    $loaded = $false
    try { [Reflection.Assembly]::LoadFrom($dll) | Out-Null; $loaded = $true } catch {}
    if (-not $loaded) {
        try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {}
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    $suSys = $PSCommandPath
    if (-not $suSys) { $suSys = Join-Path $env:SystemRoot 'System32\su-sys.ps1' }
    $wrapper = 'conhost.exe cmd.exe /d /k powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $suSys + '" -Account User -TargetUser "' + $UserName + '" -InnerUserDrop -InnerSpec "' + $spec + '" & exit'
    $w = $null
    try { $w = [Polish]::SpawnWrapperUser($wrapper, $Title) } catch { $w = 'F:call:' + $_.Exception.Message }
    $script:SuRouteFacts += "user-wrapper=$w"
    if ($w -ne 'OK') {
        Write-Host "[D] v7.33 user wrapper spawn: $w - using the direct spawn" -ForegroundColor DarkGray
        try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {}
        return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
    }
    Write-Host '[*] v7.33: user wrapper console open (born a cmd window under YOUR dark theme) - the user cmd will land inside it' -ForegroundColor DarkGray
    # v7.23/v7.26 verdict design kept: ONLY the marker file may say ok
    # ($spec.attached, written by the inner the moment the user cmd is
    # proven attached); WRAPPER-INHERIT-FAILED says failed; anything else
    # keeps polling to the 30s timeout, then the live-window census has
    # the last word before any direct spawn.
    $verdict = $null
    $saw = '(nothing)'
    $marker = "$spec.attached"
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not $verdict) {
        if (Test-Path -LiteralPath $marker) { $verdict = 'ok' }
        $m = $null
        try { $m = @(Get-Content -LiteralPath $script:PolishLog -TotalCount 1 -ErrorAction Stop)[0] } catch { $m = $null }
        if ($m) {
            $saw = $m
            if ($m -like '*WRAPPER-INHERIT-FAILED*') { $verdict = 'failed' }
        }
        if (-not $verdict) { Start-Sleep -Milliseconds 250 }
    }
    try { Remove-Item -LiteralPath $spec -Force -ErrorAction SilentlyContinue } catch {}
    if (-not $verdict -and (Test-Path -LiteralPath $marker)) { $verdict = 'ok' }
    if (-not $verdict) {
        $evid = ''
        try {
            foreach ($w2 in [Polish]::ListWindows()) {
                $p2 = $w2 -split ';', 5
                if ($p2.Count -lt 5) { continue }
                if ($p2[3] -ne '1') { continue }
                if ($p2[4] -like "*$Title*") { $evid = $w2; break }
            }
        } catch {}
        if ($evid) {
            Write-Host "[D] v7.33: relay silent but the user window is ALIVE (evid: $evid) - no direct spawn" -ForegroundColor DarkGray
            $verdict = 'ok'
        }
    }
    try { Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue } catch {}
    $script:SuRouteFacts += "user-verdict=$verdict"
    if ($verdict -eq 'ok') { return 'OK' }
    if ($verdict -eq 'failed') {
        Write-Host '[D] v7.33: the user cmd could not attach to the wrapper console - direct spawn instead' -ForegroundColor DarkGray
    } else {
        Write-Host "[D] v7.33: user wrapper route silent for 30s (last seen: $saw) - direct spawn instead" -ForegroundColor DarkGray
    }
    foreach ($f in @($script:PolishLog, $script:RelayScript)) {
        try { if ($f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } } catch {}
    }
    $script:PolishLog = $null
    $script:RelayScript = $null
    return (Invoke-SuSpawn $Token $WlPid $Title $TargetSid $Env)
}

if ($InnerUserDrop) {
    try {
        if (-not $InnerSpec -or -not (Test-Path $InnerSpec)) { Write-Host '[!] inner: spec file missing'; exit 1 }
        $specU = [IO.File]::ReadAllLines($InnerSpec)
        $innerCmd = $specU[0]
        $innerLog = $specU[1]
        $innerUser = $specU[2]
        $innerDom = $specU[3]
        $innerSid = $specU[4]
        if (-not $innerDom) { $innerDom = $env:COMPUTERNAME }
        $wl2 = Get-WinlogonInMySession
        if (-not $wl2) { try { Set-Content -LiteralPath $innerLog -Value '[D] self-polish v7.33: WRAPPER-INHERIT-FAILED (no winlogon in this session)' -Encoding Unicode } catch {}; Write-Host '[!] inner: no winlogon.exe in this session'; exit 1 }
        $mySession2 = [uint32]((Get-Process -Id $PID).SessionId)
        # inner S4U re-mint: the wrapper console was born under the ADMIN
        # token; the user token is minted HERE (machine-name domain, lt=3,
        # flags=0 - the field-proven form), session-rewritten to this one.
        $tok2 = [IntPtr]::Zero
        $res2 = [Su.T]::S4ULogon($wl2.ProcessId, $innerUser, $innerDom, [ref]$tok2)
        if ($res2 -notlike 'OK:*') {
            try { Set-Content -LiteralPath $innerLog -Value ('[D] self-polish v7.33: WRAPPER-INHERIT-FAILED (s4u: ' + $res2 + ')') -Encoding Unicode } catch {}
            Write-Host "[!] inner: user S4U failed: $res2"
            exit 1
        }
        $finalTok2 = [IntPtr]::Zero
        $r3 = [Su.T]::RewriteTokenSession($tok2, $wl2.ProcessId, $mySession2, [ref]$finalTok2)
        if ($r3 -eq 'OK') { $tok2 = $finalTok2 }
        $null = [Su.T]::GrantDesktopAsSystem($wl2.ProcessId, $innerSid)
        $env2 = [IntPtr]::Zero
        $null = [Su.T]::MakeEnvBlock($tok2, [ref]$env2)
        $dll2 = Join-Path $env:SystemRoot 'System32\su-polish.dll'
        [Reflection.Assembly]::LoadFrom($dll2) | Out-Null
        Write-Host "[*] inner: $innerUser token minted - dropping the user cmd into THIS console..."
        # v7.22 kept: NO frame paint on the wrapper console - it is dark by
        # construction (born under YOUR dark token). Re-painting a healthy
        # conhost frame is the prime suspect for the scrambled-icon round.
        $r2 = $null
        try { $r2 = [Polish]::SpawnInheritAsUser($tok2, $wl2.ProcessId, $innerCmd, $env2) } catch { $r2 = 'F:call:' + $_.Exception.Message }
        if ($r2 -like 'F:*') {
            Write-Host "[D] inner: as-user drop failed ($r2) - retrying via seclogon"
            try { $r2 = [Polish]::SpawnInherit($tok2, $innerCmd, $env2) } catch { $r2 = 'F:call:' + $_.Exception.Message }
        }
        if ($env2 -ne [IntPtr]::Zero) { [void][Su.T]::FreeEnvBlock($env2) }
        try { Remove-Item -LiteralPath $InnerSpec -Force -ErrorAction SilentlyContinue } catch {}
        if ($r2 -like 'F:*') {
            try { Set-Content -LiteralPath $innerLog -Value '[D] self-polish v7.33: WRAPPER-INHERIT-FAILED' -Encoding Unicode } catch {}
            Write-Host "[!] inner drop failed: $r2"
            exit 1
        }
        try { Set-Content -LiteralPath $innerLog -Value '[D] inner: attached' -Encoding Unicode } catch {}
        try { Set-Content -LiteralPath ($InnerSpec + '.attached') -Value 'attached' -Encoding Ascii } catch {}
        Write-Host "[i] inner: $innerUser cmd attached to this console - the window is now the user shell; brush exits"
        exit 0
    } catch {
        try { if ($innerLog) { Set-Content -LiteralPath $innerLog -Value ('[D] self-polish v7.33: WRAPPER-INHERIT-FAILED (crash: ' + $_.Exception.Message + ')') -Encoding Unicode } } catch {}
        Write-Host "[!] inner user drop crashed: $($_.Exception.Message)"
        exit 1
    }
}

switch ($Account) {

    'User' {
        if (-not $TargetUser) {
            Write-Host '[!] -TargetUser is required for -Account User' -ForegroundColor Red
            exit 1
        }

        # parse DOMAIN\user or user@domain
        $domain = ''
        $user = $TargetUser
        if ($TargetUser -match '^(.+?)\\(.+)$') {
            $domain = $matches[1]
            $user = $matches[2]
        } elseif ($TargetUser -match '^(.+?)@(.+)$') {
            $user = $matches[1]
            $domain = $matches[2]
        }
        $targetName = if ($domain) { "$domain\$user" } else { $user }

        # resolve the target to a SID
        try {
            $sidObj = (New-Object Security.Principal.NTAccount($targetName)).Translate([Security.Principal.SecurityIdentifier])
            $targetSid = $sidObj.Value
        } catch {
            Write-Host "[!] cannot resolve '$targetName' to a SID: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "[!] local users, or DOMAIN\user with a reachable DC" -ForegroundColor Yellow
            exit 1
        }

        $wl = Get-WinlogonInMySession
        if (-not $wl) { Write-Host '[!] no winlogon.exe in this session' -ForegroundColor Red; exit 1 }
        $mySession = [uint32]((Get-Process -Id $PID).SessionId)

        # --- 1) target is logged on: steal their interactive primary token ---
        Write-Host "[*] looking for a live session of $targetName ($targetSid)..."
        $tgt = Find-TargetProcess $targetSid
        if ($tgt) {
            Write-Host "[+] found $($tgt.Name) (PID $($tgt.ProcessId)) owned by $targetName - stealing its token..."
            $tok = [IntPtr]::Zero
            $res = [Su.T]::StealTokenWithSession([int]$tgt.ProcessId, $wl.ProcessId, $mySession, [ref]$tok)
            if ($res -eq 'OK') {
                Write-Host "[*] token identity: $(Format-Identity $tok)" -ForegroundColor Cyan
                # cross-session steal: this session's winsta/desktop DACL has no
                # ACE for the target - grant it so the new console can open
                $g = [Su.T]::GrantDesktopAsSystem($wl.ProcessId, $targetSid)
                if ($g -ne 'OK') { Write-Host "[D] desktop grant for $targetSid`: $g" -ForegroundColor DarkGray }
                $envBlk = [IntPtr]::Zero
                $er = [Su.T]::MakeEnvBlock($tok, [ref]$envBlk)
                if ($er -ne 'OK') { Write-Host "[D] env block: $er" -ForegroundColor DarkGray }
                $spawn = Invoke-SuSpawnUserV733 $tok $wl.ProcessId $TargetUser $targetSid $envBlk $user $domain
                [Su.T]::FreeEnvBlock($envBlk)
                if ($spawn -eq 'OK') {
                    Write-Host "[+] spawned. New window should appear." -ForegroundColor Green
                    Polish-Console $TargetUser
                    exit 0
                }
                Write-Host "[!] spawn failed: $spawn" -ForegroundColor Yellow
            } else {
                Write-Host "[!] token steal failed: $res" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[*] no live session for $targetName"
        }

        # --- 2) direct S4U via LsaLogonUser - the FIELD-PROVEN route on this
        #        build: machine name as domain, Flags=0, lt=3 (network logon)
        #        minted a genuine LSASS logon session of the target on
        #        26200.9711 and the shell spawned cleanly with the v5
        #        desktop/profile/env bundle. Moved ahead of the craft and the
        #        scheduled task in v6 because it is the only route already
        #        confirmed end-to-end on this machine.
        Write-Host "[*] trying direct LsaLogonUser S4U for $targetName (network logon, machine-name domain)..."
        $tok = [IntPtr]::Zero
        $res = [Su.T]::S4ULogon($wl.ProcessId, $user, $domain, [ref]$tok)
        if ($res -match '^OK:') {
            $finalTok = [IntPtr]::Zero
            $r2 = [Su.T]::RewriteTokenSession($tok, $wl.ProcessId, $mySession, [ref]$finalTok)
            if ($r2 -ne 'OK') { $finalTok = $tok }
            Write-Host "[*] token identity: $(Format-Identity $finalTok)" -ForegroundColor Cyan

            $g = [Su.T]::GrantDesktopAsSystem($wl.ProcessId, $targetSid)
            if ($g -ne 'OK') { Write-Host "[D] desktop grant for $targetSid`: $g" -ForegroundColor DarkGray }

            $hiveLoaded = $false
            try { $hiveLoaded = Test-Path ("Registry::HKEY_USERS\" + $targetSid) } catch {}
            if (-not $hiveLoaded) {
                $lp = [Su.T]::LoadUserProfileAsSystem($wl.ProcessId, $finalTok, $user)
                if ($lp -ne 'OK') { Write-Host "[D] profile load for $user`: $lp" -ForegroundColor DarkGray }
            }

            $envBlk = [IntPtr]::Zero
            $er = [Su.T]::MakeEnvBlock($finalTok, [ref]$envBlk)
            if ($er -ne 'OK') { Write-Host "[D] env block: $er" -ForegroundColor DarkGray }

            $spawn = Invoke-SuSpawnUserV733 $finalTok $wl.ProcessId $TargetUser $targetSid $envBlk $user $domain
            [Su.T]::FreeEnvBlock($envBlk)
            if ($spawn -eq 'OK') {
                Write-Host "[+] spawned (S4U: $res)" -ForegroundColor Green
                Polish-Console $TargetUser
                Write-Host "[i] Genuine S4U network logon session; local shell only." -ForegroundColor Yellow
                exit 0
            }
            Write-Host "[!] spawn failed: $spawn" -ForegroundColor Yellow
        } else {
            Write-Host "[!] S4U: $res" -ForegroundColor Yellow
        }

        # --- 3) craft a token for the target SID via NtCreateToken ---
        #        (works for ANY local account; no network creds / no profile)
        Write-Host "[*] crafting a token for $targetName (SID $targetSid) via NtCreateToken..."
        $isAdmin = $false
        try {
            # resolve the admins group by well-known SID (localization-proof)
            $admGroup = Get-LocalGroup -Sid 'S-1-5-32-544' -ErrorAction SilentlyContinue
            if ($admGroup) {
                $isAdmin = [bool](Get-LocalGroupMember -Group $admGroup -ErrorAction SilentlyContinue |
                    Where-Object { "$($_.SID)" -eq $targetSid })
            }
        } catch {}
        $preset = 'Standard'
        if ($isAdmin) { $preset = 'Admin' }

        # the target's REAL group list from SAM (when it is a local account) -
        # merged into the crafted token so custom memberships keep working
        $groupSids = $null
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
            $up = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, $user)
            if ($up) {
                $groupSids = @($up.GetGroups() | ForEach-Object { try { $_.Sid.Value } catch { $null } } | Where-Object { $_ })
            }
        } catch { $groupSids = $null }
        if ($groupSids) { Write-Host "[*] SAM groups for $user`: $($groupSids -join ', ')" }

        $craftPids = Get-CraftSourcePids $wl
        $tok = [IntPtr]::Zero
        $res = [Su.T]::CreateTokenForSid($targetSid, $groupSids, $preset, $craftPids, $mySession, [ref]$tok)
        if ($res -eq 'OK') {
            Write-Host "[+] token minted ($preset preset). Identity: $(Format-Identity $tok)" -ForegroundColor Green
            # the crafted token has no logon SID in this session's winsta/
            # desktop DACL - grant its user SID access so the window can open
            $g = [Su.T]::GrantDesktopAsSystem($wl.ProcessId, $targetSid)
            if ($g -ne 'OK') { Write-Host "[D] desktop grant for $targetSid`: $g" -ForegroundColor DarkGray }
            # mount the user's hive (best effort - crafted tokens can be refused;
            # a live session of the target already has it loaded)
            $hiveLoaded = $false
            try { $hiveLoaded = Test-Path ("Registry::HKEY_USERS\" + $targetSid) } catch {}
            if (-not $hiveLoaded) {
                $lp = [Su.T]::LoadUserProfileAsSystem($wl.ProcessId, $tok, $user)
                if ($lp -ne 'OK') { Write-Host "[D] profile load for $user`: $lp" -ForegroundColor DarkGray }
            }
            $envBlk = [IntPtr]::Zero
            $er = [Su.T]::MakeEnvBlock($tok, [ref]$envBlk)
            if ($er -ne 'OK') { Write-Host "[D] env block: $er" -ForegroundColor DarkGray }
            $spawn = Invoke-SuSpawn $tok $wl.ProcessId $TargetUser $targetSid $envBlk
            [Su.T]::FreeEnvBlock($envBlk)
            if ($spawn -eq 'OK') {
                Write-Host "[+] spawned. New window should appear." -ForegroundColor Green
                Polish-Console $TargetUser
                Write-Host "[i] Crafted token: local identity only (no network creds; profile best-effort)." -ForegroundColor Yellow
                exit 0
            }
            Write-Host "[!] spawn failed: $spawn" -ForegroundColor Yellow
        } else {
            Write-Host "[!] token crafting failed: $res" -ForegroundColor Yellow
        }

        # --- 4) S4U scheduled task (LAST resort since v6) ---
        #     Field status on build 26200.9711: registration is denied even to
        #     a SYSTEM caller - the XML form dies with 'Acces refuse', and the
        #     /RU+/NP form actually PROMPTS for the target's password (which
        #     reads EOF from <NUL and fails). Kept as the final fallback only
        #     because the captured stderr now explains itself in the [D] lines.
        $taskName = 'SuS4U_' + [guid]::NewGuid().ToString('N').Substring(0, 10)
        $stubFound = 0
        $taskXmlPath = $null
        try {
            Write-Host "[*] trying a scheduled-task S4U logon for $targetName (last resort)..."
            # Registration MUST be performed BY SYSTEM - a plain elevated admin
            # gets 'Access denied' registering an S4U task for another user (the
            # exact failure v1 printed). We spawn a hidden SYSTEM child (token
            # duplicated from winlogon) that drives schtasks.exe; the stub action
            # keeps a cmd alive ~30s so its token can be stolen afterwards.
            # v3 lesson (F:wait:258): a hidden schtasks child can block forever,
            # so every schtasks call is wrapped in 'cmd.exe /c ... <NUL' - any
            # surprise prompt then reads EOF instead of deadlocking the wait.
            # Primary form: register a task XML with an explicit
            # <LogonType>S4U</LogonType> principal (unambiguous on every build);
            # fallback: the classic /RU + /NP command-line form.
            $stubArgs = '/c set SU_S4U_STUB=1& timeout /t 30 /nobreak'
            $taskXml = (
                '<?xml version="1.0" encoding="UTF-16"?>' +
                '<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
                '<Principals><Principal id="Author">' +
                '<UserId>' + $targetName + '</UserId>' +
                '<LogonType>S4U</LogonType>' +
                '<RunLevel>LeastPrivilege</RunLevel>' +
                '</Principal></Principals>' +
                '<Settings>' +
                '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>' +
                '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>' +
                '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>' +
                '<StartWhenAvailable>true</StartWhenAvailable>' +
                '<AllowStartOnDemand>true</AllowStartOnDemand>' +
                '<Enabled>true</Enabled>' +
                '<Hidden>false</Hidden>' +
                '<ExecutionTimeLimit>PT2M</ExecutionTimeLimit>' +
                '</Settings>' +
                '<Triggers><TimeTrigger><StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>' +
                '<Actions Context="Author"><Exec>' +
                '<Command>cmd.exe</Command>' +
                '<Arguments>' + $stubArgs.Replace('&', '&amp;') + '</Arguments>' +
                '</Exec></Actions>' +
                '</Task>'
            )
            $taskXmlPath = Join-Path $env:TEMP ($taskName + '.xml')
            $taskLogPath = Join-Path $env:TEMP ($taskName + '.log')
            [IO.File]::WriteAllText($taskXmlPath, $taskXml, [Text.Encoding]::Unicode)
            $create = 'cmd.exe /c schtasks.exe /Create /F /TN ' + $taskName + ' /XML "' + $taskXmlPath + '" > "' + $taskLogPath + '" 2>&1 <NUL'
            $rc = [Su.T]::RunHiddenAsSystem($wl.ProcessId, $create, 25000)
            if ($rc -ne 'OK') {
                $errTxt = ''
                try { if (Test-Path $taskLogPath) { $errTxt = (Get-Content $taskLogPath -Raw -Encoding OEM).Trim() } } catch {}
                if ($errTxt) { Write-Host "[D] schtasks said: $errTxt" -ForegroundColor DarkGray }
                Write-Host "[D] XML task registration: $rc - retrying with the /RU+/NP form" -ForegroundColor DarkGray
                $stubCmd = 'cmd.exe /c set SU_S4U_STUB=1& timeout /t 30 /nobreak'
                $create2 = 'cmd.exe /c schtasks.exe /Create /F /TN ' + $taskName + ' /TR "' + $stubCmd + '" /SC ONCE /ST 23:59 /RU "' + $targetName + '" /NP > "' + $taskLogPath + '" 2>&1 <NUL'
                $rc = [Su.T]::RunHiddenAsSystem($wl.ProcessId, $create2, 25000)
                if ($rc -ne 'OK') {
                    $errTxt2 = ''
                    try { if (Test-Path $taskLogPath) { $errTxt2 = (Get-Content $taskLogPath -Raw -Encoding OEM).Trim() } } catch {}
                    if ($errTxt2) { Write-Host "[D] schtasks said: $errTxt2" -ForegroundColor DarkGray }
                }
            }
            if ($rc -ne 'OK') { throw "task registration as SYSTEM failed: $rc" }
            $rc = [Su.T]::RunHiddenAsSystem($wl.ProcessId, 'cmd.exe /c schtasks.exe /Run /TN ' + $taskName + ' <NUL', 20000)
            if ($rc -ne 'OK') { throw "task start failed: $rc" }

            for ($i = 0; $i -lt 15 -and $stubFound -eq 0; $i++) {
                Start-Sleep -Milliseconds 700
                $stubs = @(Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -match 'SU_S4U_STUB' })
                foreach ($s in $stubs) {
                    $u = [Su.T]::GetProcessTokenUser([int]$s.ProcessId)
                    if ($u -eq $targetSid) { $stubFound = [int]$s.ProcessId; break }
                }
            }

            if ($stubFound -gt 0) {
                Write-Host "[+] the Task Scheduler minted an S4U token for $targetName (stub PID $stubFound) - stealing it..."
                $tok = [IntPtr]::Zero
                $res = [Su.T]::StealTokenWithSession($stubFound, $wl.ProcessId, $mySession, [ref]$tok)
                if ($res -eq 'OK') {
                    Write-Host "[*] token identity: $(Format-Identity $tok)" -ForegroundColor Cyan
                    # S4U batch token: grant desktop access before spawning
                    $g = [Su.T]::GrantDesktopAsSystem($wl.ProcessId, $targetSid)
                    if ($g -ne 'OK') { Write-Host "[D] desktop grant for $targetSid`: $g" -ForegroundColor DarkGray }
                    $envBlk = [IntPtr]::Zero
                    $er = [Su.T]::MakeEnvBlock($tok, [ref]$envBlk)
                    if ($er -ne 'OK') { Write-Host "[D] env block: $er" -ForegroundColor DarkGray }
                    $spawn = Invoke-SuSpawn $tok $wl.ProcessId $TargetUser $targetSid $envBlk
                    [Su.T]::FreeEnvBlock($envBlk)
                    if ($spawn -eq 'OK') {
                        Write-Host "[+] spawned. New window should appear." -ForegroundColor Green
                        Polish-Console $TargetUser
                        exit 0
                    }
                    Write-Host "[!] spawn failed: $spawn" -ForegroundColor Yellow
                } else {
                    Write-Host "[!] token steal failed: $res" -ForegroundColor Yellow
                }
            } else {
                Write-Host "[*] S4U task produced no token (account probably lacks 'Log on as a batch job')" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] S4U scheduled task path failed: $($_.Exception.Message)" -ForegroundColor Yellow
        } finally {
            try { [Su.T]::RunHiddenAsSystem($wl.ProcessId, 'cmd.exe /c schtasks.exe /Delete /F /TN ' + $taskName + ' <NUL', 15000) | Out-Null } catch {}
            if ($taskXmlPath) { Remove-Item -LiteralPath $taskXmlPath -Force -ErrorAction SilentlyContinue }
            if ($taskLogPath) { Remove-Item -LiteralPath $taskLogPath -Force -ErrorAction SilentlyContinue }
            if ($stubFound -gt 0) { Stop-Process -Id $stubFound -Force -ErrorAction SilentlyContinue }
        }

        Write-Host "[!] all passwordless methods failed for $targetName" -ForegroundColor Red
        Write-Host "[!] su.bat will fall back to runas (password prompt) if it exists" -ForegroundColor Yellow
        exit 1
    }

    'System' {
        $wl = Get-WinlogonInMySession
        if (-not $wl) { Write-Host '[!] no winlogon.exe in this session' -ForegroundColor Red; exit 1 }

        Write-Host "[*] duplicating SYSTEM token from winlogon (PID $($wl.ProcessId))..."
        $tok = [IntPtr]::Zero
        $res = [Su.T]::DupPrimaryToken($wl.ProcessId, [ref]$tok)
        if ($res -ne 'OK') {
            Write-Host "[!] SYSTEM token duplication failed: $res" -ForegroundColor Red
            exit 1
        }
        Write-Host "[*] token identity: $(Format-Identity $tok)" -ForegroundColor Cyan

        # v7.7: env block + SpawnAsUser fallback, exactly the TI route's
        # shape. The ninth live run died here with 87/0x80070057: this was
        # the last spawn site passing a NULL env together with the
        # CREATE_UNICODE_ENVIRONMENT flag, and the only route with no AsUser
        # fallback. A SYSTEM env block also hands the child the TEMP its own
        # token can actually use (helps the in-window self-polish compile).
        $envBlk = [IntPtr]::Zero
        $er = [Su.T]::MakeEnvBlock($tok, [ref]$envBlk)
        if ($er -ne 'OK') { Write-Host "[D] env block (falling back to inherited env): $er" -ForegroundColor DarkGray }
        Write-Host "[*] spawning cmd as SYSTEM..."
        $spawn = Invoke-SuSpawn $tok $wl.ProcessId 'SYSTEM' 'S-1-5-18' $envBlk
        [Su.T]::FreeEnvBlock($envBlk)
        if ($spawn -ne 'OK') {
            Write-Host "[!] spawn failed: $spawn" -ForegroundColor Red
            exit 1
        }
        Write-Host "[+] spawned. New window should appear." -ForegroundColor Green
        Polish-Console 'SYSTEM'
        exit 0
    }

    'TrustedInstaller' {
        $wl = Get-WinlogonInMySession
        if (-not $wl) { Write-Host '[!] no winlogon.exe in this session' -ForegroundColor Red; exit 1 }
        $mySession = [uint32]((Get-Process -Id $PID).SessionId)
        # NT SERVICE\TrustedInstaller - note the final subauthority: 2271478464
        # (the ...0584 variant floating around in some notes is WRONG)
        $TISID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

        # --- Technique 1 (primary): craft the TRUE TI token with NtCreateToken ---
        Write-Host "[*] crafting TRUE TrustedInstaller token (TokenUser = $TISID) via NtCreateToken..."
        $craftPids = Get-CraftSourcePids $wl
        $tok = [IntPtr]::Zero
        $res = [Su.T]::CreateTokenForSid($TISID, $null, 'TI', $craftPids, $mySession, [ref]$tok)

        if ($res -eq 'OK') {
            $ident = Format-Identity $tok
            Write-Host "[+] TI token minted. Identity: $ident" -ForegroundColor Green
            # ground truth is the kernel TokenUser SID; WindowsIdentity may print
            # the bare SID or "(unreadable)" for a kernel-minted service-SID token
            # even though the token itself is perfectly valid.
            $sidVerified = $false
            try { $sidVerified = [Su.T]::TokenUserIs($tok, $TISID) } catch {}
            if (-not $sidVerified) {
                Write-Host "[!] crafted token identity mismatch (TokenUser != $TISID) - refusing to spawn" -ForegroundColor Red
                exit 1
            }
            if ($ident -notmatch 'TrustedInstaller' -and $ident -notmatch '^S-1-5-80') {
                Write-Host "[i] WindowsIdentity printed '$ident'; kernel TokenUser verified as the TI SID" -ForegroundColor Yellow
            }
            $g = [Su.T]::GrantDesktopAsSystem($wl.ProcessId, $TISID)
            if ($g -ne 'OK') { Write-Host "[D] desktop grant for the TI SID: $g" -ForegroundColor DarkGray }
            $envBlk = [IntPtr]::Zero
            $er = [Su.T]::MakeEnvBlock($tok, [ref]$envBlk)
            if ($er -ne 'OK') { Write-Host "[D] env block (falling back to inherited env): $er" -ForegroundColor DarkGray }

            Write-Host "[*] spawning cmd as TRUE TrustedInstaller..."
            # v7.25: close leftover TI windows BEFORE spawning - a leftover
            # satisfies every title-based census (it fooled the verdict and
            # the retry gate for three rounds) and keeps a stale window on
            # the desktop. Also initializes the route-facts list.
            $script:SuRouteFacts = @()
            $script:SuRouteStart = Get-Date
            $sweptJ = 0
            try {
                $suDllS = Join-Path $env:SystemRoot 'System32\su-polish.dll'
                if (Test-Path $suDllS) {
                    [Reflection.Assembly]::LoadFrom($suDllS) | Out-Null
                    $myHwndS = [Polish]::GetConsoleWindow()
                    foreach ($wS in [Polish]::ListWindows()) {
                        $pS = $wS -split ';', 5
                        if ($pS.Count -lt 5) { continue }
                        if ($pS[3] -ne '1') { continue }
                        if ($pS[1] -notlike '*Console*') { continue }
                        if ($pS[4] -notlike '*TrustedInstaller*') { continue }
                        $hS = [IntPtr][int64]$pS[0]
                        if ($hS -eq $myHwndS) { continue }
                        $null = [Polish]::PostMessage($hS, 0x10, [IntPtr]::Zero, [IntPtr]::Zero)
                        $sweptJ++
                    }
                }
            } catch {}
            if ($sweptJ -gt 0) {
                Write-Host "[i] v7.33: closed $sweptJ leftover TrustedInstaller window(s) before spawning" -ForegroundColor DarkGray
                $script:SuRouteFacts += "swept=$sweptJ"
            }
            $spawn = Invoke-SuSpawnV719 $tok $wl.ProcessId 'TrustedInstaller' $TISID $envBlk
            [Su.T]::FreeEnvBlock($envBlk)
            if ($spawn -ne 'OK') {
                Write-Host "[!] spawn failed: $spawn" -ForegroundColor Red
                exit 1
            }

            Write-Host ""
            Write-Host "[+] spawned. In the new window check:" -ForegroundColor Green
            Write-Host "    whoami /user    ->  nt service\trustedinstaller  ($TISID)" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "    Ownership (field-tested on this build):" -ForegroundColor Cyan
            Write-Host '        takeown /f <file>   ->  owner becomes WORKGROUP\<machine>$' -ForegroundColor Cyan
            Write-Host '            (the computer account - normal for a virtual account;' -ForegroundColor Cyan
            Write-Host '             NT SERVICE\* is machine-account-backed)' -ForegroundColor Cyan
            Write-Host '        icacls <file> /setowner "NT SERVICE\TrustedInstaller"' -ForegroundColor Cyan
            Write-Host '            ->  owner literally becomes NT SERVICE\TrustedInstaller' -ForegroundColor Cyan
            Write-Host '            (works from this shell: SeTakeOwnership + SeRestore are' -ForegroundColor Cyan
            Write-Host '             enabled in the minted token)' -ForegroundColor Cyan
            Write-Host '        powershell -c "(Get-Acl <file>).Owner"    (verify)' -ForegroundColor Cyan
            Write-Host ""
            Write-Host "[i] Crafted token = kernel-minted (no LSASS logon session, no network" -ForegroundColor Yellow
            Write-Host "    identity) - local operations only. takeown/icacls work through the" -ForegroundColor Yellow
            Write-Host "    SeTakeOwnershipPrivilege / SeRestorePrivilege baked into the token." -ForegroundColor Yellow
            Polish-Console 'TrustedInstaller'
            exit 0
        }

        Write-Host "[!] token crafting failed: $res" -ForegroundColor Yellow
        Write-Host "[*] falling back to a verified live-TI-process steal..." -ForegroundColor Yellow

        # --- Technique 2 (fallback): a live TI-PRIMARY process (pre-23H2 style).
        #     On 24H2 TrustedInstaller.exe runs as SYSTEM with the TI SID enabled
        #     as a *group*, so this usually reports 'not applicable' - but we
        #     verify TokenUser == TI SID before trusting any stolen token.
        try {
            if ((Get-Service TrustedInstaller -ErrorAction SilentlyContinue).Status -ne 'Running') {
                Start-Service TrustedInstaller -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 600
            }
        } catch {}

        $tiProcs = @(Get-CimInstance Win32_Process -Filter "Name='TrustedInstaller.exe'" -ErrorAction SilentlyContinue)
        foreach ($tp in $tiProcs) {
            $u = [Su.T]::GetProcessTokenUser([int]$tp.ProcessId)
            Write-Host "    TrustedInstaller.exe PID $($tp.ProcessId): TokenUser=$u" -ForegroundColor DarkGray
            if ($u -eq $TISID) {
                $tok = [IntPtr]::Zero
                $r2 = [Su.T]::StealTokenWithSession([int]$tp.ProcessId, $wl.ProcessId, $mySession, [ref]$tok)
                if ($r2 -eq 'OK') {
                    Write-Host "[+] stole a genuine TI-primary token (PID $($tp.ProcessId))"
                    $g = [Su.T]::GrantDesktopAsSystem($wl.ProcessId, $TISID)
                    if ($g -ne 'OK') { Write-Host "[D] desktop grant for the TI SID: $g" -ForegroundColor DarkGray }
                    $spawn = Invoke-SuSpawn $tok $wl.ProcessId 'TrustedInstaller' $TISID ([IntPtr]::Zero)
                    if ($spawn -eq 'OK') { Write-Host "[+] spawned." -ForegroundColor Green; Polish-Console 'TrustedInstaller'; exit 0 }
                    Write-Host "[!] spawn failed: $spawn" -ForegroundColor Red
                } else {
                    Write-Host "[!] steal from PID $($tp.ProcessId) failed: $r2" -ForegroundColor Yellow
                }
            }
        }
        if ($tiProcs.Count -gt 0) {
            Write-Host "[i] TrustedInstaller.exe is NOT TI-primary on this build (TokenUser =" -ForegroundColor Yellow
            Write-Host "    S-1-5-18 / SYSTEM, with the TI SID enabled as a group). Stealing its" -ForegroundColor Yellow
            Write-Host "    token would give a SYSTEM shell - that is the documented 24H2 behavior." -ForegroundColor Yellow
        } else {
            Write-Host "[i] no TrustedInstaller.exe process found" -ForegroundColor Yellow
        }

        # --- why the other classic tricks are dead on 24H2 ---
        Write-Host ""
        Write-Host "[i] The classic TI routes are all dead on Win 11 24H2:" -ForegroundColor Yellow
        Write-Host "    - schtasks /ru `"NT SERVICE\TrustedInstaller`" silently runs as SYSTEM since 23H2" -ForegroundColor Yellow
        Write-Host "    - SCM rejects new services with TI as ObjectName (error 22 / 1057)" -ForegroundColor Yellow
        Write-Host "    - the TI service itself runs as LocalSystem, so even repointing its" -ForegroundColor Yellow
        Write-Host "      binPath mints a SYSTEM+TI-group process, not a TI-primary one" -ForegroundColor Yellow
        Write-Host "    - MSV1_0 S4U can never resolve virtual service accounts (0xC00000A7/0xC00000BB)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[!] NtCreateToken failed ($res) - that was the only TRUE-TI route." -ForegroundColor Red
        Write-Host "[!] Check the [D] craft-source lines above: lsass.exe must show" -ForegroundColor Red
        Write-Host "    SeCreateTokenPrivilege=True. If every candidate shows open/access errors," -ForegroundColor Red
        Write-Host "    LSASS is protected (PPL) - verify RunAsPpl=0. If the error says" -ForegroundColor Red
        Write-Host "    STATUS_PRIVILEGE_NOT_HELD, re-run from a freshly elevated prompt." -ForegroundColor Red
        Write-Host "    v7 fixed the two real parameter defects behind the 0xC000000D" -ForegroundColor Red
        Write-Host "    of runs 4 and 5 (label attributes 0xC020 -> 0x60; QoS struct" -ForegroundColor Red
        Write-Host "    16 -> 12 bytes); TokenSessionId stays class 12. The" -ForegroundColor Red
        Write-Host "    parameter set now byte-matches Wh04m1001/NtCreateToken, which" -ForegroundColor Red
        Write-Host "    mints TI-primary tokens on this build family. If it STILL" -ForegroundColor Red
        Write-Host "    fails, please report the [D] lines above." -ForegroundColor Red
        exit 1
    }
}

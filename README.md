# su-windows

`su` for Windows: open a shell as another local user, as SYSTEM, or as the
real TrustedInstaller, from one elevated prompt. No password, no UAC.

    su <user>     shell as that user
    su sys        fresh SYSTEM shell
    su ti         shell as NT SERVICE\TrustedInstaller

Built for my own boxes after too many recovery scenarios that started with
"ok, which live USB is the closest one". Grew through about 35 field
rounds; the current build is v7.34. It assumes you know what a token is and
that you only run it on machines you administer.

## Requirements

- Windows 10/11, x64
- PowerShell 5.1 or newer
- an elevated shell. Nothing works without it: right-click the terminal,
  "Run as administrator", or use the built-in Windows sudo (next section)
  to elevate a single call.
- the kit files together in one folder on PATH (default:
  `C:\Windows\System32`)

## Windows has its own sudo now

Since Windows 11 24H2 there is a native `sudo` (open source:
github.com/microsoft/sudo), off by default. Turn it on once in Settings,
System, For developers, "Enable sudo" - newer builds moved the toggle to
System, Advanced - or from an elevated console:

    sudo config --enable forceNewWindow

It has three window modes: forceNewWindow (default, the command gets its
own elevated console), disableInput (runs in the current window, input
closed) and normal (inline). Microsoft documents the trade-offs at
learn.microsoft.com/windows/advanced-settings/sudo - short version: keep
the default unless you understand why inline is risky.

What it does: run one command with administrator permission, as the user
you already are, after a UAC prompt. The daily "edit the hosts file /
install that npm package / run diskpart" cases, covered.

What it doesn't do - which is why this kit exists:

- other users. sudo elevates *you*; running anything as a different
  account is not supported (Microsoft lists it as roadmap). `su <user>`
  does it, passwordless, through an S4U logon.
- SYSTEM and TrustedInstaller. `sudo netstat` is you with a UAC stamp.
  `su sys` is a real SYSTEM console, `su ti` is the true TrustedInstaller
  token with SeTakeOwnership / SeRestore.
- the lock screen. UAC needs an interactive session, so the built-in
  sudo is useless in exactly the scenarios the trapdoor is for. The
  trapdoor shell is SYSTEM from the first keystroke, no UAC anywhere.

The two get along: with the built-in sudo enabled, `sudo su ti` from a
plain terminal works - one UAC click, the kit takes it from there.

## Install

Short version: copy the files, open an elevated prompt, run `su ti`.
Full walk-through including the optional lock-screen trapdoor:
[INSTALL.md](INSTALL.md).

## What each command actually does

**su <user>**

Looks for a live session of that user first. If there is none it mints a
passwordless S4U logon through LsaLogonUser (MSV1_0_S4U_LOGON against the
machine name). You get a real logon session, so `whoami` prints the user,
but it stays a local identity: no network credentials come along for the
ride.

**su sys**

A fresh SYSTEM console. Boring and reliable.

**su ti**

A shell whose token is minted with NtCreateToken, TokenUser set to the
TrustedInstaller SID
(S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464), with
SeTakeOwnership and SeRestore enabled. This is the "true TI" people keep
asking for: `whoami /user` shows the SID, and the ownership games work
from that shell:

    takeown /f <file>       owner becomes WORKGROUP\<machine>$
                            (the computer account - normal, NT SERVICE\*
                            is machine-backed)
    icacls <file> /setowner "NT SERVICE\TrustedInstaller"
                            owner literally becomes TrustedInstaller

The token is kernel-minted, so there is no LSASS logon session behind it:
local operations only, no network identity. Fine for file and registry
surgery.

Some routes open two consoles: the launcher stays open (it prints route
info and keeps an eye on the child), the other one is your shell. Close
them when you're done, they don't clean themselves up.

## The lock-screen trapdoor (optional)

`trapdoor\install.cmd` (elevated) adds IFEO Debugger redirects for the two
accessibility apps:

- `sethc.exe` - press Shift five times at the lock screen
- `utilman.exe` - click the Ease of Access button, bottom-right of the
  lock screen

Either one opens a SYSTEM cmd **on the secure desktop**, with nobody logged
on. Since v7.34 every window su spawns from that shell inherits the
caller's desktop, so the whole kit works pre-logon: `su sys`, `su ti`,
`su <user>` all open right there on the login screen. There is no
clipboard on the secure desktop; commands get typed by hand.

Why you'd want this: ransomware ate your session, a shell extension broke
logon, an AV update ate Explorer, whatever. Shift+Restart into WinRE works
too, but this is faster and keeps your options open.

Why you should think twice: this exact registry trick is in every AV
signature database (it's a classic persistence move). Expect detections,
expect security products to remove the values eventually. Use it on
machines you own. While it is installed, the real sticky-keys dialog and
the real Ease-of-Access panel do not open (the redirect replaces them).
`trapdoor\uninstall.cmd` puts everything back.

If your antivirus eats the two .cmd files straight out of the downloaded
zip (it happens - they contain the exact strings the signatures match
on), type the commands by hand. Install, from an elevated prompt:

    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "cmd.exe" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "cmd.exe" /f

Undo:

    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f

## How it works (short)

- `su.bat` parses the command and runs the root check
- `su-sys.ps1` is the engine: token minting (S4U / NtCreateToken), the
  session lookup, the spawn logic
- `su-polish.dll` does the window work: spawning consoles, the dark theme,
  window bookkeeping. Don't take a binary from the internet on faith:
  rebuild it with `su-polish-build.ps1` in an elevated PowerShell, it
  re-runs the self test and re-verifies the installed kit afterwards
- `su-relay.ps1` runs inside each spawned window and reports back

## Troubleshooting

- **"su is not recognized"** - the files aren't on PATH. `where su` should
  print `C:\Windows\System32\su.bat`.
- **command runs, no window** - check the launcher console; AV products
  like to eat `su-polish.dll` or the spawned cmd. Look in quarantine,
  restore, and exclude the `System32\su-*` files if you accept the risk.
- **windows open in weird places** - v7.33 and older always spawned on
  `winsta0\default`, so anything launched from the trapdoor shell appeared
  on the locked desktop instead of the login screen. v7.34 fixed that
  (children inherit the caller's desktop). Run `su-polish-build.ps1` to
  make sure the installed kit is current.
- **Shift x5 does nothing at the lock screen but the button works** - seen
  in the field once, cause never pinned down; the Ease of Access button is
  the reliable door.

## Uninstall

Delete the kit files from System32 (plus any `su-*.bak*` leftovers), and if
you installed the trapdoor, run `trapdoor\uninstall.cmd`. That's
everything: the kit runs stateless. No services, no scheduled tasks, no
config files.

## History

Started mid-October 2026 as a small .bat ("run cmd as SYSTEM without the
UAC dance"), then grew a TI route, a user route, a DLL for the window
work, and finally desktop inheritance so the whole thing works from the
lock screen. v7.33 was the wrapper machinery; v7.34 removed the hardcoded
spawn desktop and cleaned up the re-run debris.

## License

MIT - see [LICENSE](LICENSE).

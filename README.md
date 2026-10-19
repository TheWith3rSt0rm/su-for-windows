# su for Windows

Unix has had `su` since forever. Windows has `runas`, which asks for a password every
single time. So here's a proper `su` for Windows 11 — passwordless user switching,
plus SYSTEM and a real TrustedInstaller shell* in one command:

```
C:\> su julie
[*] Requesting a passwordless shell as julie (root semantics)...

C:\> su ti
[*] Requesting a TRUE TrustedInstaller shell...
```

Each command opens a new window running as the account you named; your original
prompt is left alone.

It's two plain text files — a `.bat` you type and a PowerShell script that does the
actual work. No compiled binary, nothing obfuscated. If you want to know what it does
to your machine, read it; that's most of the point of it being a script.

## Requirements

- Windows 11. Written for 24H2 (build 26200.9711) — that's the machine it was built
  on, so other builds are untested territory. Reports welcome.
- PowerShell 5.1, which ships with Windows. Nothing else to install.
- An admin account. If your console isn't elevated, `su` throws one UAC prompt and
  carries on by itself. That's the only password-ish thing you'll ever see.

## Install

Grab the two files from this repo — `su.bat` and `su-sys.ps1` — and drop them into
`C:\Windows\System32` (needs an elevated prompt, it's a system folder):

```
copy su.bat su-sys.ps1 C:\Windows\System32\
```

System32 is the recommended spot: it's already in your PATH, so `su` works from any
window. Any other folder on PATH works too. Just keep the two files in the same
folder — `su.bat` looks for `su-sys.ps1` next to itself.

If you downloaded the repo as a zip, Windows may have marked the files as coming
from the web. One-time fix:

```
powershell -Command "Unblock-File C:\Windows\System32\su-sys.ps1"
```

If the files reached you over a chat wire instead of git, check the bytes
survived the trip. These are the v7.5 hashes, exactly as shipped:

```
powershell -Command "Get-FileHash .\su.bat, .\su-sys.ps1, .\LICENSE -Algorithm SHA256"

su.bat       2dbef895061c145eecc1e4c80f4a372420ce9b72e828cc8c112547f18e7aebc8
su-sys.ps1   85ef4498ec6d378a40150766d8b5df73b3582d337409249b2fe415e6ee848c7d
LICENSE      fabf7c2eabe02c957e7deff73b2230a2e244646917f25ca0c9cc672afb7783ea
```

The moment you edit a file - put your real name into the LICENSE line,
say - its hash changes, which is normal and fine. README.md can't list its
own hash; it rehashes every time it gets edited.

## Usage

```
su                    short help
su <username>         shell as that user, no password (local or DOM\user)
su system             shell as NT AUTHORITY\SYSTEM
su ti                 shell as TrustedInstaller*
```

The new identity always opens in a new window. Don't take my word for the
TrustedInstaller part — check it yourself:

```
C:\> su ti
C:\> whoami /user                    ->  nt service\trustedinstaller
C:\> icacls C:\Windows\notepad.exe /setowner "NT SERVICE\TrustedInstaller"
C:\> dir /q C:\Windows\notepad.exe   ->  owner is TrustedInstaller
```

## Antivirus, fair warning

The whole trick is creating logon tokens directly — `NtCreateToken` and friends —
which is also exactly what credential-theft tooling does. So expect some noise:
SmartScreen may grumble when you download the files, Defender or your EDR may flag
them, and some AVs will kill the shell that `su` opens.

There's no packing, no obfuscation, no network calls — it's readable PowerShell the
whole way down. Audit it, then either add an exclusion or move on. Use it on machines
you administer; it grants nothing you don't already have as an elevated admin.

## Notes & limits

- Passwordless means just that: no password, so no network credentials either. The
  spawned shell is local-only — mapped drives and domain SSO won't follow you in.
- For a user who's logged on, `su` borrows the token from their session; otherwise
  it asks LSASS directly for an S4U network logon (which works on 24H2 for plain
  SAM users, once you ask with the machine name as the domain and a network
  logon type), then falls back to a crafted token, then to a scheduled-task
  logon. Worst case you get the classic `runas` password prompt.
- So the new console can actually appear on your desktop, `su` adds one small
  access entry for the target user on your window station. It's cosmetic, it goes
  away when you sign out, and removing it by hand takes about a minute.
- The new window is a plain conhost console, not Windows Terminal — the
  default-terminal handoff only attaches consoles started by your own user, and
  Terminal itself can't run under another token. `su` rounds the window corners
  and matches your dark/light title bar where DWM allows it; the icon stays
  cmd.exe's own, same as any other console window. The `[D] window polish:` line
  in `su`'s output reports whether the frame polish attached — and, on a skip,
  which console captions it actually saw, so a miss is diagnosable from the
  output alone.
- PPL-protected processes stay out of reach. As they should.
- Something breaks? Open an issue and paste the `[!]` line — every step prints its
  exact NTSTATUS, which makes remote debugging actually possible.

---

\* **"Real" TrustedInstaller, in one paragraph.** Almost every tool that promises a
TrustedInstaller shell actually gives you SYSTEM with a TrustedInstaller group SID
stapled on — `whoami` still prints SYSTEM and `takeown` still sets the owner to
SYSTEM. On 24H2 that's genuinely all you can get from launching TrustedInstaller.exe
or borrowing its token, since that process now runs as SYSTEM and merely *carries* a
TrustedInstaller group. The old workarounds died too: the task scheduler has silently
rewritten `NT SERVICE\TrustedInstaller` jobs into SYSTEM since 23H2, and the public
S4U logon route can't resolve virtual service accounts at all. `su ti` takes the only
road left — while
impersonating SYSTEM, it crafts a token whose *user* SID is TrustedInstaller
(`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`). Hence
`whoami /user` reporting `nt service\trustedinstaller`, with `icacls /setowner`
able to hand files to TrustedInstaller. (`takeown` itself gives the file to the
computer account — that's just how Windows treats virtual accounts.) The long
version — every route tried and the NTSTATUS each one
died with — lives in the comments at the top of `su-sys.ps1`.

## Credits & license

MIT — see `LICENSE`. No warranty; use on machines you administer.

Same underlying idea as NSudo and WinSudo, built on years of James Forshaw's
Windows token research. The 24H2 TrustedInstaller-as-SYSTEM behavior was
cross-checked against write-ups by FourCore and CmdT.

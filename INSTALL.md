# Installing su

Everything below wants an elevated prompt. `su.bat` runs its own root
check and will tell you off, but half the kit fails quietly without
elevation anyway, so start elevated and stay elevated. Two ways there:

- the classic: right-click Terminal or PowerShell, "Run as administrator"
- the built-in sudo, Windows 11 24H2 and newer (enable it once in
  Settings, System, For developers, "Enable sudo"): then `sudo su sys`
  from any normal terminal works too

## 1. the core kit

Copy these files into `C:\Windows\System32` (any folder on PATH works;
System32 is the default and what the examples assume):

    su.bat
    su-sys.ps1
    su-relay.ps1
    su-polish.dll
    su-polish-build.ps1

`su-polish-build.ps1` is not needed at runtime (it rebuilds and re-verifies
the kit), but ship it with the rest.

If the files came out of a downloaded zip, unblock them so Defender stays
calm:

    Get-ChildItem C:\Windows\System32\su-* | Unblock-File

Check the hashes against `SHA256SUMS.txt` if you want to be thorough.

Now from the elevated prompt:

    where su        -> C:\Windows\System32\su.bat
    su sys          -> a SYSTEM console opens
    su ti           -> whoami says nt service\trustedinstaller
    su <youruser>   -> whoami says <machine>\<youruser>

If all four behave, the kit is in.

## 2. the lock-screen trapdoor (optional)

From an elevated prompt:

    trapdoor\install.cmd

If your AV quarantined the file, the same two reg commands are printed in
the README's trapdoor section - type those instead.

This adds two IFEO Debugger values: `sethc.exe` (Shift x5 at the lock
screen) and `utilman.exe` (the Ease of Access button). Test it right away:

1. Win+L
2. click the Ease of Access button, bottom-right corner
3. a SYSTEM cmd opens on the lock screen
4. try `su ti`, `su <user>`, `su sys` in it - every window opens right
   there (v7.34 or newer)

There is no clipboard on the secure desktop, so commands get typed by
hand.

Read the trapdoor section in the README first: AV products flag this
trick, and while it's installed the real accessibility apps don't open.
Remove it with `trapdoor\uninstall.cmd`.

## 3. upgrading

If you get a newer `su-fix-v7.NN.ps1`, run it from a fresh elevated
PowerShell:

    powershell -NoProfile -ExecutionPolicy Bypass -File su-fix-v7.35.ps1

It patches the installed kit in place, leaves `.bak-vN.NN` copies of
everything it touches, and prints what it verified on disk.
`su-polish-build.ps1` does the same job for the current version: rebuild
the DLL, run the self test, re-verify the kit.

## 4. uninstall

From an elevated prompt:

    trapdoor\uninstall.cmd        (only if you installed it)

    Remove-Item C:\Windows\System32\su.bat, C:\Windows\System32\su-sys.ps1, `
      C:\Windows\System32\su-relay.ps1, C:\Windows\System32\su-polish.dll, `
      C:\Windows\System32\su-polish-build.ps1

    Remove-Item C:\Windows\System32\su-*.bak* -ErrorAction SilentlyContinue

No services, no scheduled tasks, no registry beyond the two optional
trapdoor values.

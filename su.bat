@echo off
setlocal
set "TASK_NAME=SuTask_%RANDOM%%RANDOM%"
set "SU_TARGET="

:: ==================================================================
::  su.bat - a Linux-style 'su' for Windows  (v7.4)
::
::  su ^<username^>            PASSWORDLESS when elevated (root
::                           semantics); runas fallback otherwise
::  su system                 run cmd as NT AUTHORITY\SYSTEM
::  su ti / trustedinstaller  run cmd as a TRUE TrustedInstaller
::                           (TokenUser = NT SERVICE\TrustedInstaller,
::                           whoami shows nt service\trustedinstaller,
::                           icacls /setowner works as TI - takeown hands
::                           ownership to the computer account)
::
::  su-sys.ps1 must stay in the same folder as this file.
::
::  24H2 notes:
::   - user mode is passwordless via (in order) token steal from a
::     logged-on session, an S4U scheduled task, and NtCreateToken
::     token crafting. The old direct LsaLogonUser S4U call is broken
::     on Win 11 24H2 (0xC00000BB even as SYSTEM) - kept only as a
::     last resort inside su-sys.ps1.
::   - TI mode crafts the TI token via NtCreateToken while
::     impersonating SYSTEM (SeCreateTokenPrivilege). The old
::     "schtasks /ru NT SERVICE\TrustedInstaller" trick is DEAD since
::     Win 11 23H2 (tasks silently run as SYSTEM) - that fallback was
::     removed from this script.
:: ==================================================================

:: internal marker: relaunch-after-UAC for user mode (target in %2)
if /i "%~1"=="__SU_USER__" (
    set "SU_REL=%~2"
    goto :user_elevated
)

if "%~1"=="" goto :help
if /i "%~1"=="-h"     goto :help
if /i "%~1"=="--help" goto :help
if /i "%~1"=="/?"     goto :help

if /i "%~1"=="system"              goto :system
if /i "%~1"=="sys"                 goto :system
if /i "%~1"=="nt authority\system" goto :system
if /i "%~1"=="trustedinstaller"    goto :trustedinstaller
if /i "%~1"=="ti"                  goto :trustedinstaller

goto :user

:: ==================================================================
::  USER - passwordless (root semantics), runas fallback
:: ==================================================================
:user
call :su_rootcheck
if %errorlevel% neq 0 (
    set "SU_ACCOUNT=User"
    set "SU_TARGET=%~1"
    goto :elevate
)

:user_elevated
set "SU_TGT=%~1"
if defined SU_REL set "SU_TGT=%SU_REL%"
echo.
echo [*] Requesting a passwordless shell as %SU_TGT% (root semantics)...

if not exist "%~dp0su-sys.ps1" (
    echo [!] su-sys.ps1 NOT found in "%~dp0%" - required for passwordless
    echo     su. Falling back to runas - password prompt follows...
    goto :user_runas
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0su-sys.ps1" -Account User -TargetUser "%SU_TGT%"
if not errorlevel 1 goto :done

echo [!] Passwordless su failed for %SU_TGT% - falling back to runas...

:user_runas
set "SU_CMD="
if defined SU_REL goto :user_runas2
if not "%~2"=="" set "SU_CMD=%~2"
:user_runas2
if not defined SU_CMD (
    runas /user:"%SU_TGT%" "cmd"
) else (
    runas /user:"%SU_TGT%" "%SU_CMD%"
)
goto :done

:: ==================================================================
::  SYSTEM
:: ==================================================================
:system
echo.
echo [*] Requesting a SYSTEM shell...

call :su_rootcheck
if %errorlevel% neq 0 (
    set "SU_ACCOUNT=System"
    goto :elevate
)

if exist "%~dp0su-sys.ps1" (
    echo [*] su-sys.ps1 found - using token duplication...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0su-sys.ps1" -Account System
    if not errorlevel 1 goto :done
    echo [!] Token technique failed - trying PsExec...
) else (
    echo [!] su-sys.ps1 NOT found in "%~dp0%"
    echo     That file is what makes the SYSTEM window VISIBLE.
    echo.
)

where psexec >nul 2>&1
if errorlevel 1 goto :sys_task
echo [*] Using PsExec...
psexec -accepteula -s -i cmd /k "title SYSTEM && whoami"
goto :done

:sys_task
echo [*] Last resort: scheduled task - the window may be INVISIBLE
echo     (Session 0 isolation). Only useful for headless work.
powershell -NoProfile -Command "try { $a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/k title SYSTEM && whoami'; $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType Interactive -RunLevel Highest; Register-ScheduledTask -TaskName '%TASK_NAME%' -Action $a -Principal $p -Force -ErrorAction Stop | Out-Null; Start-ScheduledTask -TaskName '%TASK_NAME%' } catch { Write-Host ('[!] ' + $_.Exception.Message); exit 1 }"
if errorlevel 1 goto :done
timeout /t 3 /nobreak >nul
schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
goto :done

:: ==================================================================
::  TRUSTEDINSTALLER
:: ==================================================================
:trustedinstaller
echo.
echo [*] Requesting a TRUE TrustedInstaller shell...

call :su_rootcheck
if %errorlevel% neq 0 (
    set "SU_ACCOUNT=TrustedInstaller"
    goto :elevate
)

if exist "%~dp0su-sys.ps1" (
    echo [*] su-sys.ps1 found - crafting the TI token via NtCreateToken...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0su-sys.ps1" -Account TrustedInstaller
    if not errorlevel 1 goto :done
    echo [!] TI technique failed - see the messages above for the exact
    echo     NTSTATUS / reason. Note: the old schtasks-as-TI fallback was
    echo     removed - it silently runs as SYSTEM since Win 11 23H2.
) else (
    echo [!] su-sys.ps1 NOT found in "%~dp0%" - required for TI mode.
)
goto :done

:: ==================================================================
::  ELEVATION - sudo when enabled, UAC otherwise
:: ==================================================================
:elevate
where sudo >nul 2>&1
if errorlevel 1 (
    echo [*] sudo is not installed - using a UAC prompt instead.
    goto :elevate_uac
)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo" /v Enabled 2>nul | findstr /r "0x[1-9]" >nul
if errorlevel 1 (
    echo [*] sudo is installed but DISABLED - using a UAC prompt instead.
    echo     To use sudo instead, run:  sudo config --enable inline
    goto :elevate_uac
)
echo [*] sudo is enabled - elevating through it...
sudo powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0su-sys.ps1" -Account %SU_ACCOUNT% -TargetUser "%SU_TARGET%"
goto :eof

:elevate_uac
echo [*] Triggering UAC - a new elevated window will take over...
if /i "%SU_ACCOUNT%"=="User" (
    powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '__SU_USER__','%SU_TARGET%' -Verb RunAs -ErrorAction Stop } catch { Write-Host '[!] Elevation cancelled.' }"
    goto :eof
)
powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '%SU_ACCOUNT% keepwindow' -Verb RunAs -ErrorAction Stop } catch { Write-Host '[!] Elevation cancelled.' }"
goto :eof

:: ==================================================================
:done
if defined SU_REL (
    echo.
    echo [*] Press any key to close this window...
    pause >nul
)
if /i "%~2"=="keepwindow" (
    echo.
    echo [*] Done. Press any key to close this window...
    pause >nul
)
goto :eof

:: ==================================================================
::  HELP
:: ==================================================================
:help
echo.
echo  ================================================================
echo    SU for Windows  -  any user (passwordless), SYSTEM, TRUE TI
echo  ================================================================
echo.
echo  USAGE
echo    su [account] [command]
echo.
echo  ACCOUNTS
echo    username               PASSWORDLESS as any user when your
echo                           prompt is elevated (root semantics);
echo                           runas with password as fallback
echo    system, sys            NT AUTHORITY\SYSTEM
echo    ti, trustedinstaller   TRUE TrustedInstaller shell - whoami
echo                           prints nt service\trustedinstaller; icacls
echo                           /setowner gives files to TI (takeown gives
echo                           the computer account)
echo.
echo  EXAMPLES
echo    su julie                    be julie, no password (elevated)
echo    su DOM\alice                be a domain user (needs DC)
echo    su system                   be SYSTEM
echo    su ti                       be TrustedInstaller (for real)
echo.
echo  NOTES
echo    - user mode: if the target is logged in, their token is
echo      stolen from their session; otherwise an S4U scheduled
echo      task (needs batch-logon right) or a crafted token is used.
echo      All paths are local-machine only (no network credentials
echo      as that user).
echo    - ti mode: the TI token is crafted with NtCreateToken as
echo      SYSTEM (SeCreateTokenPrivilege) - the only route that
echo      still works on Win 11 24H2.
echo    - the new identity ALWAYS opens in a NEW window.
echo.
goto :eof

:: ==================================================================
::  v7.34 :su_rootcheck - the elevation probe that also accepts SYSTEM
::  (BELT: SYSTEM normally passes net session already - field round
::  35 proved su works from a SYSTEM shell; the SID check is
::  insurance for a context where the probe fails while the
::  caller is still root).
:: ==================================================================
:su_rootcheck
net session >nul 2>&1
if %errorlevel% equ 0 exit /b 0
whoami /user 2>nul | find "S-1-5-18" >nul 2>&1
if %errorlevel% equ 0 exit /b 0
exit /b 1

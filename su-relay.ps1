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
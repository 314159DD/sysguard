# sysguard rule engine. Dot-sourced by sysguard.ps1 and by the tests.
# Everything in here works on a process snapshot (a hashtable pid -> row), so the
# rules can be exercised against synthetic process trees without touching the OS.

$script:SelfPid = $PID

# ---------------------------------------------------------------- defaults
$script:StuckShellMaxAgeSec = 30        # older than this ...
$script:StuckShellMaxWsKB   = 2048      # ... and smaller than this = stuck in startup
$script:ShellNames  = @('powershell.exe', 'pwsh.exe')
$script:HelperNames = @('cmd.exe', 'node.exe')     # killed only when their parent chain is dead

$script:Thresholds = [ordered]@{
    'powershell' = 40
    'pwsh'       = 40
    'conhost'    = 60
    'node'       = 30
    'cmd'        = 30
}

# ---------------------------------------------------------------- config file
function Import-SysguardConfig {
    # Optional sysguard.config.json next to the script. Only the keys present are overridden.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $cfg = Get-Content -Path $Path -Raw | ConvertFrom-Json
    if ($cfg.stuckShellMaxAgeSec) { $script:StuckShellMaxAgeSec = [int]$cfg.stuckShellMaxAgeSec }
    if ($cfg.stuckShellMaxWsKB)   { $script:StuckShellMaxWsKB   = [int]$cfg.stuckShellMaxWsKB }
    Import-HygieneConfig $cfg
    if ($cfg.thresholds) {
        foreach ($prop in $cfg.thresholds.PSObject.Properties) {
            $script:Thresholds[$prop.Name] = [int]$prop.Value
        }
    }
    return $true
}

# ---------------------------------------------------------------- logging
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch {}
    }
    if ($script:LogBox) {
        $script:LogBox.AppendText($line + [Environment]::NewLine)
    } else {
        Write-Host $line
    }
}

# ---------------------------------------------------------------- snapshot
function Get-ProcSnapshot {
    $snap = @{}
    $rows = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, CreationDate, WorkingSetSize, CommandLine, KernelModeTime, UserModeTime
    foreach ($r in $rows) {
        $snap[[int]$r.ProcessId] = [pscustomobject]@{
            Pid     = [int]$r.ProcessId
            Ppid    = [int]$r.ParentProcessId
            Name    = $r.Name
            Created = $r.CreationDate
            WsKB    = [int]($r.WorkingSetSize / 1KB)
            Cmd     = $r.CommandLine
            CpuSec  = [double](($r.KernelModeTime + $r.UserModeTime) / 10000000)
        }
    }
    return $snap
}

function Test-ParentDead {
    param($Snap, $P)
    if (-not $Snap.ContainsKey($P.Ppid)) { return $true }
    $parent = $Snap[$P.Ppid]
    # PID reuse: a "parent" younger than its child is a different process
    if ($parent.Created -and $P.Created -and $parent.Created -gt $P.Created) { return $true }
    return $false
}

function Get-OrphanTrees {
    # Helpers (cmd/node) whose parent is dead, plus helper descendants of those.
    # A helper that still has a living NON-helper descendant (postgres behind a
    # cmd /C wrapper, a service host, ...) is protected, and so is its whole
    # ancestor chain. Nothing below a protected process is touched either.
    param($Snap)

    # protected = every non-helper, plus every live ancestor of a protected process
    $prot = @{}
    foreach ($p in $Snap.Values) {
        if ($script:HelperNames -notcontains $p.Name) { $prot[$p.Pid] = $true }
    }
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($p in $Snap.Values) {
            if (-not $prot.ContainsKey($p.Pid)) { continue }
            if ($prot.ContainsKey($p.Ppid) -or (Test-ParentDead $Snap $p)) { continue }
            $prot[$p.Ppid] = $true; $grew = $true
        }
    }

    # candidate = unprotected helper whose parent is dead or itself a candidate
    $cand = @{}
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($p in $Snap.Values) {
            if ($cand.ContainsKey($p.Pid) -or $prot.ContainsKey($p.Pid)) { continue }
            if ($script:HelperNames -notcontains $p.Name) { continue }
            if ($cand.ContainsKey($p.Ppid) -or (Test-ParentDead $Snap $p)) { $cand[$p.Pid] = $true; $grew = $true }
        }
    }
    return @($cand.Keys | ForEach-Object { $Snap[$_] })
}

function Format-Proc {
    param($P)
    $cmd = if ($P.Cmd) { $P.Cmd } else { '' }
    if ($cmd.Length -gt 90) { $cmd = $cmd.Substring(0, 90) + '...' }
    return '{0} pid={1} ppid={2} ws={3}KB {4}' -f $P.Name, $P.Pid, $P.Ppid, $P.WsKB, $cmd
}

# ---------------------------------------------------------------- rules
function Get-StuckShells {
    param($Snap, [datetime]$Now = (Get-Date))
    $out = @()
    foreach ($p in $Snap.Values) {
        if ($script:ShellNames -notcontains $p.Name) { continue }
        if ($p.Pid -eq $script:SelfPid) { continue }
        if (-not $p.Created) { continue }
        $age = ($Now - $p.Created).TotalSeconds
        if ($age -gt $script:StuckShellMaxAgeSec -and $p.WsKB -lt $script:StuckShellMaxWsKB) { $out += $p }
    }
    return $out
}

function Get-OrphanConhost {
    param($Snap)
    $out = @()
    foreach ($p in $Snap.Values) {
        if ($p.Name -ne 'conhost.exe') { continue }
        if (Test-ParentDead $Snap $p) { $out += $p }
    }
    return $out
}

function Invoke-Kill {
    param($Procs, [string]$Label, [bool]$DryRun)
    $list = @($Procs | Where-Object { $_ })
    if ($list.Count -eq 0) { Write-Log "$Label : nothing to kill"; return 0 }
    $verb = if ($DryRun) { 'WOULD KILL' } else { 'KILL' }
    $killed = 0
    foreach ($p in $list) {
        Write-Log ("{0} {1}: {2}" -f $verb, $Label, (Format-Proc $p))
        if ($DryRun) { continue }
        try { Stop-Process -Id $p.Pid -Force -ErrorAction Stop; $killed++ }
        catch { Write-Log ("failed pid={0}: {1}" -f $p.Pid, $_.Exception.Message) 'WARN' }
    }
    if (-not $DryRun) { Write-Log ("{0} : killed {1} of {2}" -f $Label, $killed, $list.Count) }
    return $killed
}

function Invoke-AllRules {
    param($Snap, [bool]$DryRun)
    $n  = Invoke-Kill (Get-StuckShells  $Snap) 'stuck shell'    $DryRun
    $n += Invoke-Kill (Get-OrphanConhost $Snap) 'orphan conhost' $DryRun
    $n += Invoke-Kill (Get-OrphanTrees   $Snap) 'orphan helper'  $DryRun
    return $n
}

# ---------------------------------------------------------------- stats
function Get-FamilyStats {
    param($Snap)
    $fam = @{}
    foreach ($p in $Snap.Values) {
        $key = $p.Name -replace '\.exe$', ''
        if (-not $fam.ContainsKey($key)) { $fam[$key] = [pscustomobject]@{ Name = $key; Count = 0; WsMB = 0 } }
        $fam[$key].Count++
        $fam[$key].WsMB += $p.WsKB / 1024
    }
    return $fam
}

function Test-ThresholdsCrossed {
    param($Fam)
    $hits = @()
    foreach ($k in $script:Thresholds.Keys) {
        if ($Fam.ContainsKey($k) -and $Fam[$k].Count -gt $script:Thresholds[$k]) {
            $hits += ('{0}={1}' -f $k, $Fam[$k].Count)
        }
    }
    return $hits
}

# ---------------------------------------------------------------- hygiene rules
# These run on every guard tick, not only when a family limit is crossed. They exist because of
# one afternoon (2026-09-25) on a 96 GB machine where the mouse stopped moving: 16 hung grep/tail
# processes kept a hard disk at 100 %, 25 throwaway postgres clusters from test-gate runs were
# never stopped (5.7 GB RAM), and a vendor telemetry process had leaked 1.08 million handles,
# which grew the kernel pools to 19 GB. None of that crosses a process-count limit.
$script:StaleToolNames     = @('grep.exe', 'find.exe', 'tail.exe', 'xargs.exe', 'rg.exe')
$script:StaleToolMaxAgeMin = 10
$script:PgLaneRoots        = @()        # data-dir prefixes of throwaway postgres clusters, from config
$script:PgLaneMaxAgeMin    = 120
$script:HandleAlertCount   = 100000
$script:PoolAlertGB        = 4
$script:CommitAlertPct     = 90

function Import-HygieneConfig {
    # Reads the hygiene keys from an already parsed config object. Called by Import-SysguardConfig.
    param($Cfg)
    if ($Cfg.staleToolMaxAgeMin) { $script:StaleToolMaxAgeMin = [int]$Cfg.staleToolMaxAgeMin }
    if ($Cfg.staleToolNames)     { $script:StaleToolNames     = @($Cfg.staleToolNames | ForEach-Object { $_.ToLower() }) }
    if ($Cfg.pgLaneRoots)        { $script:PgLaneRoots        = @($Cfg.pgLaneRoots) }
    if ($Cfg.pgLaneMaxAgeMin)    { $script:PgLaneMaxAgeMin    = [int]$Cfg.pgLaneMaxAgeMin }
    if ($Cfg.handleAlertCount)   { $script:HandleAlertCount   = [int]$Cfg.handleAlertCount }
    if ($Cfg.poolAlertGB)        { $script:PoolAlertGB        = [double]$Cfg.poolAlertGB }
    if ($Cfg.commitAlertPct)     { $script:CommitAlertPct     = [double]$Cfg.commitAlertPct }
}

function Get-AgeMin {
    param($P, [datetime]$Now = (Get-Date))
    if (-not $P.Created) { return 0 }
    return ($Now - $P.Created).TotalMinutes
}

function Get-StaleTools {
    # Search/tail tools older than StaleToolMaxAgeMin. Agents run them for seconds; an old one is
    # the leftover of a killed shell and keeps a disk busy.
    param($Snap, [datetime]$Now = (Get-Date))
    return @($Snap.Values | Where-Object {
        $_.Pid -ne $script:SelfPid -and
        $script:StaleToolNames -contains $_.Name.ToLower() -and
        (Get-AgeMin $_ $Now) -gt $script:StaleToolMaxAgeMin
    })
}

function Get-PgDataDir {
    # Data directory from a postgres command line (-D "dir" or -D dir), or $null.
    param([string]$Cmd)
    if (-not $Cmd) { return $null }
    if ($Cmd -match '-D\s+"([^"]+)"') { return $matches[1] }
    if ($Cmd -match '-D\s+(\S+)') { return $matches[1] }
    return $null
}

function Get-StalePgLanes {
    # Postmasters (postgres whose parent is not postgres) with a data dir under one of PgLaneRoots
    # and older than PgLaneMaxAgeMin. Returns objects with Proc, DataDir, PgCtl.
    param($Snap, [datetime]$Now = (Get-Date))
    $out = @()
    if (@($script:PgLaneRoots).Count -eq 0) { return $out }
    foreach ($p in $Snap.Values) {
        if ($p.Name -ne 'postgres.exe') { continue }
        $parent = $Snap[$p.Ppid]
        if ($parent -and $parent.Name -eq 'postgres.exe') { continue }
        $dir = Get-PgDataDir $p.Cmd
        if (-not $dir) { continue }
        $norm = $dir.Replace('\', '/').ToLower()
        $inRoot = $false
        foreach ($r in $script:PgLaneRoots) {
            if ($norm.StartsWith($r.Replace('\', '/').ToLower())) { $inRoot = $true }
        }
        if (-not $inRoot) { continue }
        if ((Get-AgeMin $p $Now) -le $script:PgLaneMaxAgeMin) { continue }
        $exe = if ($p.Cmd -match '^"([^"]+)"') { $matches[1] } else { ($p.Cmd -split '\s+')[0] }
        $out += [pscustomobject]@{ Proc = $p; DataDir = $dir; PgCtl = (Join-Path (Split-Path $exe) 'pg_ctl.exe') }
    }
    return $out
}

function Invoke-StopPgLanes {
    # Stops each lane with "pg_ctl stop -m fast" (data stays on disk). Falls back to killing the
    # postmaster when pg_ctl is not next to postgres.exe.
    param($Lanes, [bool]$DryRun, [datetime]$Now = (Get-Date))
    $n = 0
    foreach ($l in @($Lanes)) {
        if (-not $l) { continue }
        $verb = if ($DryRun) { 'WOULD STOP' } else { 'STOP' }
        Write-Log ('{0} stale pg lane: {1} (pid={2}, {3:N0} min)' -f $verb, $l.DataDir, $l.Proc.Pid, (Get-AgeMin $l.Proc $Now))
        if ($DryRun) { continue }
        try {
            if (Test-Path $l.PgCtl) { & $l.PgCtl stop -D $l.DataDir -m fast -w -t 30 2>&1 | Out-Null }
            else { Stop-Process -Id $l.Proc.Pid -Force -ErrorAction Stop }
            $n++
        } catch { Write-Log ('pg lane stop failed {0}: {1}' -f $l.DataDir, $_.Exception.Message) 'WARN' }
    }
    return $n
}

function Invoke-Hygiene {
    param($Snap, [bool]$DryRun, [datetime]$Now = (Get-Date))
    # Runs every tick, so it only logs when it actually finds something.
    $n = 0
    $tools = @(Get-StaleTools $Snap $Now)
    if ($tools.Count -gt 0) { $n += Invoke-Kill $tools 'stale tool' $DryRun }
    $lanes = @(Get-StalePgLanes $Snap $Now)
    if ($lanes.Count -gt 0) { $n += Invoke-StopPgLanes $lanes $DryRun $Now }
    return $n
}

# ---------------------------------------------------------------- system alerts
function Get-AlertsFrom {
    # Pure: turns measured values into alert texts. HandleRows = objects with Name, Id, HandleCount.
    param($HandleRows, [double]$PoolGB, [double]$CommitPct)
    $alerts = @()
    foreach ($h in @($HandleRows)) {
        if ($h -and $h.HandleCount -gt $script:HandleAlertCount) {
            $alerts += ('{0} (pid {1}) holds {2:N0} handles, probably a leak' -f $h.Name, $h.Id, $h.HandleCount)
        }
    }
    if ($PoolGB -gt $script:PoolAlertGB) { $alerts += ('kernel pool {0:N1} GB (normal is under 2 GB), plan a reboot' -f $PoolGB) }
    if ($CommitPct -gt $script:CommitAlertPct) { $alerts += ('commit charge at {0:N0} %' -f $CommitPct) }
    return $alerts
}

function Get-SystemAlerts {
    # Reads the live values and hands them to Get-AlertsFrom.
    $handles = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Id, HandleCount
    $pool = 0; $commit = 0
    try {
        $c = (Get-Counter '\Memory\Pool Nonpaged Bytes', '\Memory\Pool Paged Bytes', '\Memory\% Committed Bytes In Use' -ErrorAction Stop).CounterSamples
        $pool = ($c[0].CookedValue + $c[1].CookedValue) / 1GB
        $commit = $c[2].CookedValue
    } catch {}
    return Get-AlertsFrom $handles $pool $commit
}

function Get-AlertKey {
    # Alert text without its numbers, so "holds 101,000 handles" and "holds 140,000 handles"
    # count as the same alert for the cooldown.
    param([string]$Alert)
    return ($Alert -replace '[\d.,]+', '#')
}

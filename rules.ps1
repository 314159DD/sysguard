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
    $rows = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, CreationDate, WorkingSetSize, CommandLine
    foreach ($r in $rows) {
        $snap[[int]$r.ProcessId] = [pscustomobject]@{
            Pid     = [int]$r.ProcessId
            Ppid    = [int]$r.ParentProcessId
            Name    = $r.Name
            Created = $r.CreationDate
            WsKB    = [int]($r.WorkingSetSize / 1KB)
            Cmd     = $r.CommandLine
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

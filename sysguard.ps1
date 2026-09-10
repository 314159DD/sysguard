# sysguard - process-storm guard and system monitor for Windows
# Plain PowerShell 5.1 + WinForms. No dependencies.
#
#   sysguard.ps1              GUI monitor with kill buttons
#   sysguard.ps1 -Scan        print what the rules WOULD kill, exit (dry run)
#   sysguard.ps1 -Clean       apply the rules once, exit
#   sysguard.ps1 -Guard       headless loop: apply the rules when a limit is crossed
#   sysguard.ps1 -Install     register the headless guard as a logon task
#   sysguard.ps1 -Uninstall   remove that task
#
param(
    [switch]$Scan,
    [switch]$Clean,
    [switch]$Guard,
    [switch]$Install,
    [switch]$Uninstall,
    [int]$Interval = 5
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'rules.ps1')
. (Join-Path $PSScriptRoot 'sessions.ps1')

$script:LogFile    = Join-Path $PSScriptRoot 'sysguard.log'
$script:ConfigFile = Join-Path $PSScriptRoot 'sysguard.config.json'
$script:TaskName   = 'sysguard'
$script:LogMaxBytes = 1MB

# ---------------------------------------------------------------- log rotation
if ((Test-Path $script:LogFile) -and (Get-Item $script:LogFile).Length -gt $script:LogMaxBytes) {
    Move-Item -Path $script:LogFile -Destination ($script:LogFile + '.1') -Force
}

if (Import-SysguardConfig $script:ConfigFile) { Write-Log ('config loaded from ' + $script:ConfigFile) }

# ---------------------------------------------------------------- standby list flush
$script:PurgeType = @'
using System;
using System.Runtime.InteropServices;
public static class MemPurge {
    [DllImport("ntdll.dll")] static extern int NtSetSystemInformation(int cls, ref int info, int len);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKPRIV np, int len, IntPtr prev, IntPtr ret);
    [StructLayout(LayoutKind.Sequential)] struct TOKPRIV { public int Count; public long Luid; public int Attr; }
    public static int Purge() {
        IntPtr tok;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out tok);
        TOKPRIV tp; tp.Count = 1; tp.Attr = 2;
        LookupPrivilegeValue(null, "SeProfileSingleProcessPrivilege", out tp.Luid);
        AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        int cmd = 4; // MemoryPurgeStandbyList
        return NtSetSystemInformation(80, ref cmd, 4); // SystemMemoryListInformation
    }
}
'@

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Clear-StandbyList {
    if (-not (Test-IsAdmin)) { Write-Log 'standby flush needs admin. Use "Relaunch as admin".' 'WARN'; return }
    if (-not ('MemPurge' -as [type])) { Add-Type -TypeDefinition $script:PurgeType }
    $before = (Get-SysStats).RamUsed
    $rc = [MemPurge]::Purge()
    if ($rc -ne 0) { Write-Log ('standby flush failed, NTSTATUS=0x{0:X8}' -f $rc) 'WARN'; return }
    Start-Sleep -Milliseconds 500
    $after = (Get-SysStats).RamUsed
    Write-Log ('standby list flushed. RAM used {0} MB -> {1} MB' -f $before, $after)
}

function Get-SysStats {
    $os  = Get-CimInstance Win32_OperatingSystem -Property TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory
    $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -Property PercentProcessorTime
    $totalMB = [int]($os.TotalVisibleMemorySize / 1024)
    $freeMB  = [int]($os.FreePhysicalMemory / 1024)
    return [pscustomobject]@{
        CpuPct    = [int]$cpu.PercentProcessorTime
        RamUsed   = $totalMB - $freeMB
        RamTot    = $totalMB
        # commit charge: RAM plus page file. Programs that cannot get memory abort here, long before RAM itself is full.
        CommitGB  = [math]::Round(($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1MB, 1)
        CommitTot = [math]::Round($os.TotalVirtualMemorySize / 1MB, 1)
    }
}

# ---------------------------------------------------------------- single instance
function Get-OtherInstances {
    param([bool]$GuardMode)
    # strict: "-File <this script path>" so a shell that merely mentions the name does not count
    $rx = '-File\s+"?' + [regex]::Escape($PSCommandPath)
    $mine = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -Property ProcessId, CommandLine |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match $rx }
    # comma keeps a one-element array from being unrolled on return (.Count would be null)
    return ,@($mine | Where-Object { ($_.CommandLine -like '* -Guard*') -eq $GuardMode })
}

# ---------------------------------------------------------------- logon task
if ($Install) {
    $tr = 'powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Guard -Interval 10' -f $PSCommandPath
    & schtasks /Create /F /TN $script:TaskName /SC ONLOGON /RL LIMITED /TR $tr | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "schtasks failed with exit code $LASTEXITCODE" }
    Write-Host ('logon task "{0}" registered: headless guard, 10 s interval. Starts at next logon.' -f $script:TaskName)
    exit 0
}

if ($Uninstall) {
    & schtasks /Delete /F /TN $script:TaskName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "schtasks failed with exit code $LASTEXITCODE" }
    Write-Host ('logon task "{0}" removed.' -f $script:TaskName)
    exit 0
}

# ---------------------------------------------------------------- session enrichment (cached)
$script:TitleCache  = @{}      # pid -> @{ Title; At }
$script:HerdrCache  = @{ Map = @{}; At = [datetime]::MinValue }

function Get-CachedTitle {
    param([int]$ProcId)
    $now = Get-Date
    $c = $script:TitleCache[$ProcId]
    if ($c -and ($now - $c.At).TotalSeconds -lt 15) { return $c.Title }
    $t = Get-ProcConsoleTitle $ProcId
    $script:TitleCache[$ProcId] = @{ Title = $t; At = $now }
    return $t
}

function Get-EnrichedSessions {
    param($Snap)
    $sessions = Get-Sessions $Snap -TitleOf { param($ProcId) Get-CachedTitle $ProcId }
    Update-SessionActivity $sessions
    if (((Get-Date) - $script:HerdrCache.At).TotalSeconds -gt 60) {
        $script:HerdrCache.Map = Get-HerdrSpaces (Get-HerdrExe $Snap)
        $script:HerdrCache.At = Get-Date
    }
    Merge-HerdrSpaces $sessions $script:HerdrCache.Map
    return ,$sessions
}

# ---------------------------------------------------------------- one-shot modes
if ($Scan -or $Clean) {
    $snap = Get-ProcSnapshot
    $fam  = Get-FamilyStats $snap
    $hits = Test-ThresholdsCrossed $fam
    $sys  = Get-SysStats
    Write-Host ('processes: {0}   limits crossed: {1}   RAM {2}/{3} MB   commit {4}/{5} GB' -f $snap.Count, $(if ($hits) { $hits -join ', ' } else { 'none' }), $sys.RamUsed, $sys.RamTot, $sys.CommitGB, $sys.CommitTot)
    [void](Invoke-AllRules $snap (-not $Clean))
    $sessions = Get-EnrichedSessions $snap
    Write-Host ''
    Write-Host ('agent sessions: {0}' -f $sessions.Count)
    if ($sessions.Count -gt 0) {
        Write-Host ('{0,-16} {1,-40} {2,6} {3,6} {4,-10} {5,8} {6,4} {7,-30} {8}' -f 'where', 'title', 'pid', 'age', 'state', 'RAM', 'procs', 'MCPs', 'hog')
        foreach ($s in $sessions) { Write-Host (Format-SessionRow $s) }
    }
    exit 0
}

# ---------------------------------------------------------------- headless guard
if ($Guard) {
    $other = Get-OtherInstances $true
    if ($other.Count -gt 0) {
        Write-Log ('guard already running as pid {0}, this one exits' -f $other[0].ProcessId) 'WARN'
        exit 0
    }
    Write-Log ('guard started, interval {0}s, pid {1}' -f $Interval, $PID)
    while ($true) {
        try {
            $snap = Get-ProcSnapshot
            $hits = Test-ThresholdsCrossed (Get-FamilyStats $snap)
            if ($hits) {
                Write-Log ('limit crossed: ' + ($hits -join ', ')) 'ALERT'
                [void](Invoke-AllRules $snap $false)
            }
        } catch { Write-Log $_.Exception.Message 'WARN' }
        Start-Sleep -Seconds $Interval
    }
}

# ---------------------------------------------------------------- GUI
$other = Get-OtherInstances $false
if ($other.Count -gt 0) {
    # GUI already open: bring it to the front instead of opening a second one
    $ws = New-Object -ComObject WScript.Shell
    [void]$ws.AppActivate('sysguard')
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$bg    = [System.Drawing.Color]::FromArgb(24, 26, 31)
$panel = [System.Drawing.Color]::FromArgb(34, 37, 44)
$fg    = [System.Drawing.Color]::FromArgb(220, 222, 228)
$dim   = [System.Drawing.Color]::FromArgb(140, 144, 154)
$red   = [System.Drawing.Color]::FromArgb(120, 40, 40)
$mono  = New-Object System.Drawing.Font('Consolas', 10)
$monoB = New-Object System.Drawing.Font('Consolas', 11, [System.Drawing.FontStyle]::Bold)

$form = New-Object System.Windows.Forms.Form
$form.Text = 'sysguard'
$form.Size = New-Object System.Drawing.Size(1000, 900)
$form.MinimumSize = $form.Size
$form.BackColor = $bg
$form.ForeColor = $fg
$form.Font = $mono
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(40, 40)

$lblStats = New-Object System.Windows.Forms.Label
$lblStats.Font = $monoB
$lblStats.Location = New-Object System.Drawing.Point(12, 10)
$lblStats.Size = New-Object System.Drawing.Size(960, 26)
$lblStats.Text = 'starting...'
$form.Controls.Add($lblStats)

$lv = New-Object System.Windows.Forms.ListView
$lv.View = 'Details'
$lv.FullRowSelect = $true
$lv.GridLines = $false
$lv.BackColor = $panel
$lv.ForeColor = $fg
$lv.Font = $mono
$lv.Location = New-Object System.Drawing.Point(12, 42)
$lv.Size = New-Object System.Drawing.Size(960, 230)
$lv.Anchor = 'Top,Left,Right'
[void]$lv.Columns.Add('process', 240)
[void]$lv.Columns.Add('count', 80)
[void]$lv.Columns.Add('limit', 80)
[void]$lv.Columns.Add('RAM MB', 100)
[void]$lv.Columns.Add('status', 200)
$form.Controls.Add($lv)

# agent sessions: one row per claude.exe with its whole process tree
$lblSess = New-Object System.Windows.Forms.Label
$lblSess.Location = New-Object System.Drawing.Point(12, 280)
$lblSess.Size = New-Object System.Drawing.Size(960, 20)
$lblSess.ForeColor = $dim
$lblSess.Text = 'agent sessions'
$form.Controls.Add($lblSess)

$lvSess = New-Object System.Windows.Forms.ListView
$lvSess.View = 'Details'
$lvSess.FullRowSelect = $true
$lvSess.MultiSelect = $false
$lvSess.HideSelection = $false
$lvSess.GridLines = $false
$lvSess.BackColor = $panel
$lvSess.ForeColor = $fg
$lvSess.Font = $mono
$lvSess.Location = New-Object System.Drawing.Point(12, 302)
$lvSess.Size = New-Object System.Drawing.Size(960, 170)
$lvSess.Anchor = 'Top,Left,Right'
foreach ($c in @(@('where', 130), @('title', 220), @('pid', 60), @('age', 55), @('state', 90), @('RAM MB', 70), @('procs', 55), @('MCPs', 130), @('hog', 150))) { [void]$lvSess.Columns.Add($c[0], $c[1]) }
$form.Controls.Add($lvSess)

function New-Btn {
    param([string]$Text, [int]$X, [int]$Y, [int]$W, [scriptblock]$OnClick)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X, $Y)
    $b.Size = New-Object System.Drawing.Size($W, 34)
    $b.FlatStyle = 'Flat'
    $b.BackColor = $panel
    $b.ForeColor = $fg
    $b.FlatAppearance.BorderColor = $dim
    $b.Add_Click($OnClick)
    $form.Controls.Add($b)
    return $b
}

$chkDry = New-Object System.Windows.Forms.CheckBox
$chkDry.Text = 'dry run (list only)'
$chkDry.Location = New-Object System.Drawing.Point(12, 526)
$chkDry.Size = New-Object System.Drawing.Size(220, 24)
$form.Controls.Add($chkDry)

$chkGuard = New-Object System.Windows.Forms.CheckBox
$chkGuard.Text = 'auto-guard (kill when a limit is crossed)'
$chkGuard.Location = New-Object System.Drawing.Point(240, 526)
$chkGuard.Size = New-Object System.Drawing.Size(360, 24)
$form.Controls.Add($chkGuard)

$chkTop = New-Object System.Windows.Forms.CheckBox
$chkTop.Text = 'always on top'
$chkTop.Location = New-Object System.Drawing.Point(610, 526)
$chkTop.Size = New-Object System.Drawing.Size(150, 24)
$chkTop.Checked = ($env:SYSGUARD_TOPMOST -eq '1')
$chkTop.Add_CheckedChanged({ $form.TopMost = $chkTop.Checked })
$form.TopMost = $chkTop.Checked
$form.Controls.Add($chkTop)

$script:Sessions = @()
[void](New-Btn 'end selected session' 12 482 200 {
    if ($lvSess.SelectedItems.Count -eq 0) { Write-Log 'no session selected' 'WARN'; return }
    $sel = $script:Sessions | Where-Object { $_.Pid -eq [int]$lvSess.SelectedItems[0].Tag }
    if (-not $sel) { return }
    [void](Invoke-Kill (Get-SessionKillList $sel) ('session ' + $sel.Pid) $chkDry.Checked); Update-View })

$y1 = 558; $y2 = 600
[void](New-Btn 'kill stuck shells'   12  $y1 178 { [void](Invoke-Kill (Get-StuckShells  (Get-ProcSnapshot)) 'stuck shell'    $chkDry.Checked); Update-View })
[void](New-Btn 'kill orphan conhost' 200 $y1 178 { [void](Invoke-Kill (Get-OrphanConhost (Get-ProcSnapshot)) 'orphan conhost' $chkDry.Checked); Update-View })
[void](New-Btn 'kill orphan cmd/node' 388 $y1 178 { [void](Invoke-Kill (Get-OrphanTrees   (Get-ProcSnapshot)) 'orphan helper'  $chkDry.Checked); Update-View })
[void](New-Btn 'ALL three'           576 $y1 176 { [void](Invoke-AllRules (Get-ProcSnapshot) $chkDry.Checked); Update-View })
[void](New-Btn 'flush standby RAM'   12  $y2 178 { Clear-StandbyList; Update-View })
[void](New-Btn 'nuke ALL powershell (except me)' 200 $y2 366 {
    $snap = Get-ProcSnapshot
    $all = @($snap.Values | Where-Object { $script:ShellNames -contains $_.Name -and $_.Pid -ne $script:SelfPid })
    [void](Invoke-Kill $all 'powershell (nuke)' $chkDry.Checked); Update-View })
if (-not (Test-IsAdmin)) {
    [void](New-Btn 'relaunch as admin' 576 $y2 176 {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"")
        $form.Close() })
}

$script:LogBox = New-Object System.Windows.Forms.TextBox
$script:LogBox.Multiline = $true
$script:LogBox.ReadOnly = $true
$script:LogBox.ScrollBars = 'Vertical'
$script:LogBox.BackColor = $panel
$script:LogBox.ForeColor = $fg
$script:LogBox.Font = $mono
$script:LogBox.Location = New-Object System.Drawing.Point(12, 646)
$script:LogBox.Size = New-Object System.Drawing.Size(960, 206)
$script:LogBox.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($script:LogBox)

function Update-View {
    try {
        $snap = Get-ProcSnapshot
        $fam  = Get-FamilyStats $snap
        $sys  = Get-SysStats
        $adm  = if (Test-IsAdmin) { 'admin' } else { 'user' }
        $lblStats.Text = 'CPU {0,3}%   RAM {1}/{2} MB   commit {3}/{4} GB   procs {5}   [{6}]   {7}' -f $sys.CpuPct, $sys.RamUsed, $sys.RamTot, $sys.CommitGB, $sys.CommitTot, $snap.Count, $adm, (Get-Date -Format 'HH:mm:ss')

        $lv.BeginUpdate()
        $lv.Items.Clear()
        $shown = @{}
        foreach ($k in $script:Thresholds.Keys) {
            $cnt = 0; $mb = 0
            if ($fam.ContainsKey($k)) { $cnt = $fam[$k].Count; $mb = [int]$fam[$k].WsMB }
            $lim = $script:Thresholds[$k]
            $status = if ($cnt -gt $lim) { 'OVER LIMIT' } else { 'ok' }
            $it = New-Object System.Windows.Forms.ListViewItem($k)
            [void]$it.SubItems.Add("$cnt"); [void]$it.SubItems.Add("$lim"); [void]$it.SubItems.Add("$mb"); [void]$it.SubItems.Add($status)
            if ($cnt -gt $lim) { $it.BackColor = $red }
            [void]$lv.Items.Add($it)
            $shown[$k] = $true
        }
        $others = $fam.Values | Where-Object { -not $shown.ContainsKey($_.Name) } | Sort-Object WsMB -Descending | Select-Object -First 8
        foreach ($o in $others) {
            $it = New-Object System.Windows.Forms.ListViewItem($o.Name)
            [void]$it.SubItems.Add("$($o.Count)"); [void]$it.SubItems.Add('-'); [void]$it.SubItems.Add("$([int]$o.WsMB)"); [void]$it.SubItems.Add('')
            $it.ForeColor = $dim
            [void]$lv.Items.Add($it)
        }
        $lv.EndUpdate()

        $selected = if ($lvSess.SelectedItems.Count -gt 0) { [int]$lvSess.SelectedItems[0].Tag } else { 0 }
        $script:Sessions = Get-EnrichedSessions $snap
        $lvSess.BeginUpdate()
        $lvSess.Items.Clear()
        foreach ($s in $script:Sessions) {
            $where = if ($s.Space) { $s.Space } else { $s.Terminal }
            $name  = if ($s.Title) { $s.Title } elseif ($s.Cwd) { Split-Path $s.Cwd -Leaf } else { '' }
            $state = if ($s.State -eq 'idle' -and $s.IdleMin -ne $null) { 'idle {0}m' -f $s.IdleMin } elseif ($s.State) { $s.State } else { '?' }
            $it = New-Object System.Windows.Forms.ListViewItem($where)
            foreach ($v in @($name, "$($s.Pid)", "$($s.AgeMin)m", $state, "$($s.RamMB)", "$($s.Procs)", ($s.Mcps -join ','), $s.Hog)) { [void]$it.SubItems.Add($v) }
            $it.Tag = $s.Pid
            if ($s.Hog) { $it.BackColor = $red } elseif ($s.State -eq 'idle') { $it.ForeColor = $dim }
            if ($s.Pid -eq $selected) { $it.Selected = $true }
            [void]$lvSess.Items.Add($it)
        }
        $lvSess.EndUpdate()
        if ($env:SYSGUARD_SNAPSHOT) {
            # render the form to a PNG (works even when another window covers it)
            $bmp = New-Object System.Drawing.Bitmap($form.Width, $form.Height)
            $form.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)))
            $bmp.Save($env:SYSGUARD_SNAPSHOT); $bmp.Dispose()
        }

        if ($chkGuard.Checked) {
            $hits = Test-ThresholdsCrossed $fam
            if ($hits) {
                Write-Log ('auto-guard: ' + ($hits -join ', ')) 'ALERT'
                [void](Invoke-AllRules $snap $chkDry.Checked)
            }
        }
    } catch {
        Write-Log $_.Exception.Message 'WARN'
    }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $Interval * 1000
$timer.Add_Tick({ Update-View })
$form.Add_Shown({
    # force to front even when launched from a hidden console behind a fullscreen terminal
    $form.TopMost = $true; $form.Activate(); $form.BringToFront()
    $form.TopMost = $chkTop.Checked
    Write-Log 'sysguard GUI started'; Update-View; $timer.Start() })
$form.Add_FormClosed({ $timer.Stop() })
[void]$form.ShowDialog()

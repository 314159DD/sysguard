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
    $os  = Get-CimInstance Win32_OperatingSystem -Property TotalVisibleMemorySize, FreePhysicalMemory
    $cpu = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -Property PercentProcessorTime
    $totalMB = [int]($os.TotalVisibleMemorySize / 1024)
    $freeMB  = [int]($os.FreePhysicalMemory / 1024)
    return [pscustomobject]@{
        CpuPct  = [int]$cpu.PercentProcessorTime
        RamUsed = $totalMB - $freeMB
        RamTot  = $totalMB
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

# ---------------------------------------------------------------- one-shot modes
if ($Scan -or $Clean) {
    $snap = Get-ProcSnapshot
    $fam  = Get-FamilyStats $snap
    $hits = Test-ThresholdsCrossed $fam
    Write-Host ('processes: {0}   limits crossed: {1}' -f $snap.Count, $(if ($hits) { $hits -join ', ' } else { 'none' }))
    [void](Invoke-AllRules $snap (-not $Clean))
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
$form.Size = New-Object System.Drawing.Size(780, 680)
$form.MinimumSize = $form.Size
$form.BackColor = $bg
$form.ForeColor = $fg
$form.Font = $mono
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(40, 40)

$lblStats = New-Object System.Windows.Forms.Label
$lblStats.Font = $monoB
$lblStats.Location = New-Object System.Drawing.Point(12, 10)
$lblStats.Size = New-Object System.Drawing.Size(740, 26)
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
$lv.Size = New-Object System.Drawing.Size(740, 230)
$lv.Anchor = 'Top,Left,Right'
[void]$lv.Columns.Add('process', 240)
[void]$lv.Columns.Add('count', 80)
[void]$lv.Columns.Add('limit', 80)
[void]$lv.Columns.Add('RAM MB', 100)
[void]$lv.Columns.Add('status', 200)
$form.Controls.Add($lv)

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
$chkDry.Location = New-Object System.Drawing.Point(12, 284)
$chkDry.Size = New-Object System.Drawing.Size(220, 24)
$form.Controls.Add($chkDry)

$chkGuard = New-Object System.Windows.Forms.CheckBox
$chkGuard.Text = 'auto-guard (kill when a limit is crossed)'
$chkGuard.Location = New-Object System.Drawing.Point(240, 284)
$chkGuard.Size = New-Object System.Drawing.Size(360, 24)
$form.Controls.Add($chkGuard)

$chkTop = New-Object System.Windows.Forms.CheckBox
$chkTop.Text = 'always on top'
$chkTop.Location = New-Object System.Drawing.Point(610, 284)
$chkTop.Size = New-Object System.Drawing.Size(150, 24)
$chkTop.Checked = ($env:SYSGUARD_TOPMOST -eq '1')
$chkTop.Add_CheckedChanged({ $form.TopMost = $chkTop.Checked })
$form.TopMost = $chkTop.Checked
$form.Controls.Add($chkTop)

$y1 = 316; $y2 = 358
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
$script:LogBox.Location = New-Object System.Drawing.Point(12, 404)
$script:LogBox.Size = New-Object System.Drawing.Size(740, 228)
$script:LogBox.Anchor = 'Top,Bottom,Left,Right'
$form.Controls.Add($script:LogBox)

function Update-View {
    try {
        $snap = Get-ProcSnapshot
        $fam  = Get-FamilyStats $snap
        $sys  = Get-SysStats
        $adm  = if (Test-IsAdmin) { 'admin' } else { 'user' }
        $lblStats.Text = 'CPU {0,3}%   RAM {1}/{2} MB   procs {3}   [{4}]   {5}' -f $sys.CpuPct, $sys.RamUsed, $sys.RamTot, $snap.Count, $adm, (Get-Date -Format 'HH:mm:ss')

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

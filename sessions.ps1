# sysguard session model. Dot-sourced by sysguard.ps1 and by the tests.
# A session is an agent process (claude.exe by default) plus everything under it:
# MCP servers, tool shells, whatever they spawned. This file turns a process
# snapshot into session rows and enriches them with the working directory,
# the console title the agent sets, and herdr workspace names when available.

$script:AgentNames    = @('claude.exe')
$script:TerminalNames = @{
    'warp.exe'            = 'Warp'
    'WindowsTerminal.exe' = 'Windows Terminal'
    'herdr.exe'           = 'herdr'
    'Code.exe'            = 'VS Code'
    'cursor.exe'          = 'Cursor'
    'wezterm-gui.exe'     = 'WezTerm'
    'alacritty.exe'       = 'Alacritty'
}
$script:WorkShellNames = @('bash.exe', 'sh.exe', 'powershell.exe', 'pwsh.exe', 'python.exe', 'python3.13.exe')
$script:HogCpuSec      = 1800     # a child with more CPU time than this is flagged
$script:HogWsMB        = 1024     # or more working set than this
$script:ActiveCpuDelta = 0.5      # CPU seconds per tick that count as activity

$script:SessionActivity = @{}     # pid -> @{ Cpu = <sec>; LastActive = <datetime> }

# ---------------------------------------------------------------- win32
$script:ProcPeekType = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ProcPeek {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out IntPtr read);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, ref PBI pbi, int len, out int ret);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FreeConsole();
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern int GetConsoleTitle(StringBuilder sb, int size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
    [StructLayout(LayoutKind.Sequential)] struct PBI { public IntPtr Reserved1; public IntPtr PebBaseAddress; public IntPtr Reserved2a; public IntPtr Reserved2b; public IntPtr UniqueProcessId; public IntPtr Reserved3; }
    static long ReadPtr(IntPtr h, IntPtr addr) { byte[] b = new byte[8]; IntPtr r; if (!ReadProcessMemory(h, addr, b, 8, out r)) return 0; return BitConverter.ToInt64(b, 0); }
    // Current directory of another 64-bit process, read from its PEB. Null when not readable.
    public static string Cwd(int pid) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            PBI pbi = new PBI(); int ret;
            if (NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf(pbi), out ret) != 0) return null;
            long p = ReadPtr(h, (IntPtr)((long)pbi.PebBaseAddress + 0x20));
            if (p == 0) return null;
            byte[] us = new byte[16]; IntPtr r;
            if (!ReadProcessMemory(h, (IntPtr)(p + 0x38), us, 16, out r)) return null;
            ushort len = BitConverter.ToUInt16(us, 0); long buf = BitConverter.ToInt64(us, 8);
            if (len == 0 || buf == 0) return null;
            byte[] s = new byte[len];
            if (!ReadProcessMemory(h, (IntPtr)buf, s, len, out r)) return null;
            return Encoding.Unicode.GetString(s).TrimEnd('\\');
        } finally { CloseHandle(h); }
    }
    // Title of the console another process is attached to. Briefly joins that console,
    // reads the title, leaves, and re-attaches to the parent's console if there is one.
    // Ctrl+C is ignored for this process so a break typed into that console while we
    // are attached cannot take sysguard down with it.
    public static string ConsoleTitle(int pid) {
        SetConsoleCtrlHandler(IntPtr.Zero, true);
        FreeConsole();
        string title = null;
        if (AttachConsole(pid)) {
            try { StringBuilder sb = new StringBuilder(1024); if (GetConsoleTitle(sb, sb.Capacity) > 0) title = sb.ToString(); }
            finally { FreeConsole(); }
        }
        AttachConsole(-1);
        return title;
    }
}
'@

function Get-ProcCwd {
    param([int]$ProcId)
    if (-not ('ProcPeek' -as [type])) { Add-Type -TypeDefinition $script:ProcPeekType }
    try { return [ProcPeek]::Cwd($ProcId) } catch { return $null }
}

function Get-ProcConsoleTitle {
    param([int]$ProcId)
    if (-not ('ProcPeek' -as [type])) { Add-Type -TypeDefinition $script:ProcPeekType }
    try { return [ProcPeek]::ConsoleTitle($ProcId) } catch { return $null }
}

# ---------------------------------------------------------------- title parsing
function ConvertFrom-AgentTitle {
    # Claude Code prefixes its console title with a state glyph: a spinner while
    # working, an asterisk while waiting for input. Returns @{ State; Title }.
    param([string]$Title)
    if (-not $Title) { return @{ State = $null; Title = $null } }
    $t = $Title.Trim()
    if ($t.Length -eq 0) { return @{ State = $null; Title = $null } }
    $glyph = [int][char]$t[0]
    $state = $null
    if ($glyph -eq 0x2733) { $state = 'idle' }
    elseif ($glyph -ge 0x25D0 -and $glyph -le 0x25D3) { $state = 'working' }
    if ($state) { $t = $t.Substring(1).Trim() }
    return @{ State = $state; Title = $t }
}

# ---------------------------------------------------------------- tree helpers
function Get-Children {
    param($Snap)
    $kids = @{}
    foreach ($p in $Snap.Values) {
        if (-not $kids.ContainsKey($p.Ppid)) { $kids[$p.Ppid] = @() }
        $kids[$p.Ppid] += $p
    }
    return $kids
}

function Get-Subtree {
    # Every descendant of $Root, each tagged with its depth below the root.
    param($Snap, $Kids, $Root)
    $out = @()
    $stack = New-Object System.Collections.Stack
    foreach ($c in @($Kids[$Root.Pid])) { if ($c) { $stack.Push(@{ P = $c; D = 1 }) } }
    $seen = @{ $Root.Pid = $true }
    while ($stack.Count -gt 0) {
        $item = $stack.Pop(); $p = $item.P; $d = $item.D
        if ($seen.ContainsKey($p.Pid)) { continue }
        $seen[$p.Pid] = $true
        $out += [pscustomobject]@{ Proc = $p; Depth = $d }
        foreach ($c in @($Kids[$p.Pid])) { if ($c) { $stack.Push(@{ P = $c; D = $d + 1 }) } }
    }
    return $out
}

function Get-TerminalOf {
    # Walk up from the agent until a known terminal shows up. Returns @{ Name; Pid }.
    param($Snap, $Root)
    $seen = @{}
    $cur = $Root
    while ($cur -and $Snap.ContainsKey($cur.Ppid) -and -not $seen.ContainsKey($cur.Ppid)) {
        $seen[$cur.Ppid] = $true
        $cur = $Snap[$cur.Ppid]
        if ($script:TerminalNames.ContainsKey($cur.Name)) { return @{ Name = $script:TerminalNames[$cur.Name]; Pid = $cur.Pid } }
    }
    return @{ Name = 'detached'; Pid = 0 }
}

function Get-McpNames {
    # MCP servers launched through npx/uvx show their package name on the wrapper's command line.
    param($Subtree)
    $names = @()
    foreach ($e in $Subtree) {
        $cmd = [string]$e.Proc.Cmd
        if ($e.Proc.Name -eq 'cmd.exe' -and $cmd -match 'npx\s+(?:\^"-y\^"\s+|"-y"\s+|-y\s+)?\^?"?(@?[\w.-]+(?:/[\w.-]+)?)(?:@[\w.-]+)?\^?"?') {
            $names += ($Matches[1] -replace '^@', '' -replace '-mcp-server$|-mcp$|^mcp-server-|^mcp-', '')
        }
        elseif ($e.Proc.Name -eq 'uvx.exe' -and $cmd -match 'uvx\s+([\w.-]+)') {
            $names += ($Matches[1] -replace '^mcp-server-|-mcp$', '')
        }
        elseif ($e.Proc.Name -eq 'java.exe' -and $cmd -match '([\w-]+)-mcp[\w.-]*\.jar') {
            $names += $Matches[1]
        }
        elseif ($e.Depth -eq 1 -and $e.Proc.Name -match '-mcp\.exe$') {
            $names += ($e.Proc.Name -replace '-mcp\.exe$', '')
        }
    }
    return @($names | Sort-Object -Unique)
}

function Get-Hog {
    # The heaviest child that crosses the CPU or memory bar, as "name 149m" / "name 1.3GB". Empty when none.
    param($Subtree)
    $worst = $null
    foreach ($e in $Subtree) {
        $p = $e.Proc
        $cpuHit = $p.CpuSec -ge $script:HogCpuSec
        $memHit = $p.WsKB -ge ($script:HogWsMB * 1024)
        if (-not ($cpuHit -or $memHit)) { continue }
        if (-not $worst -or $p.CpuSec -gt $worst.CpuSec) { $worst = $p }
    }
    if (-not $worst) { return '' }
    $name = $worst.Name -replace '\.exe$', ''
    if ($worst.CpuSec -ge $script:HogCpuSec) { return ('{0} {1}m cpu' -f $name, [math]::Floor($worst.CpuSec / 60)) }
    return ('{0} {1:N1}GB' -f $name, ($worst.WsKB / 1MB))
}

# ---------------------------------------------------------------- sessions
function Get-Sessions {
    # $CwdOf / $TitleOf are scriptblocks taking a pid; tests inject fakes, sysguard passes the win32 readers.
    param($Snap, [scriptblock]$CwdOf = { param($ProcId) Get-ProcCwd $ProcId }, [scriptblock]$TitleOf = { param($ProcId) Get-ProcConsoleTitle $ProcId }, [datetime]$Now = (Get-Date))
    $kids = Get-Children $Snap
    $out = @()
    foreach ($root in ($Snap.Values | Where-Object { $script:AgentNames -contains $_.Name } | Sort-Object Created)) {
        $tree = Get-Subtree $Snap $kids $root
        $ram  = $root.WsKB; $cpu = $root.CpuSec
        $shells = 0
        foreach ($e in $tree) {
            $ram += $e.Proc.WsKB; $cpu += $e.Proc.CpuSec
            if ($script:WorkShellNames -contains $e.Proc.Name) { $shells++ }
        }
        $term  = Get-TerminalOf $Snap $root
        $title = ConvertFrom-AgentTitle (& $TitleOf $root.Pid)
        $cwd   = & $CwdOf $root.Pid
        $out += [pscustomobject]@{
            Pid      = $root.Pid
            ShellPid = $root.Ppid
            Terminal = $term.Name
            Space    = ''
            Title    = $title.Title
            State    = $title.State
            IdleMin  = $null
            Cwd      = $cwd
            AgeMin   = if ($root.Created) { [math]::Floor(($Now - $root.Created).TotalMinutes) } else { 0 }
            RamMB    = [int]($ram / 1024)
            Procs    = 1 + $tree.Count
            Shells   = $shells
            Mcps     = Get-McpNames $tree
            Hog      = Get-Hog $tree
            CpuSec   = $cpu
            Tree     = $tree
        }
    }
    return ,@($out)
}

function Update-SessionActivity {
    # Fills State for sessions without a title glyph, from CPU movement between ticks
    # and live tool shells; on the first sighting the state stays unknown unless a
    # tool shell is running. Also stamps IdleMin for idle sessions. Mutates the rows.
    param($Sessions, [datetime]$Now = (Get-Date))
    $live = @{}
    foreach ($s in $Sessions) {
        $live[$s.Pid] = $true
        $prev = $script:SessionActivity[$s.Pid]
        $moved = $prev -and (($s.CpuSec - $prev.Cpu) -ge $script:ActiveCpuDelta)
        $busy = $moved -or ($s.Shells -gt 0)
        $first = -not $prev
        if ($first) { $script:SessionActivity[$s.Pid] = @{ Cpu = $s.CpuSec; LastActive = $Now } ; $prev = $script:SessionActivity[$s.Pid] }
        if ($busy) { $prev.LastActive = $Now }
        $prev.Cpu = $s.CpuSec
        if (-not $s.State) { $s.State = if ($busy) { 'working' } elseif (-not $first) { 'idle' } }
        if ($s.State -eq 'idle') { $s.IdleMin = [math]::Floor(($Now - $prev.LastActive).TotalMinutes) }
    }
    foreach ($k in @($script:SessionActivity.Keys)) { if (-not $live.ContainsKey($k)) { $script:SessionActivity.Remove($k) } }
}

# ---------------------------------------------------------------- herdr
function Get-HerdrExe {
    param($Snap)
    $h = $Snap.Values | Where-Object { $_.Name -eq 'herdr.exe' -and $_.Cmd -match '^"?([^"]+herdr\.exe)' } | Select-Object -First 1
    if ($h -and $h.Cmd -match '^"?([^"]+herdr\.exe)') { return $Matches[1] }
    return $null
}

function Get-HerdrSpaces {
    # Map agent pid -> workspace label via the herdr CLI. Returns @{} when herdr is not running.
    param([string]$Exe)
    $map = @{}
    if (-not $Exe -or -not (Test-Path $Exe)) { return $map }
    try {
        $ws = (& $Exe workspace list 2>$null | ConvertFrom-Json).result.workspaces
        $labels = @{}; foreach ($w in $ws) { $labels[$w.workspace_id] = $w.label }
        $panes = (& $Exe pane list 2>$null | ConvertFrom-Json).result.panes | Where-Object { $_.agent }
        foreach ($p in $panes) {
            $info = (& $Exe pane process-info --pane $p.pane_id 2>$null | ConvertFrom-Json).result.process_info
            foreach ($fp in $info.foreground_processes) {
                if ($script:AgentNames -contains $fp.name) { $map[[int]$fp.pid] = $labels[$p.workspace_id] }
            }
        }
    } catch {}
    return $map
}

function Merge-HerdrSpaces {
    param($Sessions, $SpaceMap)
    foreach ($s in $Sessions) { if ($SpaceMap.ContainsKey($s.Pid)) { $s.Space = $SpaceMap[$s.Pid] } }
}

# ---------------------------------------------------------------- output
function Format-SessionRow {
    param($S)
    $state = if ($S.State -eq 'idle' -and $S.IdleMin -ne $null) { 'idle {0}m' -f $S.IdleMin } elseif ($S.State) { $S.State } else { '?' }
    $where = if ($S.Space) { $S.Space } else { $S.Terminal }
    $name  = if ($S.Title) { $S.Title } elseif ($S.Cwd) { Split-Path $S.Cwd -Leaf } else { '' }
    return '{0,-16} {1,-40} {2,6} {3,5}m {4,-10} {5,6}MB {6,4} {7,-30} {8}' -f $where, $name, $S.Pid, $S.AgeMin, $state, $S.RamMB, $S.Procs, ($S.Mcps -join ','), $S.Hog
}

function Get-SessionKillList {
    # Deepest descendants first, the agent last, so nothing gets re-parented mid-kill.
    param($S)
    $list = @($S.Tree | Sort-Object Depth -Descending | ForEach-Object { $_.Proc })
    $root = [pscustomobject]@{ Pid = $S.Pid; Ppid = $S.ShellPid; Name = 'claude.exe'; WsKB = 0; Cmd = $S.Title }
    return ,@($list + $root)
}

# Pester 5+ tests for the session model. Synthetic snapshots, fake cwd/title readers.

BeforeAll {
    . (Join-Path $PSScriptRoot '..\rules.ps1')
    . (Join-Path $PSScriptRoot '..\sessions.ps1')
    $script:LogFile = $null

    $script:T0 = Get-Date '2026-01-01 12:00:00'

    function New-Row {
        param([int]$Id, [int]$Ppid, [string]$Name, [int]$AgeSec = 600, [int]$WsKB = 50000, [string]$Cmd = '', [int]$CpuSec = 0)
        [pscustomobject]@{ Pid = $Id; Ppid = $Ppid; Name = $Name; Created = $script:T0.AddSeconds(-$AgeSec); WsKB = $WsKB; Cmd = $Cmd; CpuSec = $CpuSec }
    }
    function New-Snap { param([object[]]$Rows) $snap = @{}; foreach ($r in $Rows) { $snap[$r.Pid] = $r }; return $snap }

    # warp -> powershell -> claude -> (npx notion: cmd -> node -> cmd -> node), (uvx linkedin), (java discord), bash tool shell
    function New-WarpSnap {
        New-Snap @(
            (New-Row 1 0 'warp.exe' -AgeSec 5000),
            (New-Row 2 1 'powershell.exe' -AgeSec 4900),
            (New-Row 10 2 'claude.exe' -AgeSec 3600 -WsKB 400000 -CpuSec 100),
            (New-Row 11 10 'cmd.exe' -Cmd 'C:\Windows\system32\cmd.exe /d /s /c "npx ^"-y^" ^"@notionhq/notion-mcp-server^""'),
            (New-Row 12 11 'node.exe' -WsKB 37000),
            (New-Row 13 12 'cmd.exe' -Cmd 'C:\Windows\system32\cmd.exe /d /s /c notion-mcp-server'),
            (New-Row 14 13 'node.exe' -WsKB 27000),
            (New-Row 15 10 'uvx.exe' -Cmd 'uvx mcp-server-linkedin@latest'),
            (New-Row 16 15 'python.exe' -WsKB 3000),
            (New-Row 17 10 'java.exe' -Cmd 'java -jar C:\x\discord-mcp\discord-mcp-1.0.0.jar' -WsKB 66000),
            (New-Row 18 10 'bash.exe' -AgeSec 10),
            (New-Row 19 10 'cmd.exe' -Cmd 'C:\Windows\system32\cmd.exe /d /s /c "npx ^"n8n-mcp^""'),
            (New-Row 20 10 'codebase-memory-mcp.exe'),
            (New-Row 30 0 'explorer.exe' -AgeSec 9000)
        )
    }
    $script:NoCwd   = { param($ProcId) 'C:\Coding\proj' }
    $script:NoTitle = { param($ProcId) $null }
}

Describe 'ConvertFrom-AgentTitle' {
    It 'reads the spinner glyph as working and strips it' {
        $r = ConvertFrom-AgentTitle ([string][char]0x25D0 + ' V2 rebuild')
        $r.State | Should -Be 'working'
        $r.Title | Should -Be 'V2 rebuild'
    }
    It 'reads the asterisk as idle' {
        $r = ConvertFrom-AgentTitle ([string][char]0x2733 + ' Okayu hcim')
        $r.State | Should -Be 'idle'
        $r.Title | Should -Be 'Okayu hcim'
    }
    It 'passes a plain title through with no state' {
        $r = ConvertFrom-AgentTitle 'C:\Windows\system32\cmd.exe'
        $r.State | Should -BeNullOrEmpty
        $r.Title | Should -Be 'C:\Windows\system32\cmd.exe'
    }
    It 'handles null and empty' {
        (ConvertFrom-AgentTitle $null).Title | Should -BeNullOrEmpty
        (ConvertFrom-AgentTitle '   ').State | Should -BeNullOrEmpty
    }
}

Describe 'Get-Sessions' {
    BeforeAll { $script:Sessions = Get-Sessions (New-WarpSnap) -CwdOf $script:NoCwd -TitleOf $script:NoTitle -Now $script:T0 }

    It 'finds one session per agent process' {
        $script:Sessions.Count | Should -Be 1
        $script:Sessions[0].Pid | Should -Be 10
        $script:Sessions[0].ShellPid | Should -Be 2
    }
    It 'attributes the session to its terminal' {
        $script:Sessions[0].Terminal | Should -Be 'Warp'
    }
    It 'sums RAM and counts processes over the whole subtree' {
        $s = $script:Sessions[0]
        $s.Procs | Should -Be 11
        $s.RamMB | Should -Be ([int]((400000 + 37000 + 27000 + 3000 + 66000 + 50000 * 6) / 1024))
    }
    It 'names the MCP servers from npx, uvx, jar and direct exe wrappers' {
        $script:Sessions[0].Mcps | Should -Be @('codebase-memory', 'discord', 'linkedin', 'n8n', 'notionhq/notion')
    }
    It 'counts live tool shells' {
        $script:Sessions[0].Shells | Should -Be 2   # bash.exe tool shell + python under uvx
    }
    It 'takes cwd from the reader and age from the agent process' {
        $script:Sessions[0].Cwd | Should -Be 'C:\Coding\proj'
        $script:Sessions[0].AgeMin | Should -Be 60
    }
    It 'reports detached when no terminal is above the agent' {
        $snap = New-Snap @((New-Row 10 999 'claude.exe'))
        (Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf $script:NoTitle)[0].Terminal | Should -Be 'detached'
    }
    It 'walks past herdr shells to the herdr host' {
        $snap = New-Snap @(
            (New-Row 1 0 'WindowsTerminal.exe' -AgeSec 9000), (New-Row 2 1 'powershell.exe' -AgeSec 8000),
            (New-Row 3 2 'herdr.exe' -AgeSec 7000 -Cmd '"C:\h\herdr.exe" --x'), (New-Row 4 3 'herdr.exe' -AgeSec 7000),
            (New-Row 5 4 'powershell.exe' -AgeSec 6000), (New-Row 10 5 'claude.exe')
        )
        (Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf $script:NoTitle)[0].Terminal | Should -Be 'herdr'
    }
    It 'returns an empty array when there is no agent' {
        $r = Get-Sessions (New-Snap @((New-Row 1 0 'explorer.exe'))) -CwdOf $script:NoCwd -TitleOf $script:NoTitle
        @($r).Count | Should -Be 0
    }
}

Describe 'Get-Hog' {
    It 'flags a child over the CPU bar with minutes' {
        $snap = New-Snap @((New-Row 10 1 'claude.exe'), (New-Row 11 10 'python3.13.exe' -CpuSec 8982))
        (Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf $script:NoTitle)[0].Hog | Should -Be 'python3.13 149m cpu'
    }
    It 'flags a child over the memory bar in GB' {
        $snap = New-Snap @((New-Row 10 1 'claude.exe'), (New-Row 11 10 'node.exe' -WsKB 1400000))
        (Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf $script:NoTitle)[0].Hog | Should -Match '^node 1[.,]3GB$'
    }
    It 'is empty for a quiet tree' {
        (Get-Sessions (New-WarpSnap) -CwdOf $script:NoCwd -TitleOf $script:NoTitle)[0].Hog | Should -Be ''
    }
}

Describe 'Update-SessionActivity' {
    BeforeEach { $script:SessionActivity = @{} }

    It 'keeps a title-derived state untouched' {
        $snap = New-Snap @((New-Row 10 1 'claude.exe'))
        $s = Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf { param($ProcId) [string][char]0x2733 + ' x' } -Now $script:T0
        Update-SessionActivity $s -Now $script:T0
        $s[0].State | Should -Be 'idle'
        $s[0].IdleMin | Should -Be 0
    }
    It 'derives working from CPU movement between ticks and idle from none' {
        $mk = { param($cpu) Get-Sessions (New-Snap @((New-Row 10 1 'claude.exe' -CpuSec $cpu))) -CwdOf $script:NoCwd -TitleOf $script:NoTitle -Now $script:T0 }
        $a = & $mk 100; Update-SessionActivity $a -Now $script:T0
        $a[0].State | Should -BeNullOrEmpty   # first sighting: unknown
        $b = & $mk 102; Update-SessionActivity $b -Now $script:T0.AddSeconds(5)
        $b[0].State | Should -Be 'working'
        $c = & $mk 102; Update-SessionActivity $c -Now $script:T0.AddMinutes(7)
        $c[0].State | Should -Be 'idle'
        $c[0].IdleMin | Should -Be 6
    }
    It 'counts a live tool shell as working' {
        $snap = New-Snap @((New-Row 10 1 'claude.exe'), (New-Row 11 10 'bash.exe'))
        $s = Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf $script:NoTitle -Now $script:T0
        Update-SessionActivity $s -Now $script:T0
        $s[0].State | Should -Be 'working'
    }
    It 'forgets sessions that are gone' {
        $s = Get-Sessions (New-Snap @((New-Row 10 1 'claude.exe'))) -CwdOf $script:NoCwd -TitleOf $script:NoTitle
        Update-SessionActivity $s
        Update-SessionActivity @()
        $script:SessionActivity.Count | Should -Be 0
    }
}

Describe 'herdr merge' {
    It 'labels sessions by pid and leaves the rest empty' {
        $snap = New-Snap @((New-Row 10 1 'claude.exe'), (New-Row 20 1 'claude.exe'))
        $s = Get-Sessions $snap -CwdOf $script:NoCwd -TitleOf $script:NoTitle
        Merge-HerdrSpaces $s @{ 10 = 'V2 Rebuild' }
        ($s | Where-Object Pid -eq 10).Space | Should -Be 'V2 Rebuild'
        ($s | Where-Object Pid -eq 20).Space | Should -Be ''
    }
    It 'finds the herdr executable from the snapshot' {
        $snap = New-Snap @((New-Row 3 1 'herdr.exe' -Cmd '"C:\Users\x\.herdr\releases\0.8\herdr.exe" --flag'))
        Get-HerdrExe $snap | Should -Be 'C:\Users\x\.herdr\releases\0.8\herdr.exe'
        Get-HerdrExe (New-Snap @((New-Row 1 0 'explorer.exe'))) | Should -BeNullOrEmpty
    }
    It 'returns an empty map without an executable' {
        (Get-HerdrSpaces $null).Count | Should -Be 0
        (Get-HerdrSpaces 'C:\nope\herdr.exe').Count | Should -Be 0
    }
}

Describe 'Get-SessionKillList' {
    It 'orders deepest descendants first and the agent last' {
        $s = (Get-Sessions (New-WarpSnap) -CwdOf $script:NoCwd -TitleOf $script:NoTitle)[0]
        $list = Get-SessionKillList $s
        $list.Count | Should -Be 11
        $list[0].Pid | Should -Be 14
        $list[-1].Pid | Should -Be 10
        # every parent comes after its child
        $pos = @{}; for ($i = 0; $i -lt $list.Count; $i++) { $pos[$list[$i].Pid] = $i }
        foreach ($e in $list) { if ($pos.ContainsKey($e.Ppid)) { $pos[$e.Ppid] | Should -BeGreaterThan $pos[$e.Pid] } }
    }
}

Describe 'Format-SessionRow' {
    It 'prefers the herdr space over the terminal and the title over the folder' {
        $s = (Get-Sessions (New-WarpSnap) -CwdOf $script:NoCwd -TitleOf { param($ProcId) [string][char]0x25D0 + ' Fix CI' } -Now $script:T0)[0]
        $row = Format-SessionRow $s
        $row | Should -Match '^Warp\s+Fix CI\s+10\s+60m\s+working'
        $s.Space = 'Security Audit'
        Format-SessionRow $s | Should -Match '^Security Audit'
    }
    It 'falls back to the folder name without a title' {
        $s = (Get-Sessions (New-WarpSnap) -CwdOf $script:NoCwd -TitleOf $script:NoTitle -Now $script:T0)[0]
        Format-SessionRow $s | Should -Match '^Warp\s+proj\s+'
    }
}

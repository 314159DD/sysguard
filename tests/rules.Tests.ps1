# Pester 5+ tests for the rule engine. All rules run against synthetic snapshots,
# so nothing here reads or kills real processes.

BeforeAll {
    . (Join-Path $PSScriptRoot '..\rules.ps1')
    $script:LogFile = $null   # no log file during tests

    $script:T0 = Get-Date '2026-01-01 12:00:00'

    function New-Row {
        param([int]$Id, [int]$Ppid, [string]$Name, [int]$AgeSec = 600, [int]$WsKB = 50000, [string]$Cmd = '')
        [pscustomobject]@{
            Pid     = $Id
            Ppid    = $Ppid
            Name    = $Name
            Created = $script:T0.AddSeconds(-$AgeSec)
            WsKB    = $WsKB
            Cmd     = $Cmd
        }
    }

    function New-Snap {
        param([object[]]$Rows)
        $snap = @{}
        foreach ($r in $Rows) { $snap[$r.Pid] = $r }
        return $snap
    }

    function Pids { param($Procs) @($Procs | ForEach-Object { $_.Pid } | Sort-Object) }
}

Describe 'Test-ParentDead' {
    It 'is dead when the parent pid is not in the snapshot' {
        $snap = New-Snap @((New-Row 10 1 'cmd.exe'))
        Test-ParentDead $snap $snap[10] | Should -BeTrue
    }

    It 'is alive when the parent exists and is older than the child' {
        $snap = New-Snap @((New-Row 1 0 'explorer.exe' -AgeSec 900), (New-Row 10 1 'cmd.exe' -AgeSec 600))
        Test-ParentDead $snap $snap[10] | Should -BeFalse
    }

    It 'treats a parent younger than its child as pid reuse, i.e. dead' {
        $snap = New-Snap @((New-Row 1 0 'chrome.exe' -AgeSec 10), (New-Row 10 1 'cmd.exe' -AgeSec 600))
        Test-ParentDead $snap $snap[10] | Should -BeTrue
    }
}

Describe 'Get-OrphanTrees' {
    It 'returns nothing when every helper has a live parent' {
        $snap = New-Snap @(
            (New-Row 1 0 'explorer.exe' -AgeSec 900),
            (New-Row 10 1 'cmd.exe'),
            (New-Row 11 10 'node.exe')
        )
        Get-OrphanTrees $snap | Should -BeNullOrEmpty
    }

    It 'takes a whole dead cmd -> node -> cmd -> node chain' {
        $snap = New-Snap @(
            (New-Row 10 999 'cmd.exe'),
            (New-Row 11 10 'node.exe'),
            (New-Row 12 11 'cmd.exe'),
            (New-Row 13 12 'node.exe')
        )
        Pids (Get-OrphanTrees $snap) | Should -Be @(10, 11, 12, 13)
    }

    It 'spares a dead-parent wrapper that still owns a living non-helper child, and its chain' {
        $snap = New-Snap @(
            (New-Row 10 999 'cmd.exe'),
            (New-Row 11 10 'cmd.exe'),
            (New-Row 12 11 'postgres.exe')
        )
        Get-OrphanTrees $snap | Should -BeNullOrEmpty
    }

    It 'keeps the protected chain but still takes an unrelated orphan' {
        $snap = New-Snap @(
            (New-Row 10 999 'cmd.exe'),
            (New-Row 11 10 'postgres.exe'),
            (New-Row 20 998 'node.exe'),
            (New-Row 21 20 'node.exe')
        )
        Pids (Get-OrphanTrees $snap) | Should -Be @(20, 21)
    }

    It 'leaves helper siblings of the protecting child alone, because their parent is alive' {
        # 10 is spared because of postgres (11). 12 is a helper under 10; 10 is alive from 12's point of view,
        # so 12 is not an orphan and must survive too.
        $snap = New-Snap @(
            (New-Row 10 999 'cmd.exe' -AgeSec 900),
            (New-Row 11 10 'postgres.exe'),
            (New-Row 12 10 'node.exe')
        )
        Get-OrphanTrees $snap | Should -BeNullOrEmpty
    }

    It 'never touches non-helper processes with a dead parent' {
        $snap = New-Snap @((New-Row 30 999 'notepad.exe'), (New-Row 31 999 'chrome.exe'))
        Get-OrphanTrees $snap | Should -BeNullOrEmpty
    }
}

Describe 'Get-StuckShells' {
    It 'flags an old shell with a tiny working set' {
        $snap = New-Snap @((New-Row 10 1 'powershell.exe' -AgeSec 120 -WsKB 480))
        Pids (Get-StuckShells $snap -Now $script:T0) | Should -Be @(10)
    }

    It 'ignores a young shell even with a tiny working set' {
        $snap = New-Snap @((New-Row 10 1 'powershell.exe' -AgeSec 5 -WsKB 480))
        Get-StuckShells $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'ignores an old shell that has grown past the working-set limit' {
        $snap = New-Snap @((New-Row 10 1 'pwsh.exe' -AgeSec 3600 -WsKB 60000))
        Get-StuckShells $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'never flags itself' {
        $snap = New-Snap @((New-Row $PID 1 'powershell.exe' -AgeSec 3600 -WsKB 100))
        Get-StuckShells $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'skips rows without a creation time' {
        $row = New-Row 10 1 'powershell.exe' -WsKB 100
        $row.Created = $null
        Get-StuckShells (New-Snap @($row)) -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'only looks at shells' {
        $snap = New-Snap @((New-Row 10 1 'conhost.exe' -AgeSec 3600 -WsKB 100))
        Get-StuckShells $snap -Now $script:T0 | Should -BeNullOrEmpty
    }
}

Describe 'Get-OrphanConhost' {
    It 'flags a conhost whose parent is gone and keeps one whose parent lives' {
        $snap = New-Snap @(
            (New-Row 1 0 'WindowsTerminal.exe' -AgeSec 900),
            (New-Row 10 1 'conhost.exe'),
            (New-Row 11 999 'conhost.exe')
        )
        Pids (Get-OrphanConhost $snap) | Should -Be @(11)
    }
}

Describe 'Get-FamilyStats and Test-ThresholdsCrossed' {
    It 'counts by executable name without the .exe suffix and sums working set in MB' {
        $snap = New-Snap @(
            (New-Row 10 1 'node.exe' -WsKB 1024),
            (New-Row 11 1 'node.exe' -WsKB 2048),
            (New-Row 12 1 'cmd.exe' -WsKB 512)
        )
        $fam = Get-FamilyStats $snap
        $fam['node'].Count | Should -Be 2
        $fam['node'].WsMB  | Should -Be 3
        $fam['cmd'].Count  | Should -Be 1
    }

    It 'reports only the families over their limit, as name=count' {
        $rows = @()
        for ($i = 0; $i -lt 45; $i++) { $rows += New-Row (100 + $i) 1 'powershell.exe' }
        for ($i = 0; $i -lt 10; $i++) { $rows += New-Row (200 + $i) 1 'node.exe' }
        $hits = Test-ThresholdsCrossed (Get-FamilyStats (New-Snap $rows))
        $hits | Should -Be @('powershell=45')
    }

    It 'is quiet at exactly the limit' {
        $rows = @()
        for ($i = 0; $i -lt 30; $i++) { $rows += New-Row (100 + $i) 1 'cmd.exe' }
        Test-ThresholdsCrossed (Get-FamilyStats (New-Snap $rows)) | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-Kill' {
    BeforeEach { Mock Stop-Process {} }

    It 'does not stop anything in dry-run mode and returns 0' {
        $snap = New-Snap @((New-Row 10 999 'cmd.exe'))
        Invoke-Kill $snap.Values 'test' $true | Should -Be 0
        Should -Invoke Stop-Process -Times 0
    }

    It 'stops each process once and reports the count' {
        $snap = New-Snap @((New-Row 10 999 'cmd.exe'), (New-Row 11 999 'node.exe'))
        Invoke-Kill $snap.Values 'test' $false | Should -Be 2
        Should -Invoke Stop-Process -Times 2 -Exactly
    }

    It 'counts a failed stop as not killed' {
        Mock Stop-Process { throw 'access denied' }
        $snap = New-Snap @((New-Row 10 999 'cmd.exe'))
        Invoke-Kill $snap.Values 'test' $false | Should -Be 0
    }

    It 'returns 0 for an empty list' {
        Invoke-Kill @() 'test' $false | Should -Be 0
    }
}

Describe 'Import-SysguardConfig' {
    It 'returns false and keeps defaults when there is no file' {
        Import-SysguardConfig (Join-Path $TestDrive 'missing.json') | Should -BeFalse
        $script:Thresholds['node'] | Should -Be 30
    }

    It 'overrides only the keys present in the file' {
        $path = Join-Path $TestDrive 'sysguard.config.json'
        '{ "thresholds": { "node": 50, "chrome": 80 }, "stuckShellMaxAgeSec": 45 }' | Set-Content -Path $path
        Import-SysguardConfig $path | Should -BeTrue
        $script:Thresholds['node']       | Should -Be 50
        $script:Thresholds['chrome']     | Should -Be 80
        $script:Thresholds['powershell'] | Should -Be 40
        $script:StuckShellMaxAgeSec      | Should -Be 45
        $script:StuckShellMaxWsKB        | Should -Be 2048
    }
}

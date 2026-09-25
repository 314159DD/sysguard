# Pester 5+ tests for the hygiene rules and system alerts. Synthetic snapshots and fixed
# clock, nothing here reads, stops or kills real processes.

BeforeAll {
    . (Join-Path $PSScriptRoot '..\rules.ps1')
    $script:LogFile = $null

    $script:T0 = Get-Date '2026-01-01 12:00:00'

    function New-Row {
        param([int]$Id, [int]$Ppid, [string]$Name, [int]$AgeMin = 1, [string]$Cmd = '')
        [pscustomobject]@{
            Pid     = $Id
            Ppid    = $Ppid
            Name    = $Name
            Created = $script:T0.AddMinutes(-$AgeMin)
            WsKB    = 5000
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

    $script:PgExe = 'C:\tools\pg17\bin\postgres.exe'
    function New-Postmaster {
        param([int]$Id, [string]$Dir, [int]$AgeMin, [int]$Ppid = 1)
        New-Row $Id $Ppid 'postgres.exe' -AgeMin $AgeMin -Cmd ('"{0}" -D "{1}" -p 55000' -f $script:PgExe, $Dir)
    }
}

Describe 'Get-StaleTools' {
    BeforeEach { $script:StaleToolMaxAgeMin = 10 }

    It 'returns search and tail tools older than the limit' {
        $snap = New-Snap @(
            (New-Row 10 1 'grep.exe' -AgeMin 30),
            (New-Row 11 1 'tail.exe' -AgeMin 600),
            (New-Row 12 1 'rg.exe'   -AgeMin 11)
        )
        Pids (Get-StaleTools $snap -Now $script:T0) | Should -Be @(10, 11, 12)
    }

    It 'leaves young tools alone' {
        $snap = New-Snap @((New-Row 10 1 'grep.exe' -AgeMin 2), (New-Row 11 1 'find.exe' -AgeMin 10))
        Get-StaleTools $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'ignores processes that are not on the tool list' {
        $snap = New-Snap @((New-Row 10 1 'node.exe' -AgeMin 999), (New-Row 11 1 'postgres.exe' -AgeMin 999))
        Get-StaleTools $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'matches names case-insensitively' {
        $snap = New-Snap @((New-Row 10 1 'GREP.EXE' -AgeMin 60))
        Pids (Get-StaleTools $snap -Now $script:T0) | Should -Be @(10)
    }

    It 'honours a configured age limit' {
        $script:StaleToolMaxAgeMin = 60
        $snap = New-Snap @((New-Row 10 1 'grep.exe' -AgeMin 30), (New-Row 11 1 'grep.exe' -AgeMin 90))
        Pids (Get-StaleTools $snap -Now $script:T0) | Should -Be @(11)
    }

    It 'never returns sysguard itself' {
        $script:SelfPid = 10
        $snap = New-Snap @((New-Row 10 1 'grep.exe' -AgeMin 60))
        Get-StaleTools $snap -Now $script:T0 | Should -BeNullOrEmpty
        $script:SelfPid = $PID
    }
}

Describe 'Get-PgDataDir' {
    It 'reads a quoted -D argument' {
        Get-PgDataDir '"C:\pg\bin\postgres.exe" -D "C:/lanes/pr 12" -p 5432' | Should -Be 'C:/lanes/pr 12'
    }
    It 'reads an unquoted -D argument' {
        Get-PgDataDir 'postgres.exe -D C:\lanes\pr12 -p 5432' | Should -Be 'C:\lanes\pr12'
    }
    It 'returns null without -D' {
        Get-PgDataDir '"C:\pg\bin\postgres.exe" --forkchild=backend' | Should -BeNullOrEmpty
    }
}

Describe 'Get-StalePgLanes' {
    BeforeEach {
        $script:PgLaneRoots = @('C:/lanes')
        $script:PgLaneMaxAgeMin = 120
    }

    It 'returns old postmasters under a lane root with data dir and pg_ctl next to postgres.exe' {
        $snap = New-Snap @((New-Postmaster 10 'C:/lanes/pr12' -AgeMin 300))
        $l = @(Get-StalePgLanes $snap -Now $script:T0)
        $l.Count | Should -Be 1
        $l[0].Proc.Pid | Should -Be 10
        $l[0].DataDir | Should -Be 'C:/lanes/pr12'
        $l[0].PgCtl | Should -Be 'C:\tools\pg17\bin\pg_ctl.exe'
    }

    It 'leaves lanes younger than the limit alone (a gate may be using them)' {
        $snap = New-Snap @((New-Postmaster 10 'C:/lanes/pr12' -AgeMin 30))
        Get-StalePgLanes $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'never touches clusters outside the lane roots' {
        $snap = New-Snap @((New-Postmaster 10 'C:/production/data' -AgeMin 9999))
        Get-StalePgLanes $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'does nothing when no lane root is configured' {
        $script:PgLaneRoots = @()
        $snap = New-Snap @((New-Postmaster 10 'C:/lanes/pr12' -AgeMin 9999))
        Get-StalePgLanes $snap -Now $script:T0 | Should -BeNullOrEmpty
    }

    It 'returns only the postmaster, not its postgres children' {
        $snap = New-Snap @(
            (New-Postmaster 10 'C:/lanes/pr12' -AgeMin 300),
            (New-Row 11 10 'postgres.exe' -AgeMin 300 -Cmd ('"{0}" --forkchild="checkpointer"' -f $script:PgExe)),
            (New-Row 12 10 'postgres.exe' -AgeMin 300 -Cmd ('"{0}" -D "C:/lanes/pr12" --forkchild' -f $script:PgExe))
        )
        (@(Get-StalePgLanes $snap -Now $script:T0) | ForEach-Object { $_.Proc.Pid }) | Should -Be @(10)
    }

    It 'compares roots and data dirs independent of slash direction and case' {
        $script:PgLaneRoots = @('c:\LANES')
        $snap = New-Snap @((New-Postmaster 10 'C:/lanes/pr12' -AgeMin 300))
        @(Get-StalePgLanes $snap -Now $script:T0).Count | Should -Be 1
    }
}

Describe 'Invoke-StopPgLanes' {
    It 'only logs in dry run and stops nothing' {
        $lane = [pscustomobject]@{ Proc = (New-Postmaster 10 'C:/lanes/pr12' -AgeMin 300); DataDir = 'C:/lanes/pr12'; PgCtl = 'C:\does\not\exist\pg_ctl.exe' }
        Mock Stop-Process {}
        Invoke-StopPgLanes @($lane) $true $script:T0 | Should -Be 0
        Should -Invoke Stop-Process -Times 0
    }
}

Describe 'Get-AlertsFrom' {
    BeforeEach {
        $script:HandleAlertCount = 100000
        $script:PoolAlertGB = 4
        $script:CommitAlertPct = 90
    }

    It 'reports a process with too many handles' {
        $rows = @([pscustomobject]@{ Name = 'Telemetry'; Id = 42; HandleCount = 1084002 }, [pscustomobject]@{ Name = 'ok'; Id = 1; HandleCount = 500 })
        $a = @(Get-AlertsFrom $rows 1 50)
        $a.Count | Should -Be 1
        $a[0] | Should -Match 'Telemetry \(pid 42\)'
    }

    It 'reports a bloated kernel pool and a high commit charge' {
        $a = @(Get-AlertsFrom @() 18.9 95)
        $a.Count | Should -Be 2
        $a[0] | Should -Match 'kernel pool 18.9 GB'
        $a[1] | Should -Match 'commit charge at 95'
    }

    It 'stays quiet on a healthy system' {
        Get-AlertsFrom @([pscustomobject]@{ Name = 'x'; Id = 1; HandleCount = 99999 }) 1.5 60 | Should -BeNullOrEmpty
    }
}

Describe 'Get-AlertKey' {
    It 'treats the same alert with different numbers as one' {
        (Get-AlertKey 'x (pid 42) holds 101,000 handles') | Should -Be (Get-AlertKey 'x (pid 42) holds 140,500 handles')
    }
    It 'keeps different alerts apart' {
        (Get-AlertKey 'kernel pool 5 GB') | Should -Not -Be (Get-AlertKey 'commit charge at 95 %')
    }
}

Describe 'Import-HygieneConfig' {
    It 'overrides only the keys present' {
        $script:StaleToolMaxAgeMin = 10
        $script:PgLaneMaxAgeMin = 120
        Import-HygieneConfig ([pscustomobject]@{ pgLaneRoots = @('D:/lanes'); pgLaneMaxAgeMin = 45 })
        $script:PgLaneRoots | Should -Be @('D:/lanes')
        $script:PgLaneMaxAgeMin | Should -Be 45
        $script:StaleToolMaxAgeMin | Should -Be 10
    }
}

# Pester 5+ tests for cpucap.ps1. Each case runs in a child PowerShell, so the test runner
# itself never ends up inside a capped job.

BeforeAll {
    $script:Cap = Join-Path $PSScriptRoot '..\cpucap.ps1'
    $script:Exe = (Get-Process -Id $PID).Path

    function Invoke-Child {
        param([string]$Body)
        $script = ". '{0}'; {1}" -f $script:Cap, $Body
        return (& $script:Exe -NoProfile -ExecutionPolicy Bypass -Command $script) -join "`n"
    }
}

Describe 'Enter-CpuCap' {
    It 'puts the shell into a job and lowers its priority' {
        $out = Invoke-Child "Enter-CpuCap -Percent 50 -Name ('Local\sysguard-test-' + `$PID); '{0}|{1}' -f [SysguardJob]::InJob(), (Get-Process -Id `$PID).PriorityClass"
        $out | Should -Be 'True|BelowNormal'
    }

    It 'passes the job on to child processes' {
        $out = Invoke-Child "Enter-CpuCap -Percent 50 -Name ('Local\sysguard-test-' + `$PID); `$c = Start-Process ping -ArgumentList '-n','3','127.0.0.1' -WindowStyle Hidden -PassThru; Start-Sleep -Milliseconds 500; (Get-Process -Id `$c.Id).PriorityClass; Stop-Process -Id `$c.Id -Force"
        $out | Should -Be 'BelowNormal'
    }

    It 'does nothing when SYSGUARD_CPUCAP is off' {
        $out = Invoke-Child "`$env:SYSGUARD_CPUCAP = 'off'; Enter-CpuCap -Percent 50; '{0}|{1}' -f [SysguardJob]::InJob(), (Get-Process -Id `$PID).PriorityClass"
        $out | Should -Be 'False|Normal'
    }

    It 'is idempotent: a second call keeps the shell in its job' {
        $out = Invoke-Child "Enter-CpuCap -Percent 50 -Name ('Local\sysguard-test-' + `$PID); Enter-CpuCap -Percent 50; [SysguardJob]::InJob()"
        $out | Should -Be 'True'
    }
}

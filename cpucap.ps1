# sysguard cpucap: legt die aktuelle PowerShell (und damit alles, was sie startet) in ein
# gemeinsames Windows Job Object mit hartem CPU-Deckel und BelowNormal-Prioritaet.
# Alle Agent-Sitzungen teilen sich EIN Job ("Local\sysguard-agents"), der Deckel gilt also
# fuer alle zusammen. Anlass 2026-09-25: volle Testsuiten mehrerer Agents haben die CPU auf
# 100 % gezogen, Maus und Fenster hingen.
#
# Nutzung (im PowerShell-Profil): . C:\Coding\III____Full_Circle\sysguard\cpucap.ps1
#                                 Enter-CpuCap -Percent 80
# Pruefen:  Get-CpuCapStatus

if (-not ('SysguardJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SysguardJob {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr attrs, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint len);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr proc, IntPtr job, out bool result);

    [StructLayout(LayoutKind.Sequential)]
    struct CpuRate { public uint ControlFlags; public uint CpuRateValue; }

    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimit {
        public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
    }

    static IntPtr job = IntPtr.Zero;   // Handle bleibt offen, solange diese PowerShell lebt

    public static string Enter(string name, uint percent) {
        job = CreateJobObject(IntPtr.Zero, name);
        if (job == IntPtr.Zero) return "CreateJobObject fehlgeschlagen: " + Marshal.GetLastWin32Error();

        var rate = new CpuRate { ControlFlags = 0x1 | 0x4, CpuRateValue = percent * 100 }; // ENABLE | HARD_CAP
        IntPtr p1 = Marshal.AllocHGlobal(Marshal.SizeOf(rate));
        Marshal.StructureToPtr(rate, p1, false);
        bool ok1 = SetInformationJobObject(job, 15, p1, (uint)Marshal.SizeOf(rate));
        Marshal.FreeHGlobal(p1);

        var lim = new BasicLimit { LimitFlags = 0x20, PriorityClass = 0x4000 }; // PRIORITY_CLASS, BELOW_NORMAL
        IntPtr p2 = Marshal.AllocHGlobal(Marshal.SizeOf(lim));
        Marshal.StructureToPtr(lim, p2, false);
        bool ok2 = SetInformationJobObject(job, 2, p2, (uint)Marshal.SizeOf(lim));
        Marshal.FreeHGlobal(p2);

        bool ok3 = AssignProcessToJobObject(job, GetCurrentProcess());
        int err = ok3 ? 0 : Marshal.GetLastWin32Error();
        return string.Format("cap={0} prio={1} assign={2}{3}", ok1, ok2, ok3, ok3 ? "" : " err=" + err);
    }

    public static bool InJob() {
        bool r; if (job == IntPtr.Zero) return false;
        IsProcessInJob(GetCurrentProcess(), job, out r); return r;
    }
}
'@
}

function Enter-CpuCap {
    param([ValidateRange(10, 100)][int]$Percent = 80, [string]$Name = 'Local\sysguard-agents')
    if ($env:SYSGUARD_CPUCAP -eq 'off') { return }
    if ([SysguardJob]::InJob()) { return }
    $r = [SysguardJob]::Enter($Name, [uint32]$Percent)
    if ($r -notmatch 'assign=True') { Write-Warning "sysguard cpucap: $r" }
}

function Get-CpuCapStatus {
    '{0} | Prioritaet dieser Shell: {1}' -f ($(if ([SysguardJob]::InJob()) { 'im Agent-Job (CPU-Deckel aktiv)' } else { 'nicht im Agent-Job' })), (Get-Process -Id $PID).PriorityClass
}

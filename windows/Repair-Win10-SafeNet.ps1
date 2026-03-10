<#
Repair-Win10-SafeNet.ps1
Batch-mode Windows 10 repair & malware cleanup script (Safe Mode with Networking required).

-----------------------------------------
References (kept INSIDE FILE as requested)
-----------------------------------------

Safe Mode detection (SM_CLEANBOOT):
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics

Start-Transcript logging:
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-7.5

DISM global options (/LogPath /LogLevel):
- https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-global-options-for-command-line-syntax?view=windows-11

DISM default log location info:
- C:\Windows\Logs\DISM\dism.log (also discussed here)
  https://learn.microsoft.com/en-us/answers/questions/3905260/how-to-analyze-dism-log

SFC log extraction example (CBS.log [SR] lines):
- https://learn.microsoft.com/en-gb/answers/questions/5543937/how-to-repair-your-system-files-using-dism-and-sfc

MSRT official download page (no hardcoded version; always latest monthly):
- https://www.microsoft.com/en-us/download/details.aspx?id=9905&lc=1033

MSRT scope (not a replacement for antivirus; targeted prevalent families):
- https://support.microsoft.com/en-us/topic/remove-specific-prevalent-malware-with-windows-malicious-software-removal-tool-kb890830-ba51b71f-39cd-cdec-73eb-61979b0661e0

Defender MpCmdRun.exe command line (SignatureUpdate + ScanType 2 = Full):
- https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
#>

[CmdletBinding()]
param(
    [string]$LogDir = "C:\RepairLogs",

    # Optional: Provide DISM repair source if Windows Update/component store is broken
    # Example: "D:\sources\install.wim" or "D:\sources\install.esd" or "X:\Mount\Windows"
    [string]$RepairSourcePath,

    # Controls
    [switch]$SkipDISM,
    [switch]$SkipSFC,
    [switch]$SkipMSRT,
    [switch]$SkipDefender
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------- Helpers --------------------
function Write-Log([string]$Message, [string]$Level = "INFO") {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$ts][$Level] $Message"
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BootMode {
    # SM_CLEANBOOT=67 -> 0 normal, 1 safe, 2 safe+network
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);
}
"@ -ErrorAction Stop | Out-Null
    return [NativeMethods]::GetSystemMetrics(67)
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Read-NewLines {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][ref]$LastIndex
    )
    if (-not (Test-Path $Path)) { return @() }

    # Read all lines; return only the new ones since LastIndex
    $lines = Get-Content -Path $Path -ErrorAction SilentlyContinue
    if ($null -eq $lines) { return @() }

    $start = $LastIndex.Value
    if ($start -lt 0) { $start = 0 }
    if ($start -ge $lines.Count) { return @() }

    $new = $lines[$start..($lines.Count-1)]
    $LastIndex.Value = $lines.Count
    return $new
}

function Invoke-ProcessWithLiveLogs {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$Arguments,
        [Parameter(Mandatory=$true)][string]$StdOutPath,
        [Parameter(Mandatory=$true)][string]$StdErrPath,
        [Parameter(Mandatory=$true)][string]$MergedLogPath,
        [string]$StageName = "Process",
        [int]$HeartbeatSeconds = 15
    )

    # Start process with stdout/stderr redirected to files,
    # and stream NEW lines from those files to console as they appear.
    Write-Log "=== Stage: $StageName ==="
    Write-Log "Running: $FilePath $Arguments"
    Write-Log "StdOut: $StdOutPath"
    Write-Log "StdErr: $StdErrPath"

    # Ensure clean files
    Remove-Item -Force -ErrorAction SilentlyContinue $StdOutPath, $StdErrPath, $MergedLogPath | Out-Null

    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
                       -NoNewWindow -PassThru `
                       -RedirectStandardOutput $StdOutPath `
                       -RedirectStandardError  $StdErrPath

    $outIdx = 0
    $errIdx = 0
    $lastActivity = Get-Date

    while (-not $p.HasExited) {
        $outNew = Read-NewLines -Path $StdOutPath -LastIndex ([ref]$outIdx)
        $errNew = Read-NewLines -Path $StdErrPath -LastIndex ([ref]$errIdx)

        foreach ($l in $outNew) { if ($l) { Write-Host $l; Add-Content -Path $MergedLogPath -Value $l } }
        foreach ($l in $errNew) { if ($l) { Write-Host $l; Add-Content -Path $MergedLogPath -Value $l } }

        if (($outNew.Count + $errNew.Count) -gt 0) {
            $lastActivity = Get-Date
        } else {
            $delta = (New-TimeSpan -Start $lastActivity -End (Get-Date)).TotalSeconds
            if ($delta -ge $HeartbeatSeconds) {
                Write-Log "$StageName still running..."
                $lastActivity = Get-Date
            }
        }

        Start-Sleep -Seconds 2
        $p.Refresh()
    }

    # Flush remaining output after exit
    $outNew = Read-NewLines -Path $StdOutPath -LastIndex ([ref]$outIdx)
    $errNew = Read-NewLines -Path $StdErrPath -LastIndex ([ref]$errIdx)
    foreach ($l in $outNew) { if ($l) { Write-Host $l; Add-Content -Path $MergedLogPath -Value $l } }
    foreach ($l in $errNew) { if ($l) { Write-Host $l; Add-Content -Path $MergedLogPath -Value $l } }

    Write-Log "$StageName ExitCode: $($p.ExitCode)"
    return $p.ExitCode
}

function Get-DirectMsrtUrlFromDownloadCenter {
    param([string]$DetailsPageUrl)

    # No hardcoded version: scrape the page for the current download.microsoft.com exe
    Write-Log "Fetching MSRT Download Center page: $DetailsPageUrl"
    $html = (Invoke-WebRequest -UseBasicParsing -Uri $DetailsPageUrl).Content

    $matches = [regex]::Matches($html, 'https://download\.microsoft\.com/[^"\\\s]+\.exe')
    if ($matches.Count -eq 0) {
        throw "Could not find direct MSRT download URL on the Download Center page."
    }

    $urls = $matches | ForEach-Object { $_.Value } | Select-Object -Unique
    # Prefer x64
    $best = $urls | Where-Object { $_ -match 'x64' } | Select-Object -First 1
    if ($best) { return $best }
    return ($urls | Select-Object -First 1)
}

function Download-LatestMSRT {
    param([string]$OutDir)

    $details = "https://www.microsoft.com/en-us/download/details.aspx?id=9905&lc=1033"
    $direct = Get-DirectMsrtUrlFromDownloadCenter -DetailsPageUrl $details
    Write-Log "MSRT direct URL: $direct"

    $fileName = Split-Path $direct -Leaf
    $dest = Join-Path $OutDir $fileName

    Write-Log "Downloading MSRT to: $dest"
    Invoke-WebRequest -UseBasicParsing -Uri $direct -OutFile $dest

    $sig = Get-AuthenticodeSignature -FilePath $dest
    Write-Log "MSRT Authenticode Status: $($sig.Status)"
    if ($sig.Status -ne "Valid") {
        throw "MSRT signature is not valid ($($sig.Status)). Refusing to run."
    }

    return $dest
}

function Find-MpCmdRun {
    $mp = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
    if (Test-Path $mp) { return $mp }

    $platRoot = Join-Path $env:ProgramData "Microsoft\Windows Defender\Platform"
    if (Test-Path $platRoot) {
        $latest = Get-ChildItem $platRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latest) {
            $candidate = Join-Path $latest.FullName "MpCmdRun.exe"
            if (Test-Path $candidate) { return $candidate }
        }
    }
    return $null
}

# -------------------- Pre-flight --------------------
if (-not (Test-IsAdmin)) { Write-Host "ERROR: Must run as Administrator."; exit 1 }

Ensure-Dir $LogDir

$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$transcript = Join-Path $LogDir "Repair-Win10-$stamp.transcript.log"

Start-Transcript -Path $transcript -Append -Force -IncludeInvocationHeader | Out-Null

try {
    Write-Log "=== Script started ==="
    Write-Log "Transcript: $transcript"
    Write-Log "LogDir: $LogDir"

    $bootMode = Get-BootMode
    if ($bootMode -ne 2) {
        Write-Log "ERROR: Must run in Safe Mode with Networking (SM_CLEANBOOT=2). Current=$bootMode" "ERROR"
        exit 2
    }
    Write-Log "Safe Mode with Networking confirmed."

    # -------------------- DISM --------------------
    if (-not $SkipDISM) {
        # DISM: create an explicit DISM log file using /LogPath and /LogLevel (documented global options)
        $dismLog = Join-Path $LogDir "dism_$stamp.log"
        $dismOut = Join-Path $LogDir "dism_stdout_$stamp.txt"
        $dismErr = Join-Path $LogDir "dism_stderr_$stamp.txt"
        $dismMerged = Join-Path $LogDir "dism_step_$stamp.txt"

        $args = "/Online /Cleanup-Image /RestoreHealth /LogPath:`"$dismLog`" /LogLevel:4"
        if ($RepairSourcePath) {
            $args = "/Online /Cleanup-Image /RestoreHealth /Source:`"$RepairSourcePath`" /LimitAccess /LogPath:`"$dismLog`" /LogLevel:4"
        }

        Invoke-ProcessWithLiveLogs -FilePath "$env:windir\System32\DISM.exe" `
            -Arguments $args `
            -StdOutPath $dismOut -StdErrPath $dismErr -MergedLogPath $dismMerged `
            -StageName "DISM RestoreHealth" -HeartbeatSeconds 15 | Out-Null

        Write-Log "DISM explicit log: $dismLog"
        Write-Log "DISM default log also exists at: C:\Windows\Logs\DISM\dism.log"
    } else {
        Write-Log "Skipping DISM." "WARN"
    }

    # -------------------- SFC --------------------
    if (-not $SkipSFC) {
        $sfcOut = Join-Path $LogDir "sfc_stdout_$stamp.txt"
        $sfcErr = Join-Path $LogDir "sfc_stderr_$stamp.txt"
        $sfcMerged = Join-Path $LogDir "sfc_step_$stamp.txt"

        Invoke-ProcessWithLiveLogs -FilePath "$env:windir\System32\sfc.exe" `
            -Arguments "/scannow" `
            -StdOutPath $sfcOut -StdErrPath $sfcErr -MergedLogPath $sfcMerged `
            -StageName "SFC /scannow" -HeartbeatSeconds 15 | Out-Null

        # Extract SFC lines from CBS.log (only SFC-tagged entries)
        $sfcExtract = Join-Path $LogDir "sfc_results_$stamp.txt"
        $cmd = 'findstr /c:"[SR]" %windir%\Logs\CBS\CBS.log > "' + $sfcExtract + '"'
        & "$env:windir\System32\cmd.exe" /c $cmd | Out-Null
        Write-Log "Saved SFC extraction: $sfcExtract"
    } else {
        Write-Log "Skipping SFC." "WARN"
    }

    # -------------------- MSRT (download latest, run) --------------------
    if (-not $SkipMSRT) {
        Write-Log "=== Stage: MSRT (download latest, then run) ==="
        $msrtDir = Join-Path $LogDir "MSRT"
        Ensure-Dir $msrtDir

        $msrtExe = Download-LatestMSRT -OutDir $msrtDir
        $msrtOut = Join-Path $LogDir "msrt_stdout_$stamp.txt"
        $msrtErr = Join-Path $LogDir "msrt_stderr_$stamp.txt"
        $msrtMerged = Join-Path $LogDir "msrt_step_$stamp.txt"

        # Quiet + forced full scan + auto-clean
        Invoke-ProcessWithLiveLogs -FilePath $msrtExe `
            -Arguments "/Q /F:Y" `
            -StdOutPath $msrtOut -StdErrPath $msrtErr -MergedLogPath $msrtMerged `
            -StageName "MSRT /Q /F:Y" -HeartbeatSeconds 15 | Out-Null

        $mrtLog = Join-Path $env:windir "debug\mrt.log"
        if (Test-Path $mrtLog) {
            $dest = Join-Path $LogDir "mrt_$stamp.log"
            Copy-Item $mrtLog $dest -Force
            Write-Log "Copied MSRT log: $dest"
        } else {
            Write-Log "MSRT log not found at $mrtLog." "WARN"
        }
    } else {
        Write-Log "Skipping MSRT." "WARN"
    }

    # -------------------- Defender (FULL scan by default, AFTER MSRT) --------------------
    if (-not $SkipDefender) {
        Write-Log "=== Stage: Microsoft Defender (after MSRT) ==="
        $mp = Find-MpCmdRun
        if (-not $mp) {
            Write-Log "MpCmdRun.exe not found; skipping Defender." "WARN"
        } else {
            # Signature update
            $defUpOut = Join-Path $LogDir "defender_update_stdout_$stamp.txt"
            $defUpErr = Join-Path $LogDir "defender_update_stderr_$stamp.txt"
            $defUpMerged = Join-Path $LogDir "defender_signatureupdate_$stamp.txt"

            Invoke-ProcessWithLiveLogs -FilePath $mp `
                -Arguments "-SignatureUpdate" `
                -StdOutPath $defUpOut -StdErrPath $defUpErr -MergedLogPath $defUpMerged `
                -StageName "Defender SignatureUpdate" -HeartbeatSeconds 15 | Out-Null

            # FULL scan by default (ScanType 2)
            $scanType = if ($DefenderScan -eq "Quick") { 1 } else { 2 }

            $defScanOut = Join-Path $LogDir "defender_scan_stdout_$stamp.txt"
            $defScanErr = Join-Path $LogDir "defender_scan_stderr_$stamp.txt"
            $defScanMerged = Join-Path $LogDir "defender_scan_$stamp.txt"

            Invoke-ProcessWithLiveLogs -FilePath $mp `
                -Arguments "-Scan -ScanType $scanType" `
                -StdOutPath $defScanOut -StdErrPath $defScanErr -MergedLogPath $defScanMerged `
                -StageName "Defender Scan (ScanType $scanType)" -HeartbeatSeconds 15 | Out-Null
        }
    } else {
        Write-Log "Skipping Defender." "WARN"
    }

    Write-Log "=== Script finished successfully ==="
    Write-Log "All outputs are under: $LogDir"
}
catch {
    Write-Log "Unhandled error: $($_.Exception.Message)" "ERROR"
    Write-Log $_.Exception.ToString() "ERROR"
    exit 99
}
finally {
    Stop-Transcript | Out-Null
}

<#
Repair-Win10-SafeNet.ps1
Batch-mode Windows 10 repair & malware cleanup script.
REQUIRES: Safe Mode with Networking
DEFAULT: MSRT (download latest) -> Defender SignatureUpdate -> Defender FULL scan

Run
powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\Path\Repair-Win10-SafeNet.ps1
quick scan
powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\Path\Repair-Win10-SafeNet.ps1 -DefenderScan Quick
DISM repair source
powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\Path\Repair-Win10-SafeNet.ps1 -RepairSourcePath "D:\sources\install.wim"

========================
REFERENCES (by section)
========================

Safe Mode detection (GetSystemMetrics / SM_CLEANBOOT)
- Microsoft Learn: GetSystemMetrics (SM_CLEANBOOT: 0 normal, 1 safe, 2 safe+network)
  https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics  # 【1-c1d771】

Logging (Start-Transcript)
- Microsoft Learn: Start-Transcript
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.host/start-transcript?view=powershell-7.5  # 【2-0ba4d3】

OS corruption repair (DISM + SFC)
- Microsoft Support: DISM then SFC guidance
  https://support.microsoft.com/en-us/topic/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e  # 【3-66968d】
- Microsoft Learn: Repair a Windows Image (DISM /RestoreHealth /Source)
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image?view=windows-11  # 【4-1c23ca】
- SFC log extraction example (findstr [SR] from CBS.log)
  https://learn.microsoft.com/en-gb/answers/questions/5543937/how-to-repair-your-system-files-using-dism-and-sfc  # 【9-203b68】

MSRT (download latest before run)
- Official Microsoft Download Center page (always points to latest monthly MSRT)
  https://www.microsoft.com/en-us/download/details.aspx?id=9905&lc=1033  # 【5-98e16e】
- MSRT scope: not a replacement for antivirus; targets prevalent families
  https://support.microsoft.com/en-us/topic/remove-specific-prevalent-malware-with-windows-malicious-software-removal-tool-kb890830-ba51b71f-39cd-cdec-73eb-61979b0661e0  # 【6-9a28c3】

Defender command-line (MpCmdRun.exe)
- Microsoft Learn: MpCmdRun.exe ScanType + SignatureUpdate
  https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus  # 【7-62378a】
- Example internal mitigation uses MpCmdRun.exe -SignatureUpdate
  (grounding that this is a valid action in practice)
  # 【8-187de9】
#>

[CmdletBinding()]
param(
    [string]$LogDir = "C:\RepairLogs",

    # Default is FULL scan after MSRT (per your request)
    [ValidateSet("Full","Quick")]
    [string]$DefenderScan = "Full",

    # Optional: Provide DISM repair source if Windows Update is broken
    # Example: "D:\sources\install.wim" or a mounted Windows folder path
    [string]$RepairSourcePath,

    [switch]$SkipDISM,
    [switch]$SkipSFC,
    [switch]$SkipMSRT,
    [switch]$SkipDefender
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-BootMode {
    # SM_CLEANBOOT reference: GetSystemMetrics(SM_CLEANBOOT=67) 【1-c1d771】
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

function Write-Log([string]$Message, [string]$Level = "INFO") {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "[$ts][$Level] $Message"
}

function Invoke-External([string]$FilePath, [string]$Arguments) {
    Write-Log "Running: $FilePath $Arguments"
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $FilePath
    $pinfo.Arguments = $Arguments
    $pinfo.UseShellExecute = $false
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError  = $true
    $pinfo.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stdout) { $stdout.TrimEnd() | ForEach-Object { Write-Log $_ "OUT" } }
    if ($stderr) { $stderr.TrimEnd() | ForEach-Object { Write-Log $_ "ERR" } }
    Write-Log "ExitCode: $($p.ExitCode)"
    return $p.ExitCode
}

function Get-DirectMsrtUrlFromDownloadCenter {
    param([string]$DetailsPageUrl)

    Write-Log "Fetching MSRT download page HTML: $DetailsPageUrl"

    # NOTE: This queries the Download Center page and extracts the current direct download URL.
    # No MSRT version is hardcoded here. The page always points to the latest release. 【5-98e16e】
    $html = (Invoke-WebRequest -UseBasicParsing -Uri $DetailsPageUrl).Content

    # Find direct download.microsoft.com EXE links embedded in the page.
    $matches = [regex]::Matches($html, 'https://download\.microsoft\.com/[^"\\\s]+\.exe')
    if ($matches.Count -eq 0) {
        throw "Could not find a direct MSRT download.microsoft.com EXE link on the page."
    }

    # Prefer x64 build explicitly (your machine is x64)
    $urls = $matches | ForEach-Object { $_.Value } | Select-Object -Unique
    $best = $urls | Where-Object { $_ -match 'x64' } | Select-Object -First 1
    if (-not $best) { $best = $urls | Select-Object -First 1 }

    return $best
}

function Download-LatestMSRT {
    param([string]$OutDir)

    # Official MSRT Download Center page (no version hardcoding) 【5-98e16e】
    $details = "https://www.microsoft.com/en-us/download/details.aspx?id=9905&lc=1033"

    $direct = Get-DirectMsrtUrlFromDownloadCenter -DetailsPageUrl $details
    Write-Log "Direct MSRT URL found: $direct"

    $fileName = Split-Path $direct -Leaf
    $dest = Join-Path $OutDir $fileName

    Write-Log "Downloading MSRT to: $dest"
    Invoke-WebRequest -UseBasicParsing -Uri $direct -OutFile $dest

    # Verify Authenticode signature is valid before executing.
    $sig = Get-AuthenticodeSignature -FilePath $dest
    Write-Log "MSRT Authenticode Status: $($sig.Status)"
    if ($sig.Status -ne "Valid") {
        throw "MSRT signature is not valid ($($sig.Status)). Refusing to run."
    }

    return $dest
}

function Find-MpCmdRun {
    # MpCmdRun.exe location guidance 【7-62378a】
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
if (-not (Test-IsAdmin)) { Write-Output "ERROR: Must run as Administrator."; exit 1 }

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }

$stamp  = (Get-Date).ToString("yyyyMMdd-HHmmss")
$LogFile = Join-Path $LogDir "Repair-Win10-$stamp.log"

# Start-Transcript reference 【2-0ba4d3】
Start-Transcript -Path $LogFile -Append -Force -IncludeInvocationHeader | Out-Null

try {
    Write-Log "=== Repair script started ==="
    Write-Log "LogFile: $LogFile"
    Write-Log "OS: $([System.Environment]::OSVersion.VersionString)"

    # Require Safe Mode with Networking: SM_CLEANBOOT == 2 【1-c1d771】
    $bootMode = Get-BootMode
    if ($bootMode -ne 2) {
        Write-Log "This script requires Safe Mode with Networking (SM_CLEANBOOT=2). Current: $bootMode" "ERROR"
        exit 2
    }
    Write-Log "BootMode: Safe Mode with Networking confirmed (SM_CLEANBOOT=2)."

    # -------------------- DISM then SFC --------------------
    if (-not $SkipDISM) {
        $dismArgs = "/Online /Cleanup-Image /RestoreHealth"
        if ($RepairSourcePath) {
            # Repair-a-Windows-Image (/Source, /LimitAccess) 【4-1c23ca】
            $dismArgs = "/Online /Cleanup-Image /RestoreHealth /Source:`"$RepairSourcePath`" /LimitAccess"
        }
        Invoke-External -FilePath "$env:windir\System32\DISM.exe" -Arguments $dismArgs | Out-Null
    } else {
        Write-Log "Skipping DISM." "WARN"
    }

    if (-not $SkipSFC) {
        Invoke-External -FilePath "$env:windir\System32\sfc.exe" -Arguments "/scannow" | Out-Null

        # Extract SFC lines from CBS.log (findstr [SR]) 【9-203b68】
        $sfcExtract = Join-Path $LogDir "sfc_results_$stamp.txt"
        $cmd = "findstr /c:""[SR]"" %windir%\Logs\CBS\CBS.log > `"$sfcExtract`""
        Invoke-External -FilePath "$env:windir\System32\cmd.exe" -Arguments "/c $cmd" | Out-Null
        Write-Log "Saved SFC extraction: $sfcExtract"
    } else {
        Write-Log "Skipping SFC." "WARN"
    }

    # -------------------- MSRT: download latest (no version hardcode), verify, run --------------------
    if (-not $SkipMSRT) {
        $msrtOut = Join-Path $LogDir "MSRT"
        New-Item -Path $msrtOut -ItemType Directory -Force | Out-Null

        # Download Center page points to latest monthly MSRT 【5-98e16e】
        $msrtExe = Download-LatestMSRT -OutDir $msrtOut
        Write-Log "Running downloaded MSRT package: $msrtExe"

        # MSRT is a targeted removal tool (not full AV) 【6-9a28c3】
        Invoke-External -FilePath $msrtExe -Arguments "/Q /F:Y" | Out-Null

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

    # -------------------- Defender: SignatureUpdate then FULL scan (default) AFTER MSRT --------------------
    if (-not $SkipDefender) {
        $mp = Find-MpCmdRun
        if (-not $mp) {
            Write-Log "MpCmdRun.exe not found; skipping Defender." "WARN"
        } else {
            # SignatureUpdate supported by MpCmdRun.exe 【7-62378a】【8-187de9】
            Invoke-External -FilePath $mp -Arguments "-SignatureUpdate" | Out-Null

            $scanType = if ($DefenderScan -eq "Full") { 2 } else { 1 }
            # ScanType values: 1 Quick, 2 Full 【7-62378a】
            Invoke-External -FilePath $mp -Arguments "-Scan -ScanType $scanType" | Out-Null
        }
    } else {
        Write-Log "Skipping Defender." "WARN"
    }

    Write-Log "=== Repair script finished ==="
}
catch {
    Write-Log "Unhandled error: $($_.Exception.Message)" "ERROR"
    Write-Log $_.Exception.ToString() "ERROR"
    exit 99
}
finally {
    Stop-Transcript | Out-Null
}

<#
.SYNOPSIS
  Hyper-V DDA audit/fix tool with NVIDIA-only deep scan, orphan detection/removal, and safe action planning.

.DESCRIPTION
  FAST FAIL:
    - Any timed stage that exceeds -TimeoutSec throws and the script stops.
    - Any critical Hyper-V query failure throws and the script stops.

  AUDIT (default):
    - Lists all DDA devices attached to the VM via Get-VMAssignableDevice (fast, includes non-NVIDIA).
    - Lists host-assignable devices via Get-VMHostAssignableDevice.
    - Deep scans NVIDIA devices only (VEN_10DE) to build a LocationPath index.
    - Flags potentially stale/orphaned attached devices.

  FIX (optional):
    - Prints a plan, prompts for approval unless -Force.
    - Applies DDA-friendly VM settings:
        * AutomaticStopAction = TurnOff
        * GuestControlledCacheTypes = true
        * Low MMIO default = 3Gb (override with -LowMMIO)
        * High MMIO default = 33280Mb (override with -HighMMIO)
        * Disables checkpoints (unless -SkipCheckpointDisable)
    - Optional -RemoveOrphaned: removes orphaned/unavailable devices from VM.
    - Assigns NVIDIA device group (all NVIDIA functions sharing same root) if not already attached:
        * Disable PnP device
        * Dismount from host ONLY if it is mounted/host-assignable
        * Add-VMAssignableDevice

  VM power state:
    - If VM is Off when the script starts: it remains Off even after -Fix.
    - If VM is On when the script starts: it is stopped for changes and started at the end.

.PARAMETER VmName
  VM name. If omitted, script lists VMs and exits.

.PARAMETER List
  List VMs and any attached DDA devices, then exit.

.PARAMETER Fix
  Apply changes (plan + approval).

.PARAMETER RemoveOrphaned
  With -Fix: remove orphaned/unavailable devices from VM config.

.PARAMETER Force
  With -Fix: skip approval prompt.

.PARAMETER LowMMIO
    Default: 3Gb (matches your proven script). Override allowed. [1](https://microsofteur-my.sharepoint.com/personal/iregev_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/assign_gpu_to_vm.txt)

.PARAMETER HighMMIO
    Default: 33280Mb (matches your proven script). Override allowed. [1](https://microsofteur-my.sharepoint.com/personal/iregev_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/assign_gpu_to_vm.txt)

.PARAMETER SkipCheckpointDisable
  Skip disabling checkpoints (not recommended for DDA).

.PARAMETER DeepAllPnPScan
  Also index ALL PnP devices to validate non-NVIDIA LocationPaths. Can be slow.

.PARAMETER TimeoutSec
  Timeout per stage (seconds). Default 45.

.EXAMPLES
  .\Check-HyperV-DDA.ps1 -List
  .\Check-HyperV-DDA.ps1 -VmName "ubuntu"
  .\Check-HyperV-DDA.ps1 -VmName "ubuntu" -Fix -RemoveOrphaned
  .\Check-HyperV-DDA.ps1 -VmName "ubuntu" -Fix -RemoveOrphaned -Force
    .\Check-HyperV-DDA.ps1 -VmName "ubuntu" -Fix -LowMMIO 3Gb -HighMMIO 33280Mb -Force
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification='False positive in this script: variables are used across staged flow.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSPossibleIncorrectComparisonWithNull', '', Justification='Comparisons already place $null on the left; warning is stale/incorrect here.')]
param(
    [string]$VmName,
    [switch]$List,

    [switch]$Fix,
    [switch]$RemoveOrphaned,
    [switch]$Force,

    [string]$LowMMIO = "3Gb",
    [string]$HighMMIO = "33280Mb",

    [switch]$SkipCheckpointDisable,
    [switch]$DeepAllPnPScan,

    [int]$TimeoutSec = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- output helpers ----------------
function NowText { (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
function Section([string]$t){ Write-Host ""; Write-Host ("=== {0} ===" -f $t) -ForegroundColor Cyan }
function Stage([string]$t){ Write-Host ("[{0}] >>> {1}" -f (NowText), $t) -ForegroundColor Magenta }
function OK([string]$t){ Write-Host ("[ OK ] {0}" -f $t) -ForegroundColor Green }
function WARN([string]$t){ Write-Host ("[WARN] {0}" -f $t) -ForegroundColor Yellow }
function FAIL([string]$t){ Write-Host ("[FAIL] {0}" -f $t) -ForegroundColor Red }
function INFO([string]$t){ Write-Host ("[INFO] {0}" -f $t) -ForegroundColor Gray }
function IsNull([object]$v){ [object]::ReferenceEquals($v, $null) }

function HasCommand([string]$name) {
    return (-not (IsNull (Get-Command $name -ErrorAction SilentlyContinue)))
}

function HasSetVmParameter([string]$name) {
    $cmd = Get-Command Set-VM -ErrorAction SilentlyContinue
    if(IsNull $cmd){ return $false }
    return $cmd.Parameters.ContainsKey($name)
}

function ValidateEnvironmentSupport {
    $required = @(
        'Get-VM', 'Set-VM',
        'Get-VMAssignableDevice', 'Add-VMAssignableDevice', 'Remove-VMAssignableDevice',
        'Get-VMHostAssignableDevice', 'Dismount-VMHostAssignableDevice',
        'Get-PnpDevice', 'Get-PnpDeviceProperty', 'Disable-PnpDevice'
    )

    $missing = @()
    foreach($n in $required){
        if(-not (HasCommand $n)){ $missing += $n }
    }

    if($missing.Count -gt 0){
        throw ("Required commands missing: {0}" -f ($missing -join ', '))
    }

    $requiredSetVmParams = @('Name', 'AutomaticStopAction', 'GuestControlledCacheTypes', 'LowMemoryMappedIoSpace', 'HighMemoryMappedIoSpace', 'CheckpointType', 'AutomaticCheckpointsEnabled')
    $missingSetVmParams = @()
    foreach($p in $requiredSetVmParams){
        if(-not (HasSetVmParameter $p)){ $missingSetVmParams += $p }
    }

    if($missingSetVmParams.Count -gt 0){
        throw ("Set-VM missing required parameter(s): {0}" -f ($missingSetVmParams -join ', '))
    }

}

function ConvertToMmioBytes([object]$value, [string]$name) {
    if(IsNull $value){ throw ("{0} cannot be null." -f $name) }

    if($value -is [uint64] -or $value -is [int64] -or $value -is [int32]){
        return [uint64]$value
    }

    $s = [string]$value
    if([string]::IsNullOrWhiteSpace($s)){ throw ("{0} cannot be empty." -f $name) }
    $t = $s.Trim()

    if($t -match '^(?<n>\d+)\s*(?<u>[KMG]b)?$'){
        $num = [uint64]$Matches['n']
        $unit = $Matches['u']
        switch($unit){
            'Kb' { return $num * 1KB }
            'Mb' { return $num * 1MB }
            'Gb' { return $num * 1GB }
            default { return $num }
        }
    }

    throw ("Invalid {0} value '{1}'. Use bytes or suffix Kb/Mb/Gb (example: 3Gb, 33280Mb)." -f $name, $s)
}

function Timed([string]$name, [scriptblock]$sb) {
    Stage $name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $sb
        return $result
    }
    finally {
        $sw.Stop()
        INFO (("{0} finished in {1:n2}s" -f $name, $sw.Elapsed.TotalSeconds))
    }
}

function RunWithTimeout([string]$name, [int]$sec, [scriptblock]$sb, $argList = $null) {
    Stage (("{0} (timeout {1}s)" -f $name, $sec))
    $job = if(-not (IsNull $argList)){ Start-Job -ScriptBlock $sb -ArgumentList $argList } else { Start-Job -ScriptBlock $sb }
    if (-not (Wait-Job $job -Timeout $sec)) {
        Stop-Job $job -Force | Out-Null
        Remove-Job $job -Force | Out-Null
        throw ("Timeout waiting for: {0}" -f $name)
    }
    $out = Receive-Job $job
    Remove-Job $job -Force | Out-Null
    return $out
}

# ---------------- VM listing ----------------
function ShowVms {
    Section "Available VMs"
    $vms = Get-VM | Sort-Object Name
    if(-not $vms){
        WARN "No VMs found on this host."
        return
    }

    foreach($v in $vms){
        $dda = @()
        try { $dda = Get-VMAssignableDevice -VMName $v.Name -ErrorAction SilentlyContinue } catch { $dda = @() }
        $paths = if($dda -and $dda.Count -gt 0){ ($dda | Select-Object -ExpandProperty LocationPath) -join "; " } else { "(none)" }
        Write-Host ("{0,-28}  {1,-8}  DDA: {2}" -f $v.Name, $v.State, $paths)
    }
}

# ---------------- Host / PnP queries ----------------
function GetHostAssignableSet {
    $set = @{}
    $had = RunWithTimeout "Get-VMHostAssignableDevice" $TimeoutSec { Get-VMHostAssignableDevice }
    foreach($d in $had){
        if($d.LocationPath){ $set[$d.LocationPath] = $true }
    }
    return $set
}

function GetVmAssignableDevices([string]$vm) {
    return RunWithTimeout ("Get-VMAssignableDevice -VMName {0}" -f $vm) $TimeoutSec {
        param($n)
        Get-VMAssignableDevice -VMName $n -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject]@{
                    LocationPath   = $_.LocationPath
                    InstanceId     = $_.InstanceId
                    VMCheckpointId = $_.VMCheckpointId
                    VMCheckpointName = $_.VMCheckpointName
                    ResourcePoolName = $_.ResourcePoolName
                }
            }
    } $vm
}

function GetNvidiaPnPDevices {
    # ALL NVIDIA functions (audio/usb/etc too): Vendor 10DE
    return RunWithTimeout "Get-PnpDevice NVIDIA (VEN_10DE)" $TimeoutSec {
        Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VEN_10DE' }
    }
}

function GetLocationPaths([string]$instanceId) {
    return RunWithTimeout ("Get-PnpDeviceProperty LocationPaths ({0})" -f $instanceId) $TimeoutSec {
        param($iid)
        (Get-PnpDeviceProperty -InstanceId $iid -KeyName 'DEVPKEY_Device_LocationPaths' -ErrorAction SilentlyContinue).Data
    } $instanceId
}

function RootFromLocationPath([string]$lp) {
    # Group functions by removing trailing "#PCI(xxxx)" segment
    $idx = $lp.LastIndexOf("#PCI(")
    if($idx -gt 0){ return $lp.Substring(0, $idx) }
    return $lp
}

function BuildNvidiaIndex {
    $locMap = @{}
    $rootMap = @{}

    $nv = GetNvidiaPnPDevices
    $total = $nv.Count
    INFO (("NVIDIA PnP device count: {0}" -f $total))

    $i = 0
    foreach($dev in $nv){
        $i++
        if(($i % 10) -eq 0){
            Write-Progress -Activity "Indexing NVIDIA LocationPaths" -Status ("{0}/{1}" -f $i, $total) -PercentComplete (100*$i/$total)
        }

        $locs = @(GetLocationPaths $dev.InstanceId)
        foreach($lp in ($locs | Where-Object { $_ })){
            if(-not $locMap.ContainsKey($lp)){
                $root = RootFromLocationPath $lp
                $locMap[$lp] = @{
                    InstanceId = $dev.InstanceId
                    Name       = $dev.FriendlyName
                    Class      = $dev.Class
                    Root       = $root
                }
                if(-not $rootMap.ContainsKey($root)){
                    $rootMap[$root] = New-Object System.Collections.Generic.List[string]
                }
                [void]$rootMap[$root].Add($lp)
            }
        }
    }
    Write-Progress -Activity "Indexing NVIDIA LocationPaths" -Completed

    INFO (("NVIDIA LocationPaths indexed: {0}" -f $locMap.Count))
    return [pscustomobject]@{ LocMap=$locMap; RootMap=$rootMap }
}

function BuildAllPnPIndex {
    $set = @{}
    $pnps = RunWithTimeout "Get-PnpDevice -PresentOnly (ALL)" ($TimeoutSec * 4) { Get-PnpDevice -PresentOnly }
    $total = $pnps.Count
    INFO (("All PnP device count: {0}" -f $total))

    $i = 0
    foreach($p in $pnps){
        $i++
        if(($i % 50) -eq 0){
            Write-Progress -Activity "Indexing ALL PnP LocationPaths" -Status ("{0}/{1}" -f $i, $total) -PercentComplete (100*$i/$total)
        }
        try{
            $loc = (Get-PnpDeviceProperty -InstanceId $p.InstanceId -KeyName 'DEVPKEY_Device_LocationPaths' -ErrorAction SilentlyContinue).Data
            foreach($lp in ($loc | Where-Object { $_ })){
                $set[$lp] = $true
            }
        } catch { }
    }
    Write-Progress -Activity "Indexing ALL PnP LocationPaths" -Completed

    INFO (("ALL PnP LocationPaths indexed: {0}" -f $set.Count))
    return $set
}

# ---------------- DDA operations ----------------
function EnsureDisabled([string]$instanceId) {
    $dev = Get-PnpDevice -InstanceId $instanceId -ErrorAction Stop
    if(($dev.Status -like "*Disabled*") -or ($dev.Problem -eq 22)){ return }
    Disable-PnpDevice -InstanceId $instanceId -Confirm:$false -ErrorAction Stop | Out-Null
}

function DismountIfNeeded([string]$locationPath, [hashtable]$hostAssignableSet) {
    if($hostAssignableSet.ContainsKey($locationPath)){
        Dismount-VMHostAssignableDevice -Force -LocationPath $locationPath -ErrorAction Stop
    } else {
        INFO (("Skip dismount (not host-assignable): {0}" -f $locationPath))
    }
}

function NewPlanItem([string]$title, [scriptblock]$action, [hashtable]$meta = $null) {
    if(IsNull $meta){ $meta = @{} }
    return [pscustomobject]@{ Title=$title; Action=$action; Meta=$meta }
}

function ExecutePlan($plan) {
    if(-not $plan -or $plan.Count -eq 0){
        OK "No actions required."
        return
    }

    Section "Planned actions"
    $i = 1
    foreach($p in $plan){
        Write-Host ("{0,2}. {1}" -f $i, $p.Title)
        $i++
    }

    $execPlan = New-Object System.Collections.Generic.List[object]
    foreach($p in $plan){ [void]$execPlan.Add($p) }

    if(-not $Force){
        Write-Host "Proceed with these actions?"
        Write-Host "  1. No"
        Write-Host "  2. Yes, only video graphics"
        Write-Host "  3. Yes, all NVIDIA devices"
        $ans = Read-Host "Select option (1/2/3)"

        switch($ans){
            "1" {
                WARN "User declined. No changes applied."
                return
            }
            "2" {
                $graphicsPlan = New-Object System.Collections.Generic.List[object]
                $nvidiaIncluded = 0
                $nvidiaSkipped = 0
                foreach($p in $plan){
                    $kind = $null
                    $cls = $null
                    $isGraphicsMeta = $false
                    if($p.Meta.ContainsKey('Kind')){ $kind = $p.Meta.Kind }
                    if($p.Meta.ContainsKey('DeviceClass')){ $cls = $p.Meta.DeviceClass }
                    if($p.Meta.ContainsKey('IsGraphicsFunction')){ $isGraphicsMeta = [bool]$p.Meta.IsGraphicsFunction }

                    $isGraphicsAction = $isGraphicsMeta -or ($cls -eq 'Display') -or ($p.Title -match '(?i)graphics|gpu|display|video|vga|3d')
                    if(($kind -eq 'NvidiaAssign') -and (-not $isGraphicsAction)){
                        $nvidiaSkipped++
                        WARN (("Skipping non-graphics NVIDIA action: {0}" -f $p.Title))
                        continue
                    }
                    if($kind -eq 'NvidiaAssign'){
                        $nvidiaIncluded++
                        INFO (("Including NVIDIA action: {0}" -f $p.Title))
                    }
                    [void]$graphicsPlan.Add($p)
                }
                $execPlan = $graphicsPlan
                INFO (("Graphics-only filter summary: included NVIDIA actions={0}, skipped NVIDIA actions={1}" -f $nvidiaIncluded, $nvidiaSkipped))
                INFO "Proceeding with graphics-only NVIDIA assignment actions."
            }
            "3" {
                INFO "Proceeding with all NVIDIA assignment actions."
            }
            default {
                WARN "Invalid selection. No changes applied."
                return
            }
        }
    } else {
        INFO "Force enabled: skipping confirmation."
    }

    Section "Executing plan"
    foreach($p in $execPlan){
        INFO $p.Title
        & $p.Action
        OK (("Done: {0}" -f $p.Title))
    }
}

# ---------------- MAIN ----------------
if($List){
    ShowVms
    exit 0
}

Section "Environment"
Timed "Check Hyper-V enabled" {
    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
    if($hv.State -ne 'Enabled'){ throw "Hyper-V role not enabled" }
}
OK "Hyper-V enabled"

Timed "Validate command and parameter support" {
    ValidateEnvironmentSupport
}
OK "Required command support verified"

if([string]::IsNullOrWhiteSpace($VmName)){
    WARN "No -VmName provided. Listing VMs."
    ShowVms
    exit 0
}

$vm = Timed "Lookup VM" { Get-VM -Name $VmName }
[void]$vm
OK (("VM found: {0} (State: {1})" -f $vm.Name, $vm.State))
$wasRunning = ($vm.State -ne 'Off')

# VM-attached DDA devices (fast)
Section "VM assigned DDA devices (FAST)"
$vmAssignedRaw = @(Timed "Get VM assignable devices" { GetVmAssignableDevices $VmName })
$vmAssigned = @()
$unexpectedVmAssigned = @()

foreach($item in $vmAssignedRaw){
    $hasLocationPath = (-not (IsNull $item)) -and ($item.PSObject.Properties.Match('LocationPath').Count -gt 0)
    $locationPathValue = if($hasLocationPath){ [string]$item.LocationPath } else { "" }

    if($hasLocationPath -and (-not [string]::IsNullOrWhiteSpace($locationPathValue))){
        $vmAssigned += $item
    } else {
        $unexpectedVmAssigned += $item
    }
}

if($unexpectedVmAssigned.Count -gt 0){
    WARN (("Ignored {0} unexpected object(s) from Get-VMAssignableDevice output." -f $unexpectedVmAssigned.Count))

    $idx = 0
    foreach($u in $unexpectedVmAssigned){
        $idx++
        $typeName = "(null)"
        $summary = ""

        if(-not (IsNull $u)){
            if($u.PSObject.TypeNames.Count -gt 0){
                $typeName = $u.PSObject.TypeNames[0]
            } else {
                $typeName = $u.GetType().FullName
            }

            if($u -is [System.Management.Automation.ErrorRecord]){
                $summary = $u.Exception.Message
            } elseif($u -is [string]){
                $summary = $u
            } else {
                $propPairs = @(
                    $u.PSObject.Properties |
                    ForEach-Object { "{0}={1}" -f $_.Name, $_.Value }
                )
                if($propPairs.Length -gt 0){
                    $summary = ($propPairs -join '; ')
                } else {
                    $summary = [string]$u
                }
            }
        }

        WARN (("  [{0}] Type={1}; Detail={2}" -f $idx, $typeName, $summary))
    }
}

[void]$vmAssigned

$vmTable = foreach($d in $vmAssigned){
    $instanceId = $null
    if($d.PSObject.Properties.Match('InstanceId').Count -gt 0){
        $instanceId = $d.InstanceId
    }

    [pscustomobject]@{
        LocationPath       = $d.LocationPath
        VmDeviceInstanceId = $instanceId
    }
}
if($vmTable -and $vmTable.Count -gt 0){
    $vmTable | Format-Table -AutoSize
} else {
    INFO "No DDA devices assigned to VM."
}

# Host assignable list
Section "Host assignable devices (FAST)"
$hostAssignable = Timed "Get host assignable devices" { GetHostAssignableSet }
[void]$hostAssignable
INFO (("Host assignable LocationPaths: {0}" -f $hostAssignable.Count))

# NVIDIA-only scan
Section "NVIDIA scan (VEN_10DE only)"
$nvIndex = Timed "Build NVIDIA LocationPath index" { BuildNvidiaIndex }
[void]$nvIndex

# Optional all-PnP scan
$allPnPIndex = $null
if($DeepAllPnPScan){
    Section "ALL PnP scan (optional)"
    $allPnPIndex = Timed "Build ALL PnP LocationPath index" { BuildAllPnPIndex }
} else {
    INFO "Skipping ALL PnP scan. (Use -DeepAllPnPScan if you need non-NVIDIA presence confirmation.)"
}
[void]$allPnPIndex

# Analyze attachments
Section "Attached device availability (analysis)"
$orphans = New-Object System.Collections.Generic.List[object]

$analysis = foreach($dev in $vmAssigned){
    $lp = $dev.LocationPath
    $hostOk = $false
    $nvidiaSeen = $false
    $allSeen = $false
    $nClass = $null
    $nName  = $null
    $root   = $null

    if($lp){
        $hostOk = $hostAssignable.ContainsKey($lp)

        if($nvIndex.LocMap.ContainsKey($lp)){
            $nvidiaSeen = $true
            $meta = $nvIndex.LocMap[$lp]
            $nClass = $meta.Class
            $nName  = $meta.Name
            $root   = $meta.Root
        }

        if($DeepAllPnPScan -and (-not (IsNull $allPnPIndex))){
            $allSeen = $allPnPIndex.ContainsKey($lp)
        }
    }

    $orphan = $false
    $note = ""

    if($DeepAllPnPScan){
        $orphan = (-not $hostOk) -and (-not $allSeen)
        $note = if($orphan){ "Missing from host+PnP" } else { "" }
    } else {
        if($nvidiaSeen){
            $orphan = $false
            $note = if(-not $hostOk){ "NVIDIA seen but not host-assignable (may be dismounted/assigned)" } else { "" }
        } else {
            $orphan = (-not $hostOk)
            $note = if($orphan){ "Not host-assignable (non-NVIDIA presence not checked)" } else { "" }
        }
    }

    if($orphan){ [void]$orphans.Add($dev) }

    [pscustomobject]@{
        LocationPath   = $lp
        HostAssignable = $hostOk
        NvidiaPnPSeen  = $nvidiaSeen
        NvidiaClass    = $nClass
        NvidiaName     = $nName
        RootGroup      = $root
        Orphan         = $orphan
        Note           = $note
    }
}

if($analysis){
    # FIXED: correct Sort-Object syntax (no "-Descending," bug)
    $analysis |
      Sort-Object @{Expression='Orphan';Descending=$true}, @{Expression='HostAssignable';Descending=$false} |
      Format-Table -AutoSize
}

if($orphans.Count -gt 0){
    WARN (("Potential orphan/stale attachments detected: {0}" -f $orphans.Count))
    WARN "These are common causes of VM start failure: 'Virtual PCI Express Port ... Element not found'."
}

# Select NVIDIA root group
Section "Auto-select NVIDIA group for assignment"
$targetRoot = $null
foreach($row in $analysis){
    if($row.NvidiaPnPSeen -and $row.RootGroup){
        $targetRoot = $row.RootGroup
        break
    }
}
if(-not $targetRoot){
    $targetRoot = ($nvIndex.RootMap.Keys | Sort-Object | Select-Object -First 1)
}

$targetGroup = @()
if($targetRoot -and $nvIndex.RootMap.ContainsKey($targetRoot)){
    $candidateGroup = $nvIndex.RootMap[$targetRoot]
    foreach($lp in $candidateGroup){
        $alreadyAssigned = ($vmAssigned | Where-Object { $_.LocationPath -eq $lp } | Measure-Object).Count -gt 0
        $currentlyHostAssignable = $hostAssignable.ContainsKey($lp)

        if($alreadyAssigned -or $currentlyHostAssignable){
            $targetGroup += $lp
        } else {
            WARN (("Skipping NVIDIA LocationPath not currently host-assignable/assigned: {0}" -f $lp))
        }
    }

    OK (("Selected NVIDIA root group: {0}" -f $targetRoot))
    INFO (("Group function count (assignable candidates): {0}" -f $targetGroup.Count))
    foreach($lp in $targetGroup){ INFO (("  - {0}" -f $lp)) }
} else {
    WARN "No NVIDIA group could be selected (no NVIDIA LocationPaths indexed)."
}

# FIX plan
if($Fix){
    Section "Fix planning"
    $plan = New-Object System.Collections.Generic.List[object]
    $lowMmioBytes = ConvertToMmioBytes $LowMMIO 'LowMMIO'
    $highMmioBytes = ConvertToMmioBytes $HighMMIO 'HighMMIO'

    if($wasRunning){
        [void]$plan.Add((NewPlanItem ("Stop VM '{0}' (VM was running)" -f $VmName) {
            Stop-VM -Name $VmName -Force -ErrorAction Stop
        }))
    }

    # DDA-friendly settings (your defaults) [1](https://microsofteur-my.sharepoint.com/personal/iregev_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/assign_gpu_to_vm.txt)
    [void]$plan.Add((NewPlanItem "Set VM AutomaticStopAction=TurnOff" {
        Set-VM -Name $VmName -AutomaticStopAction TurnOff -ErrorAction Stop
    }))

    [void]$plan.Add((NewPlanItem "Enable GuestControlledCacheTypes (Write-Combining)" {
        Set-VM -Name $VmName -GuestControlledCacheTypes $true -ErrorAction Stop
    }))

    [void]$plan.Add((NewPlanItem ("Set MMIO Low={0} High={1}" -f $LowMMIO, $HighMMIO) {
        Set-VM -LowMemoryMappedIoSpace $lowMmioBytes -VMName $VmName -ErrorAction Stop
        Set-VM -HighMemoryMappedIoSpace $highMmioBytes -VMName $VmName -ErrorAction Stop
    }))

    if(-not $SkipCheckpointDisable){
        [void]$plan.Add((NewPlanItem "Disable checkpoints (recommended for DDA)" {
            Set-VM -Name $VmName -CheckpointType Disabled -ErrorAction Stop
            Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false -ErrorAction Stop
        }))
    } else {
        WARN "Skipping checkpoint disable due to -SkipCheckpointDisable."
    }

    if($RemoveOrphaned -and $orphans.Count -gt 0){
        foreach($o in $orphans){
            $lp = $o.LocationPath
            [void]$plan.Add((NewPlanItem ("Remove orphaned DDA device from VM: {0}" -f $lp) {
                Remove-VMAssignableDevice -VMName $VmName -LocationPath $lp -ErrorAction Stop
            }))
        }
    } elseif($orphans.Count -gt 0) {
        WARN "Orphans detected. Use -RemoveOrphaned with -Fix to remove them."
    }

    # Assign NVIDIA group (disable + conditional dismount + add)
    if($targetGroup -and $targetGroup.Count -gt 0){
        foreach($lp in $targetGroup){
            $already = ($vmAssigned | Where-Object { $_.LocationPath -eq $lp } | Measure-Object).Count -gt 0
            if($already){
                INFO (("Already assigned, skipping: {0}" -f $lp))
                continue
            }

            if(-not $nvIndex.LocMap.ContainsKey($lp)){
                throw ("Internal error: NVIDIA index missing LocationPath: {0}" -f $lp)
            }

            $meta = $nvIndex.LocMap[$lp]
            $iid  = $meta.InstanceId
            $cls  = $meta.Class
            $nam  = $meta.Name
            $isGraphicsFunction = ($cls -eq 'Display') -or ($nam -match '(?i)graphics|gpu|display|video|vga|3d')

            [void]$plan.Add((NewPlanItem ("Disable NVIDIA PnP device ({0}) '{1}'" -f $cls, $nam) {
                EnsureDisabled $iid
            } @{ Kind='NvidiaAssign'; DeviceClass=$cls; LocationPath=$lp; IsGraphicsFunction=$isGraphicsFunction }))

            [void]$plan.Add((NewPlanItem ("Dismount from host if mounted: {0}" -f $lp) {
                DismountIfNeeded $lp $hostAssignable
            } @{ Kind='NvidiaAssign'; DeviceClass=$cls; LocationPath=$lp; IsGraphicsFunction=$isGraphicsFunction }))

            [void]$plan.Add((NewPlanItem ("Assign to VM (Add-VMAssignableDevice): {0}" -f $lp) {
                try {
                    Add-VMAssignableDevice -VMName $VmName -LocationPath $lp -ErrorAction Stop
                } catch {
                    $msg = $_.Exception.Message
                    if($msg -match 'specified device was not found'){
                        WARN (("Skipping assignment; device not found at add time: {0}" -f $lp))
                    } else {
                        throw
                    }
                }
            } @{ Kind='NvidiaAssign'; DeviceClass=$cls; LocationPath=$lp; IsGraphicsFunction=$isGraphicsFunction }))
        }
    } else {
        WARN "No NVIDIA group selected; skipping NVIDIA assignment."
    }

    if($wasRunning){
        [void]$plan.Add((NewPlanItem ("Start VM '{0}' (VM was running before)" -f $VmName) {
            Start-VM -Name $VmName -ErrorAction Stop
        }))
    } else {
        INFO "VM was Off before run; it will remain Off."
    }

    ExecutePlan $plan
}

Section "Done"
OK "Audit complete."
if($orphans.Count -gt 0){
    WARN "Potential stale/orphan attachments present. Consider: -Fix -RemoveOrphaned"
}

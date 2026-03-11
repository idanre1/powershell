param(
    # If omitted, the script will list VMs and exit (unless -List is used).
    [string]$VmName,

    # If set, script applies recommended MMIO/caching and assignment fixes.
    [switch]$Fix,

    # Optional exact NVIDIA PnP InstanceId (use when multiple GPUs are present).
    [string]$NvidiaInstanceId,

    # Just list VMs and (if possible) their assigned DDA devices, then exit.
    [switch]$List
)

function Write-Section($t){ Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Warn($t){ Write-Host "[WARN] $t" -ForegroundColor Yellow }
function Info($t){ Write-Host "[INFO] $t" -ForegroundColor Gray }
function Good($t){ Write-Host "[ OK ] $t" -ForegroundColor Green }
function Bad($t){ Write-Host "[FAIL] $t" -ForegroundColor Red }

function Show-Vms {
    Write-Section "Available VMs"
    $vms = Get-VM | Sort-Object Name
    if(-not $vms){ Warn "No VMs found on this host."; return }
    foreach($v in $vms){
        $state = $v.State
        $dda = @()
        try { $dda = Get-VMAssignableDevice -VMName $v.Name -ErrorAction SilentlyContinue } catch { }
        if($dda -and $dda.Count -gt 0){
            $paths = ($dda | Select-Object -ExpandProperty LocationPath) -join "; "
            Write-Host ("{0,-28}  {1,-8}  DDA: {2}" -f $v.Name, $state, $paths)
        } else {
            Write-Host ("{0,-28}  {1,-8}  DDA: (none)" -f $v.Name, $state)
        }
    }
}

# If -List was passed, just show VMs and exit.
if($List){
    Show-Vms
    return
}

Write-Section "Environment"
$hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
if($hv.State -ne 'Enabled'){ Bad "Hyper-V role not enabled"; exit 1 } else { Good "Hyper-V enabled" }

# If VmName not supplied, show VMs and exit with a friendly hint.
if([string]::IsNullOrWhiteSpace($VmName)){
    Warn "No -VmName provided. Showing available VMs (use -VmName <Name> or -List)."
    Show-Vms
    return
}

# Validate VM
$vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if(-not $vm){
    Bad "VM '$VmName' not found."
    Show-Vms
    exit 1
} else {
    Good "VM found: $($vm.Name)"
}

# --- 1) Discover NVIDIA devices on host ---
Write-Section "Host NVIDIA device discovery"
$nv = Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VEN_10DE' } | Sort-Object FriendlyName

if($NvidiaInstanceId){
    $nv = $nv | Where-Object { $_.InstanceId -eq $NvidiaInstanceId }
}

if(-not $nv){
    Bad "No NVIDIA (VEN_10DE) devices detected on host. Is the GPU physically present?"
    exit 1
}

$nv | ForEach-Object {
    $id = $_.InstanceId
    $name = $_.FriendlyName
    $state = $_.Status
    $loc = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_LocationPaths' -ErrorAction SilentlyContinue).Data
    $pdo = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_PDOName' -ErrorAction SilentlyContinue).Data

    Info "Device: $name"
    Info "  InstanceId: $id"
    Info "  Status: $state"
    if($loc){ Info "  LocationPath(s):"; $loc | ForEach-Object { Info "    $_" } } else { Warn "  No LocationPath found" }
    if($pdo){ Info "  PDO: $pdo" }

    # For DDA, device should be disabled on host
    if($_.Status -like '*Disabled*' -or $_.Problem -eq 22){
        Good "  Device is disabled on host (required for DDA)"
    } else {
        Warn "  Device appears ENABLED on host. For DDA it must be disabled."
        if($Fix){
            Info "  Disabling device on host via Disable-PnpDevice..."
            try{
                Disable-PnpDevice -InstanceId $id -Confirm:$false -ErrorAction Stop
                Good "  Disabled."
            } catch {
                Bad "  Failed to disable device: $($_.Exception.Message)"
            }
        }
    }

    $_ | Add-Member -NotePropertyName LocationPaths -NotePropertyValue $loc -Force
}

# Select primary GPU with a LocationPath
$gpu = $nv | Where-Object { $_.LocationPaths -and $_.LocationPaths.Count -gt 0 } | Select-Object -First 1
if(-not $gpu){
    Bad "No NVIDIA device with a valid LocationPath; cannot proceed."
    exit 1
}
$gpuLoc = $gpu.LocationPaths[0]
Info "Primary GPU LocationPath: $gpuLoc"

# --- 2) VM DDA assignment status ---
Write-Section "VM DDA assignment status"
$vmAssigned = $false
$assigned = $null
try{
    $assigned = Get-VMAssignableDevice -VMName $VmName -ErrorAction SilentlyContinue
} catch { }

if($assigned){
    $assigned | ForEach-Object {
        Info "Assigned device: $($_.LocationPath) [$($_.InstanceId)]"
    }
    if($assigned.LocationPath -contains $gpuLoc){
        $vmAssigned = $true
        Good "Target GPU is already assigned to VM"
    } else {
        Warn "Target GPU not in VM's current assignments."
    }
} else {
    Warn "VM has no assignable devices attached."
}

# --- 3) VM MMIO & cache settings ---
Write-Section "VM MMIO window and caching"
$vmcfg = Get-VM -Name $VmName
$low  = $vmcfg.LowMemoryMappedIoSpace
$high = $vmcfg.HighMemoryMappedIoSpace
$gcc  = $vmcfg.GuestControlledCacheTypes
$iomm = $vmcfg.IOMMUEnabled

Info "LowMemoryMappedIoSpace : $low"
Info "HighMemoryMappedIoSpace: $high"
Info "GuestControlledCacheTypes: $gcc"
Info "IOMMUEnabled: $iomm"

$recLow  = 536870912     # 512MB
$recHigh = 34359738368   # 32GB

$needFix = $false
if($low -lt $recLow){ Warn "Low MMIO too small (<512MB)" ; $needFix = $true }
if($high -lt $recHigh){ Warn "High MMIO too small (<32GB)" ; $needFix = $true }
if(-not $gcc){ Warn "GuestControlledCacheTypes is OFF" ; $needFix = $true }
if(-not $iomm){ Warn "IOMMUEnabled is OFF (usually should be ON)" ; $needFix = $true }

if($Fix){
    if($needFix){
        if($vm.State -ne 'Off'){
            Warn "VM must be Off to change MMIO/cache settings. Stopping VM..."
            Stop-VM -Name $VmName -Force
        }
        try{
            Set-VM -Name $VmName -LowMemoryMappedIoSpace $recLow -HighMemoryMappedIoSpace $recHigh -GuestControlledCacheTypes $true -ErrorAction Stop
            Set-VM -Name $VmName -IOMMUEnabled $true -ErrorAction SilentlyContinue | Out-Null
            Good "Applied recommended MMIO/caching settings."
        } catch {
            Bad "Failed to set MMIO/cache settings: $($_.Exception.Message)"
        }
    } else {
        Good "MMIO and caching already suitable."
    }
}

# --- 4) Assignment repair (optional) ---
Write-Section "Assignment verification/repair"
if(-not $vmAssigned -and $Fix){
    if($vm.State -ne 'Off'){
        Warn "VM must be Off for (un)assignment. Stopping VM..."
        Stop-VM -Name $VmName -Force
    }
    try{
        Disable-PnpDevice -InstanceId $gpu.InstanceId -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Add-VMAssignableDevice -VMName $VmName -LocationPath $gpuLoc -ErrorAction Stop
        Good "GPU assigned to VM."
        $vmAssigned = $true
    } catch {
        Bad "Failed to assign GPU: $($_.Exception.Message)"
        Warn "If the device is in use by the host display driver, log off any local sessions or move display to iGPU/another GPU."
    }
}

# --- 5) Host assignable inventory ---
Write-Section "Host assignable devices inventory"
try{
    $hostDevs = Get-VMHostAssignableDevice -ErrorAction Stop
    if($hostDevs){
        $hostDevs | ForEach-Object { Info ("Host assignable: " + $_.LocationPath) }
        if($hostDevs.LocationPath -contains $gpuLoc){
            Good "GPU appears as host-assignable"
        } else {
            Warn "GPU not listed as host-assignable (might still be OK if already assigned)"
        }
    } else {
        Warn "No host-assignable devices reported."
    }
} catch {
    Warn "Get-VMHostAssignableDevice not available on this SKU or OS."
}

# --- 6) Event log hints ---
Write-Section "Event log hints (Hyper-V / Kernel-PnP)"
$events = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName=@('Microsoft-Windows-Hyper-V-Worker','Microsoft-Windows-Hyper-V-VmSwitch','Kernel-PnP','VMSP') } -MaxEvents 200 |
          Where-Object { $_.Message -match $VmName -or $_.Message -match 'Assignable' -or $_.Message -match 'Passthrough' }

if($events){
    $events | Select-Object TimeCreated, Id, ProviderName, Message | Sort-Object TimeCreated | Select-Object -Last 15 |
        ForEach-Object { $_ | Format-List *; "`n" }
} else {
    Info "No recent relevant events."
}

# --- 7) Final summary ---
Write-Section "Summary"
if($vmAssigned){ Good "GPU is assigned to VM." } else { Warn "GPU is NOT assigned to VM." }
if($Fix -and (Get-VM -Name $VmName).State -eq 'Off'){ 
    Info "Starting VM..."
    try { Start-VM -Name $VmName; Good "VM started." } catch { Warn "Could not start VM automatically: $($_.Exception.Message)" }
}

Info "Tip: run with -List to see all VMs and their DDA devices."

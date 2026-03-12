#Configure the VM for a Discrete Device Assignment
$vm = Read-Host -Prompt 'Input the VM name'

#Set automatic stop action to TurnOff
Set-VM -Name $vm -AutomaticStopAction TurnOff
#Enable Write-Combining on the CPU
Set-VM -GuestControlledCacheTypes $true -VMName $vm
#Configure 32 bit MMIO space
Set-VM -LowMemoryMappedIoSpace 3Gb -VMName $vm
#Configure Greater than 32 bit MMIO space
Set-VM -HighMemoryMappedIoSpace 33280Mb -VMName $vm

#Find the Location Path and disable the Device
#Enumerate all PNP Devices on the system
$pnpdevs = Get-PnpDevice -presentOnly
#Select only those devices that are Display devices manufactured by NVIDIA
$gpudevs = $pnpdevs |where-object {$_.Class -like "Display" -and $_.Manufacturer -like "NVIDIA"}
#Select the location path of the first device that's available to be dismounted by the host.
$locationPath = ($gpudevs | Get-PnpDeviceProperty DEVPKEY_Device_LocationPaths).data[0]
echo "Location path: $locationPath"

#Disable the PNP Device
# legacy only video device: Disable-PnpDevice  -InstanceId $gpudevs[0].InstanceId
# new with AI
#On Server 2019, Hyper‑V hides endpoint devices until:
#
#the device is explicitly disabled in PnP
#then Hyper‑V re‑enumerates assignable devices
#
#This differs from newer Windows versions.
echo "Disabling PNP device $gpudevs"
# Disable ALL NVIDIA GPU-related PCI devices
Get-PnpDevice |
  Where-Object {
    $_.InstanceId -match 'VEN_10DE' -or
    $_.InstanceId -match '^HDAUDIO\\FUNC_01'
  } |
  Disable-PnpDevice -Confirm:$false
pause

#Dismount the Device from the Host
echo "Dismount the Device from the Host"
Dismount-VMHostAssignableDevice -force -LocationPath $locationPath
pause

#Assign the device to the guest VM.
echo "Assign the device to the guest VM."
Add-VMAssignableDevice -LocationPath $locationPath -VMName $vm

#Configure the VM for a Discrete Device Assignment
$vm = Read-Host -Prompt 'Input the VM name'

#Find the Location Path and disable the Device
#Enumerate all PNP Devices on the system
$pnpdevs = Get-PnpDevice
#Select only those devices that are Display devices manufactured by NVIDIA
$gpudevs = $pnpdevs |where-object {$_.Class -like "Display" -and $_.Manufacturer -like "NVIDIA"}
#Select the location path of the first device that's available to be dismounted by the host.
$locationPath = ($gpudevs | Get-PnpDeviceProperty DEVPKEY_Device_LocationPaths).data[0]
echo "Location path: $locationPath"
echo "PNP device $gpudevs"

#Remove the device to the guest VM.
Remove-VMAssignableDevice -LocationPath $locationPath -VMName $vm

#Mount the Device from the Host
Mount-VMHostAssignableDevice -LocationPath $locationPath

#Enable the PNP Device
Enable-PnpDevice  -InstanceId $gpudevs[0].InstanceId


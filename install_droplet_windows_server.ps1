$Vm = Read-Host -Prompt 'Input the VM name'

#==============================================================
# Creates a rule to open an incomming port in the firewall.
#==============================================================
echo "Adding ssh firewall rule"

#$numberAsString = read-host "type an port number"
#$mynumber = [int]$numberAsString


$port1 = New-Object -ComObject HNetCfg.FWOpenPort

$port1.Port = 22

$port1.Name = 'SSH Port' # name of Port

$port1.Enabled = $true

$fwMgr = New-Object -ComObject HNetCfg.FwMgr

$profiledomain=$fwMgr.LocalPolicy.GetProfileByType(0)

$profiledomain.GloballyOpenPorts.Add($port1)

#==============================================================
# Creates a rule to open an incomming port in the firewall.
#==============================================================
#device-manager->goto display driver location path: copy the PCIE details:
# dont forget to disable the device
$PciePath = "PCIROOT(64)#PCI(0000)#PCI(0000)"

Set-VM -Name $Vm -AutomaticStopAction TurnOff
Set-VM -VMName $Vm -GuestControlledCacheTypes $true
Set-VM -VMName $Vm -LowMemoryMappedIoSpace 128Mb
Set-VM -VMName $Vm -HighMemoryMappedIoSpace 18000Mb

Dismount-VMHostAssignableDevice -force -LocationPath "PCIROOT(64)#PCI(0000)#PCI(0000)"
Add-VMAssignableDevice -VMName $Vm -LocationPath "PCIROOT(64)#PCI(0000)#PCI(0000)"

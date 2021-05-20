# make joint link for onedrive sync
$target = "QoS"
$src = "c:\git\qos"

mklink /j "%UserProfile%\OneDrive\$target" $src


# appbundle
$app=args[0]

# signtool location
New-Item -Path Alias:signtool -Value C:\"Program Files (x86)"\"Windows Kits"\10\bin\10.0.22621.0\x64\signtool.exe

# sign
signtool sign /fd /a SHA256 $app
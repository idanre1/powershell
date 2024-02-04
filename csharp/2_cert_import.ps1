# !!! Dont forget to import certificate to the user store !!!

# appbundle
$app=$args[0]

# signtool location
New-Item -Path Alias:signtool -Value C:\"Program Files (x86)"\"Windows Kits"\10\bin\10.0.22621.0\x64\signtool.exe

# sign
signtool sign /fd SHA256 /a /f test_cert_${user}.pfx $app
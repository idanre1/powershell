# new certificate
New-SelfSignedCertificate -Type Custom -Subject "CN=iregev" -KeyUsage DigitalSignature -FriendlyName "AppTestForDebug" -CertStoreLocation "Cert:\CurrentUser\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

# make sure its there
Set-Location Cert:\CurrentUser\My
Get-ChildItem | Format-Table Subject, FriendlyName, Thumbprint
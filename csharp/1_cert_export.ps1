# Certificate Thumbprint
$cert_thumb=$args[0]
# username
$user=$args[1]

Export-PfxCertificate -cert Cert:\CurrentUser\My\$cert_thumb -FilePath test_cert_${user}.pfx -ProtectTo $user
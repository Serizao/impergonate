package adcs


import(
b64 "encoding/base64"
)


func InfFile(caConfig string) string {
return `
		$domain=New-Object -TypeName System.DirectoryServices.DirectoryEntry
		$domainDN=$domain.distinguishedName
		$objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList ('LDAP://'+$domainDN)
		$objSearcher.Filter = '(&(objectClass=user)(samAccountName='+([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name.Split('\')[1]+'))'
		$userDn =  $objSearcher.FindAll().Path.Replace('LDAP://','')
		$CertName = $userDn
		$CRTPath = 'c:\windows\temp\'+$CertName+'_.crt'
		$CSRPath = 'c:\windows\temp\'+$CertName+'_.csr'
		$INFPath = 'c:\windows\temp\'+$CertName+'_.inf'
		$Signature = '$Windows NT$' 
		$INF ='
		[Version]
		Signature = \"[[signature]]\"

		[NewRequest] 
		Subject = \"[[user_dn]]\" 
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
		$INF | out-file -filepath $INFPath -force
		certreq -new $INFPath $CSRPath
		certreq -submit -attrib "CertificateTemplate:User" -config `+caConfig+` $CSRPath $CRTPath
		rm $INFPath
		rm $CSRPath
	`
}

func FinalCommand(cmd string)string{
	b64cmd:=b64.URLEncoding.EncodeToString([]byte(cmd))
	return "powershell -c iex ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('"+b64cmd+"')))"
}




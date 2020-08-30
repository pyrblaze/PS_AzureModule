<#
.SYNOPSIS
    Connects to Azure Key Vault entries for Certificate and Secret Download
.DESCRIPTION
    Utilizes Login-AzureRmAccount (AzureRM) to connect to the Azure Key Vault entries for downloading certificate pfx file, copying separate vault for Secret entry
	Imports certificate into non-Admin keyvault.
.NOTES
	Created by Jonathan Underwood
.EXAMPLE
    Get-AzureKeyVaultCertificatePassword -AzureKeyVaultName "TestKV" -AzureKeyVaultSecretName "TestKVSecret" -CertificateName "MyCert"
#>
function Get-AzureKeyVaultCertificatePassword{
	param(
		[String] $AzureKeyVaultName,
		[String] $AzureKeyVaultSecretName,
		[String] $CertificateName
	)

	if((Get-Module AzureRM) -eq $null){
		Install-Module AzureRM -Scope CurrentUser -Verbose		
	}

	Write-Verbose "Attempting to connect to Azure."
	$UserAuthentication = Login-AzureRmAccount -ErrorAction Stop -Verbose
	
	$pfxPath = [Environment]::CurrentDirectory + "\$CertificateName.pfx"


	$kvSecret = Get-AzureKeyVaultSecret -VaultName $AzureKeyVaultName -Name $CertificateName -ErrorAction Stop -Verbose
	$password = (Get-AzureKeyVaultSecret -VaultName $AzureKeyVaultName -Name $AzureKeyVaultSecretName -Verbose).SecretValue
	$securePassword = ConvertTo-SecureString $password -AsPlainText -Force 
	$kvSecretBytes = [System.Convert]::FromBase64String($kvSecret.SecretValueText)
	Remove-Variable "kvSecret"

	$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
	$certCollection.Import($kvSecretBytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
	$protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password)
	Remove-Variable "password"
	[System.IO.File]::WriteAllBytes($pfxPath, $protectedCertificateBytes)
	
	Write-Verbose "Setting Cert manager location: CurrentUser\My"
	Set-Location Cert:\CurrentUser\My

	Write-Verbose "Installing Certificate into My Cert store."
	Import-PfxCertificate -FilePath $pfxPath -Password $securePassword		
}
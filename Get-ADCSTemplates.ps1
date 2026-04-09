#
# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================
#
# COMMENT: Collect all important certificate template
#          parameters into a grid view or csv to
#          start analysis, comparing, etc
#
#
# USAGE:
#	.\Get-ADCSTemplates.ps1 [-ReportToGrid $true (default)] [-Export2Csv $false (Default)] [-ExportFileName]
#
# requires AD Powershell module and read access to ADCS AD objects
#
#
#
# version 1.1 / 05.04.2026
# version 1.2 / 09.04.2026
#  - fixed readability in csv/excel and gridview
#  - fixed permission bug
#  - re-ordered table columns
# 
#



param(
    [Parameter(Mandatory=$false)]
    [Bool]$ReportToGrid = $true,

    [Parameter(Mandatory=$false)]
    [bool]$Export2Csv = $false,

    [Parameter(Mandatory=$false)]
    [string]$ExportFileName = ""
)



function Get-PKITemplatePermission {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$TemplateName
	)
	
    $htSecView = @{}
	$oTemplate = Get-ADObject -Filter 'Name -eq $TemplateName' -SearchBase $CATemplateOU
    $ACL = (Get-Acl "ad:$oTemplate").Access
	ForEach ($ACE in $ACL) {
<#
		$htSecView[$ACE.IdentityReference] = New-Object 'psobject' -Property @{
			#'TemplateName'		 = $oTemplate.Name
			'IdentityReference'	 = $ACE.IdentityReference
			'FullControll'	     = "false"
			'Read'			     = "false"
			'Write'			     = "false"
			'AutoEnrollment'	 = "false"
			'Enroll'			 = "false"
		}
#>
		[string]$key = $ACE.IdentityReference.Value
        if (!($htSecView.ContainsKey($key))) {
            $htSecView[$key] = @()
        }

		if ($ACE.AccessControlType -eq 'Allow') {
			if ($ACE.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
				$htSecView[$key] += ("FullControll")
#				$htSecView[$ACE.IdentityReference].FullControll = "true"
			}
			if ($ACE.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericRead)) {
				$htSecView[$key] += ("Read")
#				$htSecView[$ACE.IdentityReference].Read = "true"
			}
			if ($ACE.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)) {
				$htSecView[$key] += ("Write")
#				$htSecView[$ACE.IdentityReference].Write = "true"
			}
			if ($ACE.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) {
				If ($_.ObjectType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2') {
    				$htSecView[$key] += ("AutoEnrollment")
#					$htSecView[$ACE.IdentityReference].AutoEnrollment = "true"
				}
				If ($ACE.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') {
    				$htSecView[$key] += ("Enroll")
#					$htSecView[$ACE.IdentityReference].Enroll = "true"
				}
			}
		} else {
			if ($ACE.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) {
				If ($_.ObjectType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2') {
    				$htSecView[$key] += ("Deny-AutoEnroll")
#					$htSecView[$ACE.IdentityReference].AutoEnrollment = "denied"
				}
				If ($ACE.ObjectType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') {
    				$htSecView[$key] += ("Deny-Enroll")
#					$htSecView[$ACE.IdentityReference].Enroll = "denied"
				}
			}
        }
	}
    $b = ($htSecView.GetEnumerator()| % { "$($_.Name)=$($_.Value)" })|Out-String
    return $b
#	$htSecView.Values | Select-Object 'TemplateName', 'IdentityReference', 'FullControll', 'Read', 'Write', 'Enroll', 'AutoEnrollment'
}

#being lazy, so stolen from:
#https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
function Convert-pKIPeriod ([Byte[]]$ByteArray) {
    [array]::Reverse($ByteArray)
    $LittleEndianByte = -join ($ByteArray | %{"{0:x2}" -f $_})
    $Value = [Convert]::ToInt64($LittleEndianByte,16) * -.0000001
    if (!($Value % 31536000) -and ($Value / 31536000) -ge 1) {[string]($Value / 31536000) + " years"}
    elseif (!($Value % 2592000) -and ($Value / 2592000) -ge 1) {[string]($Value / 2592000) + " months"}
    elseif (!($Value % 604800) -and ($Value / 604800) -ge 1) {[string]($Value / 604800) + " weeks"}
    elseif (!($Value % 86400) -and ($Value / 86400) -ge 1) {[string]($Value / 86400) + " days"}
    elseif (!($Value % 3600) -and ($Value / 3600) -ge 1) {[string]($Value / 3600) + " hours"}
    else {"0 hours"}
}


function Convert-Oid2Text
{
    param (
        [Parameter(Mandatory = $true)]
        [String]$OIDString
    )
    [string]$result = (New-Object Security.Cryptography.Oid($OIDString)).FriendlyName
    Return $result
}


#region common variable block
$DateStr = (Get-Date).ToString("yyyyMMddHHmm")
$domainDNS = (Get-ADDomain).DNSRoot
$domainDN = (Get-ADDomain).DistinguishedName
[string]$CATemplateOU = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($domainDN)"
[string]$EnrollmentOU = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$($domainDN)"
$BaseDirectory = "$(If($PSISE){split-path $psise.CurrentFile.FullPath}else{Split-Path $MyInvocation.MyCommand.Definition -Parent})"

if ($Export2Csv -and [String]::IsNullOrEmpty($ExportFileName)) {
    $ExportFileName = "$($BaseDirectory)\ADCS-TemplateList-$($DateStr).csv"
}
#endregion

Write-Host
Write-Host "Running with following Parameters:" -ForegroundColor Yellow
Write-Host "Report to Grid: " -NoNewline; Write-Host ($(if($ReportToGrid){"true"}else{"false"})) -ForegroundColor Yellow
Write-Host "Export to CSV : " -NoNewline; Write-Host ($(if($Export2Csv){"true"}else{"false"})) -ForegroundColor Yellow
if ($Export2Csv) {
    Write-Host " "
    Write-Host "Export filename: "  -NoNewline; Write-Host "$($ExportFileName)" -ForegroundColor Yellow
}
Write-Host " "


#region enumaerate flags

[flags()] Enum GenFlags
{
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
    CT_FLAG_ADD_EMAIL = 0x2
    CT_FLAG_ADD_OBJ_GUID = 0x4
    CT_FLAG_PUBLISH_TO_DS = 0x8
    CT_FLAG_EXPORTABLE_KEY = 0x10
    CT_FLAG_AUTO_ENROLLMENT = 0x20
    CT_FLAG_MACHINE_TYPE = 0x40
    CT_FLAG_IS_CA = 0x80
    CT_FLAG_ADD_DIRECTORY_PATH = 0x100
    CT_FLAG_ADD_TEMPLATE_NAME = 0x200
    CT_FLAG_ADD_SUBJECT_DIRECTORY_PATH = 0x400
    CT_FLAG_IS_CROSS_CA = 0x800
    CT_FLAG_DONOTPERSISTINDB = 0x1000
    CT_FLAG_IS_DEFAULT = 0x10000
    CT_FLAG_IS_MODIFIED = 0x20000
    CT_FLAG_IS_DELETED = 0x40000
    CT_FLAG_POLICY_MISMATCH = 0x80000
}

[flags()] Enum EnrolFlags
{
    CT_FLAG_NO_FLAG = 0x0
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x1
    CT_FLAG_PEND_ALL_REQUESTS = 0x2
    CT_FLAG_PUBLISH_TO_KRA_CONTAINER = 0x4
    CT_FLAG_PUBLISH_TO_DS = 0x8
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x10
    CT_FLAG_AUTO_ENROLLMENT = 0x20
    CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x40
    CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80
    CT_FLAG_USER_INTERACTION_REQUIRED = 0x100
    CT_FLAG_ADD_TEMPLATE_NAME = 0x200 
    CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x400
    CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF = 0x800
    CT_FLAG_ADD_OCSP_NOCHECK = 0x1000
    CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x2000
    CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS = 0x4000
    CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x8000
    CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x10000
    CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST = 0x20000
    CT_FLAG_SKIP_AUTO_RENEWAL = 0x40000
}

[flags()] Enum PrivKeyFlags
{
    CTPRIVATEKEY_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x1
    CTPRIVATEKEY_FLAG_EXPORTABLE_KEY = 0x10
    CTPRIVATEKEY_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x20
    CTPRIVATEKEY_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x40
    CTPRIVATEKEY_FLAG_REQUIRE_SAME_KEY_RENEWAL = 0x80
    CTPRIVATEKEY_FLAG_USE_LEGACY_PROVIDER = 0x100
    CTPRIVATEKEY_FLAG_EK_TRUST_ON_USE = 0x200
    CTPRIVATEKEY_FLAG_EK_VALIDATE_CERT = 0x400
    CTPRIVATEKEY_FLAG_EK_VALIDATE_KEY = 0x800
    CTPRIVATEKEY_FLAG_ATTEST_NONE = 0x0
    CTPRIVATEKEY_FLAG_ATTEST_PREFERRED = 0x1000
    CTPRIVATEKEY_FLAG_ATTEST_REQUIRED = 0x2000
    CTPRIVATEKEY_FLAG_ATTEST_WITHOUT_POLICY = 0x4000
    #TEMPLATE_SERVER_VER_NONE_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x0
    TEMPLATE_SERVER_VER_2003_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x10000
    TEMPLATE_SERVER_VER_2008_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x20000
    TEMPLATE_SERVER_VER_2008R2_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x30000
    TEMPLATE_SERVER_VER_WIN8_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x40000
    TEMPLATE_SERVER_VER_WINBLUE_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x50000
    TEMPLATE_SERVER_VER_THRESHOLD_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x60000
    V7_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x70000
    V8_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x80000
    V9_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0x90000
    V10_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0xa0000
    V11_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0xb0000
    V12_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0xc0000
    V13_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0xd0000
    V14_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0xe0000
    V15_CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT = 0xf0000
    CTPRIVATEKEY_FLAG_HELLO_KSP_KEY = 0x100000
    CTPRIVATEKEY_FLAG_HELLO_LOGON_KEY = 0x200000
    #TEMPLATE_CLIENT_VER_NONE_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x0
    TEMPLATE_CLIENT_VER_XP_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x1000000
    TEMPLATE_CLIENT_VER_VISTA_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x2000000
    TEMPLATE_CLIENT_VER_WIN7_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x3000000
    TEMPLATE_CLIENT_VER_WIN8_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x4000000
    TEMPLATE_CLIENT_VER_WINBLUE_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x5000000
    TEMPLATE_CLIENT_VER_THRESHOLD_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x6000000
    V7_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x7000000
    V8_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x8000000
    V9_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0x9000000
    V10_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0xa000000
    V11_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0xb000000
    V12_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0xc000000
    V13_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0xd000000
    V14_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0xe000000
    V15_CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT = 0xf000000
}

[flags()] Enum NameFlags
{
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
    CT_FLAG_ADD_EMAIL = 0x2
    CT_FLAG_ADD_OBJ_GUID = 0x4
    CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x8
    CT_FLAG_ADD_DIRECTORY_PATH = 0x100
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x10000
    CT_FLAG_VALUE_NOT_DEFINED = 0x20000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x400000
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x800000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x1000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x2000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x4000000
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x8000000
    CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000
    CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
}

[flags()] Enum KeyUsage
{
    decipherOnly = 0x0
    encipherOnly = 0x1	
    cRLSign = 0x2
    keyCertSign = 0x4	
    keyAgreement = 0x8	
    dataEncipherment = 0x10	
    keyEncipherment = 0x20	
    nonRepudiation= 0x40	
    digitalSignature = 0x80	
}

#endregion

#region get CA/template into hastable
Write-Host "  reading CA assigned ADCS templates from AD ..." -ForegroundColor Yellow

$CaTmplMap = @{}
$ActiveCAs = Get-ADObject -SearchBase ($EnrollmentOU) -Filter "objectclass -eq 'pKIEnrollmentService'"` -Properties certificateTemplates ,cn
Foreach ($CA in $ActiveCAs) {
    foreach ($tmpl in $CA.certificateTemplates) {
        if ($CaTmplMap[$tmpl]) {
            $CaTmplMap[$tmpl] += $CA.cn
        } else {
            $CaTmplMap[$tmpl] = $CA.cn
        }
    }
}

Write-Host "--> done! " -ForegroundColor Green

#endregion

#region read all template objects from AD
Write-Host "  collecting all ADCS templates from AD ..." -ForegroundColor Yellow

$aTmpls = Get-ADObject -Filter "objectclass -eq 'pKICertificateTemplate'" -Properties * -SearchBase $CATemplateOU |
    select 'Name', 
        'AssignedCA',
        'Created', 
        'Modified', 
        'flags',
        'flags-Enc',
        'msPKI-Cert-Template-OID', 
        'msPKI-Certificate-Application-Policy', 
        'str-Certificate-Application-Policy', 
        'msPKI-Certificate-Name-Flag', 
        'Name-Flag-Enc', 
        'msPKI-Enrollment-Flag', 
        'Enroll-Flag-Enc', 
        'msPKI-Minimal-Key-Size', 
        'msPKI-Private-Key-Flag', 
        'Priv-Key-Flag-Enc', 
        'msPKI-RA-Signature', 
        'msPKI-Template-Minor-Revision', 
        'msPKI-Template-Schema-Version', 
        'pKICriticalExtensions', 
        'strCriticalExtensions', 
        'pKIDefaultCSPs', 
        'strDefaultCSPs', 
        'pKIDefaultKeySpec', 
        'pKIExpirationPeriod',
        'ExpirationPeriod-Enc',
        'pKIOverlapPeriod',
        'OverlapPeriod-Enc',
        'pKIExtendedKeyUsage', 
        'strExtendedKeyUsage', 
        'pKIKeyUsage', 
        'KeyUsage-Enc', 
        'Security'

Write-Host "--> done! " -ForegroundColor Green
Write-Host " "

Write-Host ("Received {0} templates" -f $aTmpls.Count) -ForegroundColor Cyan
#endregion

#region get template permissions, assigned CA and convert all values into readable strings
Write-Host "  decoding binary values into human readable format ..." -ForegroundColor Yellow

$i = 0
ForEach ($tmpl in $aTmpls) {
    Write-Host "> Processing: $($tmpl.Name)" -ForegroundColor Yellow
    $match = $CaTmplMap.Keys | % {if($_.contains($tmpl.Name)){$_}}

    if ($match) {
        $aTmpls[$i].AssignedCA = $CaTmplMap[$tmpl.Name]
    } else {
        $aTmpls[$i].AssignedCA = ""
    }
    $aTmpls[$i].'flags-Enc' = ([GenFlags] $aTmpls[$i].flags|Out-String).Replace(", ","`n")
    $aTmpls[$i].'Name-Flag-Enc' = ([NameFlags] $aTmpls[$i].'msPKI-Certificate-Name-Flag'|Out-String).Replace(", ","`n")
    $aTmpls[$i].'Enroll-Flag-Enc' = ([EnrolFlags] $aTmpls[$i].'msPKI-Enrollment-Flag'|Out-String).Replace(", ","`n")
    $aTmpls[$i].'Priv-Key-Flag-Enc' = ([PrivKeyFlags] $aTmpls[$i].'msPKI-Private-Key-Flag'|Out-String).Replace(", ","`n")
    $aTmpls[$i].'KeyUsage-Enc' = ([KeyUsage] $aTmpls[$i].'pKIKeyUsage'|Out-String).Replace(", ","`n")
    $aTmpls[$i].'ExpirationPeriod-Enc' = Convert-pKIPeriod $aTmpls[$i].'pKIExpirationPeriod'
    $aTmpls[$i].'OverlapPeriod-Enc' = Convert-pKIPeriod $aTmpls[$i].'pKIOverlapPeriod'
    $aTmpls[$i].'str-Certificate-Application-Policy' = foreach ($eku in $aTmpls[$i].'msPKI-Certificate-Application-Policy') {
        "$(Convert-Oid2Text -OIDString $($eku|out-string).Trim()) - $(($eku|out-string).Trim())"
    }
    $aTmpls[$i].'str-Certificate-Application-Policy' = ($aTmpls[$i].'str-Certificate-Application-Policy'|Out-String)

    $aTmpls[$i].'strCriticalExtensions' = foreach ($oid in $aTmpls[$i].'pKICriticalExtensions') {
        "$(Convert-Oid2Text -OIDString $($oid|out-string).Trim()) - $(($oid|out-string).Trim())"
    }
    
    $aTmpls[$i].'strCriticalExtensions' = ($aTmpls[$i].'strCriticalExtensions'|Out-String)
    $aTmpls[$i].'strDefaultCSPs' = ($aTmpls[$i].'pKIDefaultCSPs'|Out-String)
    $aTmpls[$i].'strExtendedKeyUsage' =  foreach ($eku in $aTmpls[$i].'pKIExtendedKeyUsage') {
        "$(Convert-Oid2Text -OIDString $($eku|out-string).Trim()) - $(($eku|out-string).Trim())"
    }
    $aTmpls[$i].'strExtendedKeyUsage' =  ($aTmpls[$i].'strExtendedKeyUsage'|Out-String)

	$aTmpls[$i++].Security = Get-PKITemplatePermission -Template $tmpl.Name
}
Write-Host "--> done! " -ForegroundColor Green
Write-Host " "
#endregion

#region generate output object
Write-Host "  generating output object ..." -ForegroundColor Yellow
$aExpList = $aTmpls |
        select 'Name', 
        'AssignedCA',
        'Created', 
        'Modified', 
        'str-Certificate-Application-Policy', 
        'strExtendedKeyUsage', 
        'msPKI-Minimal-Key-Size', 
        'KeyUsage-Enc', 
        'strCriticalExtensions', 
        'strDefaultCSPs', 
        'pKIDefaultKeySpec', 
        'flags-Enc',
        'Name-Flag-Enc', 
        'Enroll-Flag-Enc', 
        'Priv-Key-Flag-Enc', 
        'msPKI-RA-Signature', 
        'msPKI-Template-Minor-Revision', 
        'msPKI-Template-Schema-Version', 
        'ExpirationPeriod-Enc',
        'OverlapPeriod-Enc',
        'Security' 

Write-Host "--> done! " -ForegroundColor Green
Write-Host " "
#endregion

if ($Export2Csv) {
    Write-Host "  exporting to file: $($ExportFileName) ..." -ForegroundColor Yellow
    $aExpList | Sort-Object Name | export-csv -Path $ExportFileName -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
    Write-Host "--> done! " -ForegroundColor Green
    Write-Host " "
}
if ($ReportToGrid) {
    Write-Host "  generating gridview ..." -ForegroundColor Yellow
    $aExpList | Sort-Object Name | Out-GridView -Title 'ADCS Template Overview'
    Write-Host "--> done! " -ForegroundColor Green
    Write-Host " "
}
Write-Host "Finished script! " -ForegroundColor Green





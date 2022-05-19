#requires -RunAsAdministrator
#requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    Position=0)]
    [string]$CompanyName,

  [Parameter(ValueFromPipelineByPropertyName=$true)]
    [string]$TierOUName='Admin',

  [Parameter(ValueFromPipelineByPropertyName=$true)]
    [AllowNull()]
    [ValidateRange(1,2)]
    [int]$NoOfTiers=2,

  [switch]$SkipLAPS,

  [switch]$SkipPAW,

  [switch]$SkipTierEndpoints,

  [switch]$SkipComputerRedirect,

  [switch]$Minimal
)

$DomainDN=(Get-ADDomain).DistinguishedName
$DomainSID=(Get-ADDomain).DomainSid.Value

function Update-TsXLAPSSchema {
  #Looks for AdmPwd schema extensions. Adds them if they can't be found.
  Write-Verbose 'Looks for AdmPwd schema extensions. Adds them if they cant be found.'
  if (Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext) -SearchScope OneLevel -Filter * -Property name | Where-Object {$_.Name -like '*AdmPwd*'}) {
    return $true;
  }
  else {
    Write-Verbose 'AdmPwd LAPS schema extensions not found. Adding schema extension...'
    if (Get-ADPrincipalGroupMembership -Identity $env:username | Where-Object {$_.SID -eq "$DomainSID-518"}) {
      Try {
        Update-AdmPwdADSchema
        return $true;
      }
      Catch {
        return $false;
      }
    }
    else {
      return $false;
    }
  }
}

function Set-TSxOUPermission {
  param (
  [Parameter(Position=0,Mandatory)]
  [string]$OrganizationalUnitDN,
  [Parameter(Position=1,Mandatory)]
  [string]$GroupName,
  [Parameter(Position=2,Mandatory)]
  [ValidateSet('ComputersCreate','ComputersCreateGPLink','BitLocker','GroupsMembers','GroupsCreate','Users','UsersCreate','OUsCreate','DenyGPLink')]
  [string]$ObjectType
  )

  $NBDomainName = (Get-ADDomain).NetBIOSName
  if ($GroupName -ne 'Everyone') {
    $TargetGroup = "$NBDomainName\$GroupName"
  }
  else {
    $TargetGroup = $GroupName
  }

  Write-Verbose "Adding $ObjectType permissions to $GroupName at $OrganizationalUnitDN"
  #Computer objects only: Create, Delete, Read/write all properties, Reset password, Change password
  if ($ObjectType -eq 'ComputersCreate') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CCDC;Computer" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":LCCCDC;;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RCWD;;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;Reset Password;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;Change Password;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":WS;Validated write to service principal name;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":WS;Validated write to DNS host name;Computer" /I:S | Out-Null
  }
  #Computer objects: Create, Delete, Read/write all properties, Reset password, Change password. Read GPOptions, Read/Write GPLinks
  if ($ObjectType -eq 'ComputersCreateGPLink') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CCDC;Computer" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":LCCCDC;;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RCWD;;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;Reset Password;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;Change Password;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":WS;Validated write to service principal name;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":WS;Validated write to DNS host name;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RP;GPOptions;" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;GPLink;" /I:T | Out-Null
  }

  #Computer objects only: Read TPM Owner Info, Read BitLocker RecoveryInformation and password
  if ($ObjectType -eq 'BitLocker') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RP;msTPM-OwnerInformation;Computer" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RP;;msFVE-RecoveryInformation" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;msFVE-RecoveryPassword;msFVE-RecoveryInformation" /I:S | Out-Null
  }

  #Group objects only: Manage membership
  if ($ObjectType -eq 'GroupsMembers') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;Member;Group" /I:S | Out-Null
  }

  #Group objects only: Create, Delete, Read/write all properties.
  if ($ObjectType -eq 'GroupsCreate') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CCDC;Group" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;;Group" /I:S | Out-Null
  }

  #User objects only: Read/write all properties, Reset password
  if ($ObjectType -eq 'Users') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;;User" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;Reset Password;User" /I:S | Out-Null
  }

  #User objects only: Create, Delete, Read/write all properties, Reset password
  if ($ObjectType -eq 'UsersCreate') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CCDC;User" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;;User" /I:S | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CA;Reset Password;User" /I:S | Out-Null
  }

  #OU objects only: Create, Delete, Read/write all properties
  if ($ObjectType -eq 'OUsCreate') {
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":CCDC;Organizationalunit" /I:T | Out-Null
    dsacls.exe $OrganizationalUnitDN /G $TargetGroup":RPWP;;Organizationalunit" /I:S | Out-Null
  }

  #Deny create GPOLinks
  if ($ObjectType -eq 'DenyGPLink') {
    dsacls.exe $OrganizationalUnitDN /D $TargetGroup":WP;GPLink;" /I:P | Out-Null
  }
}

function New-TSxSubOU {
  param (
  [Parameter(Position=0,Mandatory)]
    [ValidateSet('T0','Tier0','T1','Tier1','T2','Tier2','TE','TierEndpoints')]
    [string]$Tier,
  [Parameter(Position=1,Mandatory)]
    [string]$Name,
  [Parameter(Position=2)]
    [string]$Description,
  [Parameter(Position=3)]
    [string]$CompanyName,
  [Parameter(Position=4)]
    [string]$TierOUName
  )

  if ($null -eq $TierOUName) {
    $TierOUName = 'Admin'
  }
  $DomainDN=(Get-ADDomain).DistinguishedName
  #Set parameters to be used in tiers. Tier 0 creates only OU then exits.
  if ($Tier -eq 'T0' -or $Tier -eq 'Tier0') {
    $Tier = 'Tier0'
    if ($null -like $Description) {
      $Description = "$Tier $Name"
    }
    $ou = New-TSxADOrganizationalUnit -Name "$Name" -Path "OU=Servers,OU=Tier0,OU=$TierOUName,$DomainDN" -Description "$Description" -ErrorAction Stop
    if (!$ou) {
      Write-Error "OU $Name not created in $Path"
      return $false
    }
  }
  else {
    if ($Tier -eq 'T1' -or $Tier -eq 'Tier1') {
      $Tier = 'Tier1'
      $TierServerOU = "OU=Servers,OU=$Tier,OU=$TierOUName,$DomainDN"
      $TierGroupOU = "OU=Groups,OU=$Tier,OU=$TierOUName,$DomainDN"
    }
    if ($Tier -eq 'T2' -or $Tier -eq 'Tier2') {
      $Tier = 'Tier2'
      $TierServerOU = "OU=Servers,OU=$Tier,OU=$TierOUName,$DomainDN"
      $TierGroupOU = "OU=Groups,OU=$Tier,OU=$TierOUName,$DomainDN"
    }
    if ($Tier -eq 'TE' -or $Tier -eq 'TierEndpoints') {
      $Tier = 'TierEndpoints'
      $TierServerOU = "OU=Endpoints,OU=$CompanyName,$DomainDN"
      $TierGroupOU = "OU=Groups,OU=$Tier,OU=$TierOUName,$DomainDN"
    }
    #Create OU, group and GPO. Links GPO to OU and sets LAPS read permissions to group.
    if ($null -like $Description) {
      $Description = "$Tier $Name"
    }
    $ou = New-TSxADOrganizationalUnit -Name "$Name" -Path $TierServerOU -Description "$Description"
    if (!$ou) {
      Write-Error "OU $Name not created in $TierServerOU"
      return $false
    }
    if ($Tier -eq 'TierEndpoints') {
      $group = New-TSxADGroup -Name "Domain Company Admin - $Name" -Path "$TierGroupOU" -GroupCategory Security -GroupScope Global -Description "$Description Admins"
      if (!$group) {
        Write-Error "Group $Name not created in $TierGroupOU"
        return $false
      }
      $gpo = New-TSxGPO -Name "Admin - Add $($group.Name) to Local Remote Desktop Users group"
      if (!$gpo) {
        Write-Error "GPO $Name not created"
        return $false
      }
      Write-Verbose "Created group:$($group.Name) and OU:$($gpo.Name) in $Tier"
    }
    else {
      $group = New-TSxADGroup -Name "Domain $Tier Admin - $Name" -Path "$TierGroupOU" -GroupCategory Security -GroupScope Global -Description "$Description Admins"
      if (!$group) {
        Write-Error "Group $Name not created in $TierGroupOU"
        return $false
      }
      $gpo = New-TSxGPO -Name "Admin - Add $($group.Name) to Local Admin group"
      if (!$gpo) {
        Write-Error "GPO $Name not created"
        return $false
      }
      Write-Verbose "Created group:$($group.Name) and OU:$($gpo.Name) in $Tier"
    }
    New-TSxGPLink -Id ($gpo.id).Guid -Target $ou.DistinguishedName -LinkEnabled Yes | Out-Null
    Add-ADFineGrainedPasswordPolicySubject -Identity PWDPolicy-AdminAccounts -Subjects $group.Name
    Try {
      Set-AdmPwdReadPasswordPermission -Identity $ou.DistinguishedName -AllowedPrincipals $group.Name -ErrorAction Stop | Out-Null
    }
    Catch {}
    Set-TSxOUPermission -OrganizationalUnitDN $ou.DistinguishedName -GroupName $group.Name -ObjectType ComputersCreate
    Write-Verbose "Created OU $Name and dependencies in $Tier..."
  }
}

Function New-TSxAuthenticationPolicy{
  Param(
  $Tier
  )

  #Get and try to connect to dc holding pdcemulator role
  $pdc = (Get-ADDomain).PDCEmulator
  $DomainSID=(Get-ADDomain).DomainSid.Value
  $DCDomainGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-516""").Name
  Try {
    Get-ADGroup -Identity $DCDomainGroup -Server $pdc -ErrorAction Stop | Out-Null
  }
  Catch {
    Write-Error "Can't query $pdc. Verify it responds and try again. ErrorMessage: $($_.Exception.Message)" -Verbose
    return $false
  }

  #Create the authentication policy and verify it's created successfully before continuing
  $EAP = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $adauth = Get-ADAuthenticationPolicy -Identity "1hr_$($Tier)Admin_TGT" -ErrorAction SilentlyContinue
  $ErrorActionPreference = $EAP    
  if (!$adauth) {
    Try {
      New-ADAuthenticationPolicy -Name "1hr_$($Tier)Admin_TGT" -Description "1hr_$($Tier)Admin_TGT" -UserTGTLifetimeMins 60 -Server $pdc -ErrorAction Stop
      Do {
        $authpolicy = Get-ADAuthenticationPolicy -Identity "1hr_$($Tier)Admin_TGT" -Server $pdc
        Start-Sleep -Seconds 5
      } Until ($authpolicy)
    }
    Catch {
      Write-Error "Unable to create Authentication Policy 1hr_$($Tier)Admin_TGT. ErrorMessage: $($_.Exception.Message)" -Verbose
      return $false
    }
  }
  
  #Create the authentication policy silo and verify it's created successfully before continuing
  $EAP = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $adauthsilo = Get-ADAuthenticationPolicySilo -Identity "Restricted_$($Tier)Admin_Logon" -ErrorAction SilentlyContinue
  $ErrorActionPreference = $EAP
    if (!$adauthsilo) {
    Try {
      New-ADAuthenticationPolicySilo -Name "Restricted_$($Tier)Admin_Logon" -Description "Restricted_$($Tier)Admin_Logon" -UserAuthenticationPolicy "1hr_$($Tier)Admin_TGT" -ComputerAuthenticationPolicy "1hr_$($Tier)Admin_TGT" -ServiceAuthenticationPolicy "1hr_$($Tier)Admin_TGT" -Server $pdc -ErrorAction Stop
      Do {
        $authpolicysilo = Get-ADAuthenticationPolicySilo -Identity "Restricted_$($Tier)Admin_Logon" -Server $pdc
        Start-Sleep -Seconds 5
      } Until ($authpolicysilo)
    }
    Catch {
      Write-Error "Unable to create Authentication Policy Silo Restricted_$($Tier)Admin_Logon. ErrorMessage: $($_.Exception.Message)" -Verbose
      return $false
    }
  }
  
  #Set computers users are allowed to authenticate from and enfore the policies
  Set-ADAuthenticationPolicy -Identity "1hr_$($Tier)Admin_TGT" -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == ""Restricted_$($Tier)Admin_Logon""))" -Enforce $true -UserAllowedNTLMNetworkAuthentication $true -Server $pdc -ErrorAction Stop
  Set-ADAuthenticationPolicySilo -Identity "Restricted_$($Tier)Admin_Logon" -Enforce $true -Server $pdc -ErrorAction Stop
  Write-Verbose "Created Authentication Silo for $Tier."
}

Function New-TSxADOrganizationalUnit {
  Param(
    $Name,
    $Path,
    $Description,
    [switch]$NoOut
  )

  $EAP = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $object = Get-ADOrganizationalUnit -Identity "OU=$Name,$Path"
  $ErrorActionPreference = $EAP
  if ($object) {
    if (!$NoOut) {
      return $object
    }
  }
  else {
    Try {
      New-ADOrganizationalUnit -Name "$Name" -Path $Path -Description "$Description" -ErrorAction Stop
    }
    Catch {
      Write-Error "Could not create OU $Name in $Path. Error: $($_.Exception.Message)"
      return $false
    }
    Do {
      $success = Get-ADOrganizationalUnit -Identity "OU=$Name,$Path"
      Start-Sleep -Seconds 1
    } Until ($success)
    Write-Verbose "Created OU $Name in $Path."
    if (!$NoOut) {
      return $success
    }
  }
}

Function New-TSxGPO {
  Param(
    $Name,
    [switch]$NoOut
  )

  $EAP = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $object = Get-GPO -Name "$Name"
  $ErrorActionPreference = $EAP
  if ($object) {
    if (!$NoOut) {
      return $object
    }
  }
  else {
    $ErrorActionPreference = $EAP
    Try {
      $gpo = New-GPO -Name "$Name" -ErrorAction Stop
    }
    Catch {
      Write-Error "Could not create GPO $Name. Error: $($_.Exception.Message)"
      return $false
    }
    Do {
      $success = Get-GPO -Name "$Name" -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 1
    } Until ($success)
    Write-Verbose "Created GPO $Name."
    if (!$NoOut) {
      return $gpo
    }
  }
}

Function New-TSxADGroup {
  Param(
    $Name,
    $Path,
    $GroupCategory,
    $GroupScope,
    $Description,
    [switch]$NoOut
  )
  
  $EAP = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $object = Get-ADGroup -Identity $Name
  $ErrorActionPreference = $EAP
  if ($object) {
    if (!$NoOut) {
      return $object
    }
  }
  else {
    Try {
      New-ADGroup -Name "$Name" -Path "$Path" -GroupCategory "$GroupCategory" -GroupScope "$GroupScope" -Description "$Description" -ErrorAction Stop
    }
    Catch {
      Write-Error "Could not create group $Name in $Path. Error: $($_.Exception.Message)"
      return $false
    }
    Do {
      $success = Get-ADGroup -Identity "$Name"
      Start-Sleep -Seconds 1
    } Until ($success)
    Write-Verbose "Created group $Name in $Path."
    if (!$NoOut) {
      return $success
    }
  }
}

Function New-TSxGPLink {
  Param(
    $Id,
    $Target,
    $LinkEnabled
  )

  $dc = (Get-ADDomain).PDCEmulator

  Try {
    Get-ADUser -Identity krbtgt -Server $dc
  }
  Catch {
    $dc = (Get-ADDomainController).HostName
  }

  Do {
    $success = Get-GPO -Id $Id -ErrorAction SilentlyContinue -Server $dc
    Start-Sleep -Seconds 1
  } Until ($success)
  
  Try {
    New-GPLink -Id $Id -Target "$Target" -LinkEnabled $LinkEnabled -ErrorAction Stop -Server $dc
    Write-Verbose "Created GPLink in $Target."
    return $true
  }
  Catch [System.ArgumentException] {
    Write-Warning "Link already exists in $Target!"
  }
  Catch {
    Write-Error "Could not GPOLink $Id in $Target. Error: $($_.Exception.Message)"
    return $false
  }
}

# If minimal switch set then add all skips and only 1 tier
if ($Minimal) {
  $NoOfTiers = 1
  $SkipLAPS = $true
  $SkipPAW = $true
  $SkipTierEndpoints = $true
}

# Check for LAPS extensions unless SkipLAPS set. Create if not enabled. Exit if fails.
if (!($SkipLAPS)) {
  if ((Get-Module -ListAvailable | Where-Object Name -eq AdmPwd.PS).Count -eq 1) {
    Import-Module -Name AdmPwd.PS
  }
  else {
    Write-Error 'LAPS Module required for LAPS configuration. Install LAPS management tools'
    Break
  }
  
  if (!(Update-TSxLAPSSchema)) {
    Write-Error 'LAPS Schema extensions has not been added and user is not a member of group "Schema Admins". Add user to this group, logout and logon then rerun script'
    Exit
  }
}

#Read ExtraOrganizationalUnits csv-file.
if (Test-Path -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\ExtraOrganizationalUnits.csv" -ErrorAction SilentlyContinue) {
  $extraous = Import-Csv -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\ExtraOrganizationalUnits.csv" -Delimiter ','
  Write-Verbose 'Read extra OU from ExtraOrganizationalUnits.csv'
}
if (!($extraous)) {
  'Name, Tier, Description
GenericServers,T0,
GenericServers,T1,
GenericServers,T2,
GenericEndpoints,TE,
' | Set-Content -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\ExtraOrganizationalUnits.csv"
  $extraous = Import-Csv -Path "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)\ExtraOrganizationalUnits.csv" -Delimiter ','
  Write-Verbose 'Read extra OU from ExtraOrganizationalUnits.csv'
}

#Add domain admins and enterprise admins to array
$adminaccountgroups = @()
$serviceaccountgroups = @()
$adminaccountgroups += (Get-ADGroup -Filter "SID -eq ""$DomainSID-512""").Name
$adminaccountgroups += (Get-ADGroup -Filter "SID -eq ""$DomainSID-519""").Name

#Create fine-grained password policies for admin accounts and service accounts.
Try {
  $adminpwd = New-ADFineGrainedPasswordPolicy -Name PWDPolicy-AdminAccounts -Precedence 50 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -MinPasswordAge '0.00:00:00' -MaxPasswordAge '365.00:00:00' -MinPasswordLength 16 -LockoutObservationWindow '0.00:05:00' -LockoutDuration '0.00:05:00' -LockoutThreshold 50 -ProtectedFromAccidentalDeletion $true -Description 'Password Policy for Admin Accounts' -PassThru
  Write-Verbose 'Created fine-grained password policy for admin accounts.'
}
Catch {
  $adminpwd = Get-ADFineGrainedPasswordPolicy -Identity PWDPolicy-AdminAccounts
}
Try {
  $servicepwd = New-ADFineGrainedPasswordPolicy -Name PWDPolicy-ServiceAccounts -Precedence 100 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -MinPasswordAge '0.00:00:00' -MaxPasswordAge '0.00:00:00' -MinPasswordLength 24 -LockoutObservationWindow '0.00:05:00' -LockoutDuration '0.00:05:00' -LockoutThreshold 50 -ProtectedFromAccidentalDeletion $true -Description 'Password Policy for Servie Accounts' -PassThru
  Write-Verbose 'Created fine-grained password policy for service accounts.'
}
Catch {
  $servicepwd = Get-ADFineGrainedPasswordPolicy -Identity PWDPolicy-ServiceAccounts
}

#Creates all GPOs needed for Tiers
Write-Output 'Creating GPOs...'
$enablerdpgpo = New-TSxGPO -Name 'Admin - Enable Remote Desktop w NLA Disabled'
if (!($SkipLAPS)) {
  $lapssettingsgpo = New-TSxGPO -Name 'Admin - LAPS Settings'
  $lapsinstallgpo = New-TSxGPO -Name 'Admin - LAPS Install'
}
if (!($Minimal)) {
  $enforcerestricrdpgpo = New-TSxGPO -Name 'Admin - Enforce using Restricted Mode for RDP connections'
}
$restrictt0adminlogongpo = New-TSxGPO -Name 'Admin - Restrict Admin Logon T0'
$restrictt1adminlogongpo = New-TSxGPO -Name 'Admin - Restrict Admin Logon T1'
$rdprestrictedgpo = New-TSxGPO -Name 'Admin - Enable Remote Desktop w Restricted Admin Mode Enable'
$t1jumpstationgroupsgpo = New-TSxGPO -Name 'Admin - Add Domain Tier1 Jumpstation AD Groups to Local Groups'
$t1jumpstationlimitedgroupsgpo = New-TSxGPO -Name 'Admin - Add Domain Tier1 JumpstationLimited AD Groups to Local Groups'
$disablesecdesktopgpo = New-TSxGPO -Name 'Admin - Disable Secure Desktop for UAC'
if ($NoOfTiers -eq 2) {
  $restrictt2adminlogongpo = New-TSxGPO -Name 'Admin - Restrict Admin Logon T2'
  $t2jumpstationgroupsgpo = New-TSxGPO -Name 'Admin - Add Domain Tier2 Jumpstation AD Groups to Local Groups'
  $t2jumpstationlimitedgroupsgpo = New-TSxGPO -Name 'Admin - Add Domain Tier2 JumpstationLimited AD Groups to Local Groups'
}
if (!($SkipTierEndpoints)) {
  $restrictteadminlogongpo = New-TSxGPO -Name 'Admin - Restrict Admin Logon TE'
  $tejumpstationgroupsgpo = New-TSxGPO -Name 'Admin - Add Domain TierEndpoints AD Groups to Local Groups'
}
$dckerberosgpo = New-TSxGPO -Name 'Admin - Kerberos Settings for Domain Controllers'
$clientkerberosgpo = New-TSxGPO -Name 'Admin - Kerberos Settings for Clients'
if (!($SkipPAW)) {
  $restrictpahlogongpo = New-TSxGPO -Name 'Admin - Restrict Logon TierEndpointPAW Hosts'
  $comphighperf = New-TSxGPO -Name 'Admin - Set Computer Powerplan to High Performance'
}

#Creates base OU.s for Tier and Company.
$tierou = New-TSxADOrganizationalUnit -Name $TierOUName -Path $DomainDN -Description 'All admin accounts, service accounts, PAWs, servers and admingroups'
if (!($SkipTierEndpoints -and $SkipComputerRedirect)) {
  $companyou = New-TSxADOrganizationalUnit -Name $CompanyName -Path $DomainDN -Description "BaseOU for $CompanyName"
}

#Create and set default Computers OU.
if (!($SkipTierEndpoints -and $SkipComputerRedirect)) {
  $computerqou = New-TSxADOrganizationalUnit -Name ComputerQuarantine -Path $companyou.DistinguishedName -Description 'Quarantined Computers'
}
if (!($SkipComputerRedirect)) {
  & redircmp.exe $computerqou.DistinguishedName
  Write-Verbose "Computer default OU redirected to $($computerqou.DistinguishedName)"
}

#Blocks creating GPO Links in base OU.s
if (!($SkipTierEndpoints -and $SkipComputerRedirect)) {
  Set-TSxOUPermission -OrganizationalUnitDN $companyou.DistinguishedName -GroupName Everyone -ObjectType DenyGPLink
}
Set-TSxOUPermission -OrganizationalUnitDN $tierou.DistinguishedName -GroupName Everyone -ObjectType DenyGPLink


Write-Output 'Creating Tier0...'
#Creates all Tier0 OU.s
$t0ou = New-TSxADOrganizationalUnit -Name Tier0 -Path $tierou.DistinguishedName -Description 'Tier0 accounts, PAWs, servers and groups'
New-TSxADOrganizationalUnit -Name AdminAccounts -Path $t0ou.DistinguishedName  -Description 'Tier0 Admin accounts' -NoOut
New-TSxADOrganizationalUnit -Name ServiceAccounts -Path $t0ou.DistinguishedName  -Description 'Tier0 Service accounts' -NoOut
$t0jumpou = New-TSxADOrganizationalUnit -Name JumpStations -Path $t0ou.DistinguishedName  -Description 'Tier0 JumpStations management servers.'
if (!($SkipPAW)) {
  $t0pawou = New-TSxADOrganizationalUnit -Name PrivilegedAccessWorkstations -Path $t0ou.DistinguishedName -Description 'Tier0 Privileged access workstations'
}
$t0groupou = New-TSxADOrganizationalUnit -Name Groups -Path $t0ou.DistinguishedName -Description 'Tier0 Groups'
$t0serverou = New-TSxADOrganizationalUnit -Name Servers -Path $t0ou.DistinguishedName -Description 'Tier0 Servers'
foreach ($extraou in $extraous | Where-Object {$_.Tier -eq 'T0'}) {
  New-TSxSubOU -Tier T0 -Name $extraou.Name -Description $extraou.Description -TierOUName $TierOUName -CompanyName $CompanyName
}

#Block GPO inheritance for Tier0 PAW and Jumpstations
Write-Verbose 'Blocking GPO inheritance for PAW and Jumpstations in Tier 0'
if (!($SkipPAW)) {
  Set-GPInheritance -Target $t0pawou.DistinguishedName -IsBlocked Yes | Out-Null
}
Set-GPInheritance -Target $t0jumpou.DistinguishedName -IsBlocked Yes | Out-Null

#Creates all GPO Links for Tier0
New-TSxGPLink -Id ($enablerdpgpo.Id).Guid -Target $t0jumpou.DistinguishedName -LinkEnabled Yes | Out-Null
New-TSxGPLink -Id ($restrictt0adminlogongpo.Id).Guid -Target $t0jumpou.DistinguishedName -LinkEnabled Yes | Out-Null
New-TSxGPLink -Id ($restrictt0adminlogongpo.Id).Guid -Target $t0serverou.DistinguishedName -LinkEnabled Yes | Out-Null
New-TSxGPLink -Id ($restrictt0adminlogongpo.Id).Guid -Target "OU=Domain Controllers,$DomainDN" -LinkEnabled Yes | Out-Null
if (!($SkipLAPS)) {
  New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $t0serverou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $t0jumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $t0serverou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $t0jumpou.DistinguishedName -LinkEnabled Yes | Out-Null
}
if (!($Minimal)) {
  New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $t0jumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($rdprestrictedgpo.Id).Guid -Target $t0serverou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($rdprestrictedgpo.Id).Guid -Target "OU=Domain Controllers,$DomainDN" -LinkEnabled Yes | Out-Null 
}
New-TSxGPLink -Id ($dckerberosgpo.Id).Guid -Target "OU=Domain Controllers,$DomainDN" -LinkEnabled Yes | Out-Null
New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $t0jumpou.DistinguishedName -LinkEnabled Yes | Out-Null
if (!($SkipPAW)) {
  New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $t0pawou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $t0pawou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($restrictt0adminlogongpo.Id).Guid -Target $t0pawou.DistinguishedName -LinkEnabled Yes | Out-Null
}

#Creates Tier0 managed groups.
$t1admingroup = New-TSxADGroup -Name 'Domain Tier1 Admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Tier1 Admin accounts'
$adminaccountgroups += $t1admingroup.Name
$t0servicegroup = New-TSxADGroup -Name 'Domain Tier0 Service accounts' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Tier0 Service accounts'
$serviceaccountgroups += $t0servicegroup.Name
New-TSxADGroup -Name 'Domain Legacy Group Admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Delegated permissions for group objects in legacy structure' -NoOut
New-TSxADGroup -Name 'Domain Legacy Computer Admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Delegated permissions for computer objects in legacy structure' -NoOut
New-TSxADGroup -Name 'Domain Legacy User Admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Delegated permissions for user objects in legacy structure' -NoOut
if ($NoOfTiers -eq 2) {
  $t2admingroup = New-TSxADGroup -Name 'Domain Tier2 Admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Tier2 Admin accounts'
  $adminaccountgroups += $t2admingroup.Name
}
if (!($SkipPAW)) {
  $t0pawdjoingroup = New-TSxADGroup -Name 'Domain Tier0 PrivilegedAccessWorkstations DomainJoin' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Tier0 Privileged access workstation DomainJoin'
  $t0pawadmingroup = New-TSxADGroup -Name 'Domain TierEndpointPAW PrivilegedAccessHosts admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'TierEndpointPAW Privileged access hosts admins'
}
if (!($SkipTierEndpoints)) {
  $teadmingroup = New-TSxADGroup -Name 'Domain TierEndpoints Admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'TierEndpoint Admins Accounts'
  $adminaccountgroups += $teadmingroup.Name
  $helpdeskgroup = New-TSxADGroup -Name 'Domain Helpdesk operator' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Helpdesk Operators'
  $adminaccountgroups += $helpdeskgroup.Name
  $companyendpointadmingroup = New-TSxADGroup -Name 'Domain Company Endpoint admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Endpoint Admins'
  $adminaccountgroups += $companyendpointadmingroup.Name
  $companyuseradmingroup = New-TSxADGroup -Name 'Domain Company User admins' -Path $t0groupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Endpoint Admins'
  $adminaccountgroups += $companyuseradmingroup.Name
}

#Sets Tier0 LAPS self permissions unless SkipLAPS set.
if (!($SkipLAPS)) {
  Write-Verbose 'Setting LAPS computer self permissions in Tier0'
  Set-AdmPwdComputerSelfPermission -Identity $t0jumpou.DistinguishedName | Out-Null
  Set-AdmPwdComputerSelfPermission -Identity $t0serverou.DistinguishedName | Out-Null
}

#Sets Tier0 OU permissions
if (!($SkipPAW)) {
  Set-TSxOUPermission -OrganizationalUnitDN $t0pawou.DistinguishedName -GroupName $t0pawdjoingroup.Name -ObjectType ComputersCreate
}

#Create Tier0 AuthenticationPolicySilo
New-TSxAuthenticationPolicy -Tier T0


#Create Tiers
foreach ($i in 1..$NoOfTiers) {
  Write-Output "Creating Tier$i..."
  #Creates all Tier OU.s
  $txou = New-TSxADOrganizationalUnit -Name Tier$i -Path $tierou.DistinguishedName -Description "Tier$i accounts, PAWs, servers and groups"
  $txadminou = New-TSxADOrganizationalUnit -Name AdminAccounts -Path $txou.DistinguishedName -Description "Tier$i Admin Accounts"
  $txserviceou = New-TSxADOrganizationalUnit -Name ServiceAccounts -Path $txou.DistinguishedName  -Description "Tier$i Service Accounts"
  $txjumpou = New-TSxADOrganizationalUnit -Name JumpStations -Path $txou.DistinguishedName  -Description "Tier$i JumpStations Management Servers"
  $txjumplimitedou = New-TSxADOrganizationalUnit -Name JumpStationsLimited -Path $txou.DistinguishedName  -Description "Tier$i JumpStationsLimited Management Servers"
  if (!($SkipPAW)) {
    $txpawou = New-TSxADOrganizationalUnit -Name PrivilegedAccessWorkstations -Path $txou.DistinguishedName -Description "Tier$i Privileged Access Workstations"
  }
  $txgroupou = New-TSxADOrganizationalUnit -Name Groups -Path $txou.DistinguishedName -Description "Tier$i Groups"
  $txserverou = New-TSxADOrganizationalUnit -Name Servers -Path $txou.DistinguishedName -Description "Tier$i Servers"
  foreach ($extraou in $extraous | Where-Object {$_.Tier -eq "T$i"}) {
    New-TSxSubOU -Tier "T$i" -Name $extraou.Name -Description $extraou.Description -TierOUName $TierOUName -CompanyName $CompanyName
  }

  #Block GPO inheritance for Tier PAW and Jumpstations
  Write-Verbose "Blocking GPO inheritance for PAW and Jumpstations in $Tier$i"
  if (!($SkipPAW)) {
    Set-GPInheritance -Target $txpawou.DistinguishedName -IsBlocked Yes | Out-Null
  }
  Set-GPInheritance -Target $txjumpou.DistinguishedName -IsBlocked Yes | Out-Null
  Set-GPInheritance -Target $txjumplimitedou.DistinguishedName -IsBlocked Yes | Out-Null

  #Creates all GPO Links for Tier
  New-TSxGPLink -Id ($enablerdpgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($enablerdpgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
  if (!($SkipLAPS)) {
    New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $txserverou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $txserverou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
  }
  if (!($Minimal)) {
    New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
  }
  New-TSxGPLink -Id ($rdprestrictedgpo.Id).Guid -Target $txserverou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $txserverou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
  if ($i -eq 1) {
    New-TSxGPLink -Id ($restrictt1adminlogongpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($restrictt1adminlogongpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($restrictt1adminlogongpo.Id).Guid -Target $txserverou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($t1jumpstationgroupsgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($t1jumpstationlimitedgroupsgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
    if (!($SkipPAW)) {
      New-TSxGPLink -Id ($restrictt1adminlogongpo.Id).Guid -Target $txpawou.DistinguishedName -LinkEnabled Yes | Out-Null
    }
  } 
  if ($i -eq 2) {
    New-TSxGPLink -Id ($restrictt2adminlogongpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($restrictt2adminlogongpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($restrictt2adminlogongpo.Id).Guid -Target $txserverou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($t2jumpstationgroupsgpo.Id).Guid -Target $txjumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($t2jumpstationlimitedgroupsgpo.Id).Guid -Target $txjumplimitedou.DistinguishedName -LinkEnabled Yes | Out-Null
    if (!($SkipPAW)) {
      New-TSxGPLink -Id ($restrictt2adminlogongpo.Id).Guid -Target $txpawou.DistinguishedName -LinkEnabled Yes | Out-Null
    }
  }
  if (!($SkipPAW)) {
    New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $txpawou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $txpawou.DistinguishedName -LinkEnabled Yes | Out-Null
  }
  
  #Creates Tier managed groups.
  if (!($SkipPAW)) {
    $txpawdjoingroup = New-TSxADGroup -Name "Domain Tier$i PrivilegedAccessWorkstations DomainJoin" -Path $txgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description "Tier$i Privileged Access Workstation DomainJoin"
  }
  $txservicegroup = New-TSxADGroup -Name "Domain Tier$i Service accounts" -Path $txgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description "Tier$i Service Accounts"
  $serviceaccountgroups += $txservicegroup.Name
  $txjumprdpgroup = New-TSxADGroup -Name "Domain Tier$i Jumpstation remote desktop users" -Path $txgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description "Tier$i Jumpstation remote desktop users"
  $adminaccountgroups += $txjumprdpgroup.Name
  $txjumpadmingroup = New-TSxADGroup -Name "Domain Tier$i Jumpstation Admins" -Path $txgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description "Tier$i Jumpstation admins"
  $adminaccountgroups += $txjumpadmingroup.Name
  $txjumplimitedrdpgroup = New-TSxADGroup -Name "Domain Tier$i JumpstationLimited remote desktop users" -Path $txgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description "Tier$i JumpstationLimited remote desktop users"
  $adminaccountgroups += $txjumplimitedrdpgroup.Name
  $txjumplimitedadmingroup = New-TSxADGroup -Name "Domain Tier$i JumpstationLimited Admins" -Path $txgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description "Tier$i JumpstationLimited Admins"
  $adminaccountgroups += $txjumplimitedadmingroup.Name
  if ($i -eq 1) {
    Add-ADGroupMember -Identity $txjumpadmingroup -Members $t1admingroup
    Add-ADGroupMember -Identity $txjumplimitedadmingroup -Members $t1admingroup
  }
  if ($i -eq 2) {
    Add-ADGroupMember -Identity $txjumpadmingroup -Members $t2admingroup
    Add-ADGroupMember -Identity $txjumplimitedadmingroup -Members $t2admingroup
  }
  
  #Sets Tier LAPS self permissions unless SkipLAPS set.
  if (!($SkipLAPS)) {
    Write-Verbose "Setting LAPS computer self permissions in $Tier$i"
    Set-AdmPwdComputerSelfPermission -Identity $txjumpou.DistinguishedName | Out-Null
    Set-AdmPwdComputerSelfPermission -Identity $txjumplimitedou.DistinguishedName | Out-Null
    Set-AdmPwdComputerSelfPermission -Identity $txserverou.DistinguishedName | Out-Null
    
    Set-AdmPwdReadPasswordPermission -Identity $txjumpou.DistinguishedName -AllowedPrincipals $txjumpadmingroup.Name | Out-Null
    Set-AdmPwdReadPasswordPermission -Identity $txjumplimitedou.DistinguishedName -AllowedPrincipals $txjumplimitedadmingroup.Name | Out-Null
  }

  #Sets Tier OU permissions
  if (!($SkipPAW)) {
    Set-TSxOUPermission -OrganizationalUnitDN $txpawou.DistinguishedName -GroupName $txpawdjoingroup.Name -ObjectType ComputersCreate
  }

  if ($i -eq 1) {
    Set-TSxOUPermission -OrganizationalUnitDN $txserverou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType ComputersCreateGPLink
    Set-TSxOUPermission -OrganizationalUnitDN $txserverou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType OUsCreate
    Set-TSxOUPermission -OrganizationalUnitDN $txjumpou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType ComputersCreateGPLink
    Set-TSxOUPermission -OrganizationalUnitDN $txjumplimitedou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType ComputersCreateGPLink
    if (!($SkipTierEndpoints) -and !($SkipComputerRedirect)) {
      Set-TSxOUPermission -OrganizationalUnitDN $computerqou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType ComputersCreate
    }
    Set-TSxOUPermission -OrganizationalUnitDN $txadminou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType UsersCreate
    Set-TSxOUPermission -OrganizationalUnitDN $txgroupou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType GroupsCreate
    Set-TSxOUPermission -OrganizationalUnitDN $txserviceou.DistinguishedName -GroupName $t1admingroup.Name -ObjectType UsersCreate
  }

  if ($i -eq 2) {
    Set-TSxOUPermission -OrganizationalUnitDN $txserverou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType ComputersCreateGPLink
    Set-TSxOUPermission -OrganizationalUnitDN $txserverou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType OUsCreate
    Set-TSxOUPermission -OrganizationalUnitDN $txjumpou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType ComputersCreateGPLink
    Set-TSxOUPermission -OrganizationalUnitDN $txjumplimitedou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType ComputersCreateGPLink
    if (!($SkipTierEndpoints) -and !($SkipComputerRedirect)) {
      Set-TSxOUPermission -OrganizationalUnitDN $computerqou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType ComputersCreate
    }
    Set-TSxOUPermission -OrganizationalUnitDN $txadminou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType UsersCreate
    Set-TSxOUPermission -OrganizationalUnitDN $txgroupou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType GroupsCreate
    Set-TSxOUPermission -OrganizationalUnitDN $txserviceou.DistinguishedName -GroupName $t2admingroup.Name -ObjectType UsersCreate
  }

  #Create Tier AuthenticationPolicySilo
  New-TSxAuthenticationPolicy -Tier T$i
  New-TSxAuthenticationPolicy -Tier "T$($i)Limited"
}


if (!($SkipTierEndpoints)) {
  Write-Output 'Creating TierEndpoints...'
  #Creates all TierEndpoint OU.s
  $tetierou = New-TSxADOrganizationalUnit -Name TierEndpoints -Path $tierou.DistinguishedName -Description 'TierEndpoints accounts, PAWs and groups'
  $teadminou = New-TSxADOrganizationalUnit -Name AdminAccounts -Path $tetierou.DistinguishedName -Description 'TierEndpoints Admin Accounts'
  $teserviceou = New-TSxADOrganizationalUnit -Name ServiceAccounts -Path $tetierou.DistinguishedName -Description 'TierEndpoints Service Accounts'
  $tejumpou = New-TSxADOrganizationalUnit -Name JumpStations -Path $tetierou.DistinguishedName  -Description 'TierEndpoints JumpStations Management Servers.'
  $tegroupou = New-TSxADOrganizationalUnit -Name Groups -Path $tetierou.DistinguishedName -Description 'TierEndpoints Groups'
  if (!($SkipPAW)) {
    $tepawou = New-TSxADOrganizationalUnit -Name PrivilegedAccessWorkstations -Path $tetierou.DistinguishedName -Description 'TierEndpoints Privileged Access Workstations'
  }
  $compendpointou = New-TSxADOrganizationalUnit -Name Endpoints -Path $companyou.DistinguishedName -Description 'All User Endpoints'
  $composdou = New-TSxADOrganizationalUnit -Name OSDeploy -Path $compendpointou.DistinguishedName -Description 'OS Deploy Temporary Endpoints'
  $compusergroupou = New-TSxADOrganizationalUnit -Name UserGroups -Path $companyou.DistinguishedName -Description 'All User Groups'
  $compendpointgroupou = New-TSxADOrganizationalUnit -Name EndpointGroups -Path $companyou.DistinguishedName -Description 'All Endpoint Groups'
  New-TSxADOrganizationalUnit -Name DistributionGroups -Path $compusergroupou.DistinguishedName -Description 'All User Distribution Groups' -NoOut
  New-TSxADOrganizationalUnit -Name AzureADReplicatedSecurityGroups -Path $compusergroupou.DistinguishedName -Description 'All User AzureAD Replicated User Groups' -NoOut
  New-TSxADOrganizationalUnit -Name SecurityGroups -Path $compusergroupou.DistinguishedName -Description 'All User Security Groups' -NoOut
  New-TSxADOrganizationalUnit -Name AzureADReplicatedSecurityGroups -Path $compendpointgroupou.DistinguishedName -Description 'All Endpoint AzureAD Replicated User Groups' -NoOut
  New-TSxADOrganizationalUnit -Name SecurityGroups -Path $compendpointgroupou.DistinguishedName -Description 'All Endpoint Security Groups' -NoOut
  $compuserou = New-TSxADOrganizationalUnit -Name UserAccounts -Path $companyou.DistinguishedName  -Description 'All Users'
  New-TSxADOrganizationalUnit -Name DisabledUsers -Path $compuserou.DistinguishedName  -Description 'All Disabled Users' -NoOut
  New-TSxADOrganizationalUnit -Name EnabledUsers -Path $compuserou.DistinguishedName  -Description 'All Enabled Users' -NoOut
  New-TSxADOrganizationalUnit -Name ResourceUsers -Path $compuserou.DistinguishedName  -Description 'All Resource Users' -NoOut
  foreach ($extraou in $extraous | Where-Object {$_.Tier -eq 'TE'}) {
    New-TSxSubOU -Tier TE -Name $extraou.Name -Description $extraou.Description -TierOUName $TierOUName -CompanyName $CompanyName
  }

  #Block GPO inheritance for TierEndpoints PAW, Jumpstations and OSDeploy
  Write-Verbose "Blocking GPO inheritance for PAW, Jumpstations and OSDeploy in $TierEndoints"
  if (!($SkipPAW)) {
    Set-GPInheritance -Target $tepawou.DistinguishedName -IsBlocked Yes | Out-Null
  }
  Set-GPInheritance -Target $tejumpou.DistinguishedName -IsBlocked Yes | Out-Null
  Set-GPInheritance -Target $composdou.DistinguishedName -IsBlocked Yes | Out-Null

  #Creates all GPO Links for TierEndpoints
  New-TSxGPLink -Id ($enablerdpgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  if (!($SkipLAPS)) {
    New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $compendpointou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapssettingsgpo.Id).Guid -Target $computerqou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $compendpointou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($lapsinstallgpo.Id).Guid -Target $computerqou.DistinguishedName -LinkEnabled Yes | Out-Null
  }
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $compendpointou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $computerqou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($disablesecdesktopgpo.Id).Guid -Target $composdou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($restrictteadminlogongpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($restrictteadminlogongpo.Id).Guid -Target $compendpointou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($restrictteadminlogongpo.Id).Guid -Target $computerqou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($restrictteadminlogongpo.Id).Guid -Target $composdou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($tejumpstationgroupsgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $tejumpou.DistinguishedName -LinkEnabled Yes | Out-Null
  if (!($SkipPAW)) {
    New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $tepawou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($enforcerestricrdpgpo.Id).Guid -Target $tepawou.DistinguishedName -LinkEnabled Yes | Out-Null
    New-TSxGPLink -Id ($restrictteadminlogongpo.Id).Guid -Target $tepawou.DistinguishedName -LinkEnabled Yes | Out-Null
  }
  $ErrorActionPreference = 'SilentlyContinue'
  if (Get-ADOrganizationalUnit -Identity "OU=RemoteDesktopSessionEndpoints,$($compendpointou.DistinguishedName)") {
    New-TSxGPLink -Id ($rdprestrictedgpo.Id).Guid -Target "OU=RemoteDesktopSessionEndpoints,$($compendpointou.DistinguishedName)" -LinkEnabled Yes | Out-Null
  }
  $ErrorActionPreference = 'Continue'

  #Creates TierEndpoints managed groups.
  if (!($SkipPAW)) {
    $tepawdjoingroup = New-TSxADGroup -Name 'Domain TierEndpoints PrivilegedAccessWorkstations DomainJoin' -Path $tegroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'TierEndpoints Privileged Access Workstation DomainJoin'
  }
  $teservicegroup = New-TSxADGroup -Name 'Domain TierEndpoints Service accounts' -Path $tegroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'TierEndpoints Service Accounts'
  $serviceaccountgroups += $teservicegroup
  $tejumprdpgroup = New-TSxADGroup -Name 'Domain TierEndpoints Jumpstation remote desktop users' -Path $tegroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'TierEndpoints Jumpstation remote desktop users'
  $adminaccountgroups += $tejumprdpgroup.Name
  $tejumpadmingroup = New-TSxADGroup -Name 'Domain TierEndpoints Jumpstation Admins' -Path $tegroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'TierEndpoints Jumpstation Admins'
  $adminaccountgroups += $tejumprdpgroup.Name
  Add-ADGroupMember -Identity $tejumpadmingroup -Members $teadmingroup

  #Sets TierEndpoints LAPS self permissions unlessSkip set.
  if (!($SkipLAPS)) {
    Write-Verbose "Setting LAPS computer self permissions in TierEndpoints"
    Set-AdmPwdComputerSelfPermission -Identity $tejumpou.DistinguishedName | Out-Null
    Set-AdmPwdComputerSelfPermission -Identity $compendpointou.DistinguishedName | Out-Null
    Set-AdmPwdComputerSelfPermission -Identity $computerqou.DistinguishedName | Out-Null
    Set-AdmPwdComputerSelfPermission -Identity $composdou.DistinguishedName | Out-Null
    Set-AdmPwdReadPasswordPermission -Identity $tejumpou.DistinguishedName -AllowedPrincipals $teadmingroup.Name | Out-Null
  }

  #Sets TierEndpoints OU permissions
  if (!($SkipPAW)) {
    Set-TSxOUPermission -OrganizationalUnitDN $tepawou.DistinguishedName -GroupName $tepawdjoingroup.Name -ObjectType ComputersCreate
  }

  Set-TSxOUPermission -OrganizationalUnitDN $compuserou.DistinguishedName -GroupName $helpdeskgroup.Name -ObjectType Users
  Set-TSxOUPermission -OrganizationalUnitDN $compendpointou.DistinguishedName -GroupName $helpdeskgroup.Name -ObjectType BitLocker
  Set-TSxOUPermission -OrganizationalUnitDN $compusergroupou.DistinguishedName -GroupName $helpdeskgroup.Name -ObjectType GroupsMembers

  Set-TSxOUPermission -OrganizationalUnitDN $computerqou.DistinguishedName -GroupName $companyendpointadmingroup.Name -ObjectType ComputersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compendpointou.DistinguishedName -GroupName $companyendpointadmingroup.Name -ObjectType ComputersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compendpointou.DistinguishedName -GroupName $companyendpointadmingroup.Name -ObjectType OUsCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compendpointgroupou.DistinguishedName -GroupName $companyendpointadmingroup.Name -ObjectType GroupsCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compendpointgroupou.DistinguishedName -GroupName $companyendpointadmingroup.Name -ObjectType OUsCreate

  Set-TSxOUPermission -OrganizationalUnitDN $compusergroupou.DistinguishedName -GroupName $companyuseradmingroup.Name -ObjectType GroupsCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compusergroupou.DistinguishedName -GroupName $companyuseradmingroup.Name -ObjectType OUsCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compuserou.DistinguishedName -GroupName $companyuseradmingroup.Name -ObjectType UsersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $compuserou.DistinguishedName -GroupName $companyuseradmingroup.Name -ObjectType OUsCreate

  Set-TSxOUPermission -OrganizationalUnitDN $teadminou.DistinguishedName -GroupName $teadmingroup.Name -ObjectType UsersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $teserviceou.DistinguishedName -GroupName $teadmingroup.Name -ObjectType UsersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $tegroupou.DistinguishedName -GroupName $teadmingroup.Name -ObjectType GroupsCreate
  Set-TSxOUPermission -OrganizationalUnitDN $tejumpou.DistinguishedName -GroupName $teadmingroup.Name -ObjectType ComputersCreate
}


if (!($SkipPAW)) {
  Write-Output 'Creating TierEndpointsPAW...'
  #Creates all TierEndpointsPAW OU.s
  $tepou = New-TSxADOrganizationalUnit -Name TierEndpointsPAW -Path $tierou.DistinguishedName -Description 'TierEndpointPAW groups and PAW Hosts'
  $tepgroupou = New-TSxADOrganizationalUnit -Name Groups -Path $tepou.DistinguishedName -Description 'TierEndpointsPAW Groups'
  $teppahou = New-TSxADOrganizationalUnit -Name PrivilegedAccessHosts -Path $tepou.DistinguishedName -Description 'TierEndpointsPAW Privileged Access Hosts'
  $tepusersou = New-TSxADOrganizationalUnit -Name UserAccounts -Path $tepou.DistinguishedName -Description 'TierEndpointsPAW Privileged Access Hosts User Accounts'

  #Block GPO inheritance for TierEndpointsPAW PAW Hosts
  Set-GPInheritance -Target $teppahou.DistinguishedName -IsBlocked Yes | Out-Null

  #Creates TierEndpointsPAW managed groups.
  $teppahdjoingroup = New-TSxADGroup -Name 'Domain TierEndpointsPAW PrivilegedAccessHosts DomainJoin' -Path $tepgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Tier EndpointsPAW Privileged Access Hosts DomainJoin'
  New-TSxADGroup -Name 'Domain TierEndpointsPAW PrivilegedAccessHosts users' -Path $tepgroupou.DistinguishedName -GroupCategory Security -GroupScope Global -Description 'Tier EndpointsPAW Privileged Access Hosts Users' -NoOut

  #Sets TierEndpointsPAW OU permissions
  Set-TSxOUPermission -OrganizationalUnitDN $teppahou.DistinguishedName -GroupName $t0pawadmingroup.Name -ObjectType ComputersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $teppahou.DistinguishedName -GroupName $teppahdjoingroup.Name -ObjectType ComputersCreate
  Set-TSxOUPermission -OrganizationalUnitDN $tepgroupou.DistinguishedName -GroupName $t0pawadmingroup.Name -ObjectType GroupsCreate
  Set-TSxOUPermission -OrganizationalUnitDN $tepusersou.DistinguishedName -GroupName $t0pawadmingroup.Name -ObjectType UsersCreate

  #Creates all GPO Links for EndpointPAW
  New-TSxGPLink -Id ($restrictpahlogongpo.Id).Guid -Target $teppahou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($clientkerberosgpo.Id).Guid -Target $teppahou.DistinguishedName -LinkEnabled Yes | Out-Null
  New-TSxGPLink -Id ($comphighperf.Id).Guid -Target $teppahou.DistinguishedName -LinkEnabled Yes | Out-Null

  #Create TierEndpointsPAW AuthenticationPolicySilo
  New-TSxAuthenticationPolicy -Tier TP
}


# Creates CompanyOU if Minimal set
if ($Minimal) {
  $companyou = New-TSxADOrganizationalUnit -Name $CompanyName -Path $DomainDN -Description "BaseOU for $CompanyName"
  $compendpointou = New-TSxADOrganizationalUnit -Name Endpoints -Path $companyou.DistinguishedName -Description 'All User Endpoints'
  New-TSxGPLink -Id ($restrictt1adminlogongpo.Id).Guid -Target $compendpointou.DistinguishedName -LinkEnabled Yes | Out-Null
  if (!($SkipComputerRedirect)) {
    New-TSxGPLink -Id ($restrictt1adminlogongpo.Id).Guid -Target $computerqou.DistinguishedName -LinkEnabled Yes | Out-Null
  }
  New-TSxADOrganizationalUnit -Path $compendpointou -Name 'GenericEndpoints' -Description '' -NoOut
}

#Assign created admin and service account groups to password policies
Write-Verbose "Adding all admin and service account groups to fine-grained password policies"
Add-ADFineGrainedPasswordPolicySubject -Identity $adminpwd.Name -Subjects $adminaccountgroups
Add-ADFineGrainedPasswordPolicySubject -Identity $servicepwd.Name -Subjects $serviceaccountgroups

Write-Output '' 'Done!'

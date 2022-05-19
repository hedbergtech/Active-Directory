<#
.Synopsis
   TSxUtilityModule.psm1
.DESCRIPTION
   TSxUtilityModule.psm1
.NOTES
   Author:mikael.nystrom@truesec.se
   Version 1.1
   # Added New-TSxAdminAccountCon
#>

Function New-TSxRandomPassword{
    <#
    .DESCRIPTION
    Generate a password
    .EXAMPLE
    New-UUPassword
    Generates a 30 Character complex password
    .EXAMPLE
    New-UUPassword -PasswordLength 12 -Complex $false
    Generate a 12 Character simple password
    .PARAMETER PasswordLength
    Lenght of password
    .PARAMETER Simple
    Make a simple password, no special character
    #>
      [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
      [OutputType("System.String")]
      param(
          [parameter(mandatory = $false)]
          [int]
          $PasswordLength = 30,
          [parameter(mandatory = $false)]
          [Switch]$Simple
      )
      if ($pscmdlet.ShouldProcess("Generating a $PasswordLength char password")) {
          #Characters to use based
          $strCharacters = "A", "B", "C", "D", "E", "F", "G", "H", "J", "K", "L", "M", "N", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"
          $strComplex = "!", "_", "?", "*", "%", "-", "(", ")", "="
          $strNumbers = "2", "3", "4", "5", "6", "7", "8", "9", "0"
  
          #Check to see if password contains at least 1 digit
          $bolHasNumber = $false
          $pass = $null
          #Sets which Character Array to use based on $Complex
          #Loop to actually generate the password
          for ($i = 0; $i -lt $PasswordLength; $i++) {
              $c = Get-Random -InputObject $strCharacters
              if ([char]::IsDigit($c)) {$bolHasNumber = $true}
              $pass += $c
          }
          if ($Simple -ne $true) {
              # Get 4 random characters, and replace them with special characters
              $RandomChar = 1..($PasswordLength - 1) | Get-Random -count 4
              foreach ($Char in $RandomChar) {
                  $NewChar = Get-Random -InputObject $strComplex
                  if ([char]::IsDigit($NewChar)) {$bolHasNumber = $true}
                  $pwArray = $pass.ToCharArray()
                  $pwArray[$Char] = $NewChar
                  $pass = ""
                  foreach ($s in $pwArray) {
                      $pass += $s
                  }
  
              }
  
          }
          #Check to see if a Digit was seen, if not, fixit
          if ($bolHasNumber) {
              return $pass
          }
          else {
              $RandomChar = Get-Random -Maximum ($PasswordLength - 1)
              $NewChar = Get-Random -InputObject $strNumbers
              $pwArray = $pass.ToCharArray()
              $pwArray[$RandomChar] = $NewChar
              $pass = ""
              foreach ($s in $pwArray) {
                  $pass += $s
              }
              return $pass
          }
      }
  }
  Function New-TSxAdminAccountT0{
      [cmdletbinding(SupportsShouldProcess=$True)]
  
      Param
      (
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LogonName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $FirstName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LastName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $AccountDescription,
  
          [parameter(mandatory=$True)]
          $AddToSilo
  
      )
      if((Test-TSxAdminAccount -SamAccountName $LogonName) -eq $True){
          Write-Warning "$LogonName already exist"
          Return
          }
      $CurrentDomain = Get-ADDomain
      $AccountOUDN = "OU=AdminAccounts,OU=Tier0,OU=Admin,$((Get-ADDomain).DistinguishedName)"
      $TargetOU = (Get-ADOrganizationalUnit -Identity $AccountOUDN)
      $UserPrincipalName = $LogonName + "@" + $((Get-ADDomain).Forest)
      $NewAccount = New-ADUser `
      -Description $($AccountDescription) `
      -DisplayName $("[T0 ADM] " + $FirstName + " " + $LastName) `
      -GivenName $($FirstName) `
      -Surname $($LastName) `
      -Name $("[T0 ADM] " + $FirstName + " " + $LastName) `
      -Path $TargetOU `
      -SamAccountName $($LogonName) `
      -CannotChangePassword $false `
      -PasswordNeverExpires $false `
      -ChangePasswordAtLogon $False `
      -UserPrincipalName $UserPrincipalName `
      -PassThru 
  
      $AccountPW = New-TSxRandomPassword -PasswordLength 14
      $SecurePassword = ConvertTo-SecureString -String $AccountPW -AsPlainText -Force
      $Return = Set-ADAccountPassword $NewAccount -NewPassword $SecurePassword -PassThru -ErrorAction Stop
  
      #Set-ADAccountControl $NewAccount -CannotChangePassword $false -PasswordNeverExpires $true
      #Set-ADUser $NewAccount -ChangePasswordAtLogon $False 
      $Return = Enable-ADAccount $NewAccount
  
      $DomainSID=(Get-ADDomain).DomainSid.Value
      $DomainAdminGroup = Get-ADGroup -Filter "SID -eq ""$DomainSID-512"""
      Add-ADGroupMember -Identity $DomainAdminGroup.SamAccountName -Members $NewAccount
      
      if($AddToSilo -eq $true){
          Set-TSxAdminADAuthenticationPolicySiloForUser -Tier T0 -ADUserIdentity $NewAccount
      }
  
      $Object = New-Object PSCustomObject
      $object | Add-Member NoteProperty DisplayName $NewAccount.Name
      $object | Add-Member NoteProperty SamAccountName $NewAccount.SamAccountName
      $object | Add-Member NoteProperty UserPrincipalName $NewAccount.UserPrincipalName
      $Object | Add-Member NoteProperty Password $AccountPW
      Return $Object
  }
  Function New-TSxAdminAccountT1{
      [cmdletbinding(SupportsShouldProcess=$True)]
  
      Param
      (
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LogonName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $FirstName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LastName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $AccountDescription,
  
          [parameter(mandatory=$True)]
          $AddToSilo,
  
          [parameter(mandatory=$True)]
          $Limited
  
      )
      if((Test-TSxAdminAccount -SamAccountName $LogonName) -eq $True){
          Write-Warning "$LogonName already exist"
          Return
      }
      $CurrentDomain = Get-ADDomain
      $AccountOUDN = "OU=AdminAccounts,OU=Tier1,OU=Admin,$((Get-ADDomain).DistinguishedName)"
      $TargetOU = (Get-ADOrganizationalUnit -Identity $AccountOUDN)
      $UserPrincipalName = $LogonName + "@" + $((Get-ADDomain).Forest)
      $NewAccount = New-ADUser `
      -Description $($AccountDescription) `
      -DisplayName $("[T1 ADM] " + $FirstName + " " + $LastName) `
      -GivenName $($FirstName) `
      -Surname $($LastName) `
      -Name $("[T1 ADM] " + $FirstName + " " + $LastName) `
      -Path $TargetOU `
      -SamAccountName $($LogonName) `
      -CannotChangePassword $false `
      -PasswordNeverExpires $false `
      -ChangePasswordAtLogon $False `
      -UserPrincipalName $UserPrincipalName `
      -PassThru
  
      $AccountPW = New-TSxRandomPassword -PasswordLength 14
      $SecurePassword = ConvertTo-SecureString -String $AccountPW -AsPlainText -Force
      $Return = Set-ADAccountPassword $NewAccount -NewPassword $SecurePassword -PassThru -ErrorAction Stop
      $Return = Enable-ADAccount $NewAccount
  
      if ($Limited) {
          $ADGroups = "Domain Tier1 JumpstationLimited Remote Desktop Users"
      }
      else {
          $ADGroups = "Domain Tier1 Jumpstation Admins"
      }
      foreach($ADGroup in $ADGroups){
          $Group = Get-ADGroup $ADGroup
          Add-ADGroupMember -Identity $Group -Members $NewAccount
      }
  
      if($AddToSilo -eq $true){
          if ($Limited) {
              Set-TSxAdminADAuthenticationPolicySiloForUser -Tier T1Limited -ADUserIdentity $NewAccount
          }
          else {
              Set-TSxAdminADAuthenticationPolicySiloForUser -Tier T1 -ADUserIdentity $NewAccount
          }
      }
  
      $Object = New-Object PSCustomObject
      $object | Add-Member NoteProperty DisplayName $NewAccount.Name
      $object | Add-Member NoteProperty SamAccountName $NewAccount.SamAccountName
      $object | Add-Member NoteProperty UserPrincipalName $NewAccount.UserPrincipalName
      $Object | Add-Member NoteProperty Password $AccountPW
      Return $Object
  }
  Function New-TSxAdminAccountT2{
      [cmdletbinding(SupportsShouldProcess=$True)]
  
      Param
      (
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LogonName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $FirstName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LastName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $AccountDescription,
  
          [parameter(mandatory=$True)]
          $AddToSilo,
  
          [parameter(mandatory=$True)]
          $Limited
  
      )
      if((Test-TSxAdminAccount -SamAccountName $LogonName) -eq $True){
          Write-Warning "$LogonName already exist"
          Return
      }
      $CurrentDomain = Get-ADDomain
      $AccountOUDN = "OU=AdminAccounts,OU=Tier2,OU=Admin,$((Get-ADDomain).DistinguishedName)"
      $TargetOU = (Get-ADOrganizationalUnit -Identity $AccountOUDN)
      $UserPrincipalName = $LogonName + "@" + $((Get-ADDomain).Forest)
      $NewAccount = New-ADUser `
      -Description $($AccountDescription) `
      -DisplayName $("[T2 ADM] " + $FirstName + " " + $LastName) `
      -GivenName $($FirstName) `
      -Surname $($LastName) `
      -Name $("[T2 ADM] " + $FirstName + " " + $LastName) `
      -Path $TargetOU `
      -SamAccountName $($LogonName) `
      -CannotChangePassword $false `
      -PasswordNeverExpires $false `
      -ChangePasswordAtLogon $False `
      -UserPrincipalName $UserPrincipalName `
      -PassThru
  
      $AccountPW = New-TSxRandomPassword -PasswordLength 14
      $SecurePassword = ConvertTo-SecureString -String $AccountPW -AsPlainText -Force
      $Return = Set-ADAccountPassword $NewAccount -NewPassword $SecurePassword -PassThru -ErrorAction Stop
      $Return = Enable-ADAccount $NewAccount
  
      if ($Limited) {
          $ADGroups = "Domain Tier2 JumpstationLimited Remote Desktop users"
      }
      else {
          $ADGroups = "Domain Tier2 Jumpstation Admins"
      }
      foreach($ADGroup in $ADGroups){
          $Group = Get-ADGroup $ADGroup
          Add-ADGroupMember -Identity $Group -Members $NewAccount
      }
  
      if($AddToSilo -eq $true){
          if ($Limited) {
              Set-TSxAdminADAuthenticationPolicySiloForUser -Tier T2Limited -ADUserIdentity $NewAccount
          }
          else {
              Set-TSxAdminADAuthenticationPolicySiloForUser -Tier T2 -ADUserIdentity $NewAccount
          }
      }
  
      $Object = New-Object PSCustomObject
      $object | Add-Member NoteProperty DisplayName $NewAccount.Name
      $object | Add-Member NoteProperty SamAccountName $NewAccount.SamAccountName
      $object | Add-Member NoteProperty UserPrincipalName $NewAccount.UserPrincipalName
      $Object | Add-Member NoteProperty Password $AccountPW
      Return $Object
  }
  Function New-TSxAdminAccountTE{
      [cmdletbinding(SupportsShouldProcess=$True)]
  
      Param
      (
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LogonName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $FirstName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LastName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $AccountDescription
      )
      if((Test-TSxAdminAccount -SamAccountName $LogonName) -eq $True){
          Write-Warning "$LogonName already exist"
          Return
      }
  
      $CurrentDomain = Get-ADDomain
      $AccountOUDN = "OU=AdminAccounts,OU=TierEndpoints,OU=Admin,$((Get-ADDomain).DistinguishedName)"
      $TargetOU = (Get-ADOrganizationalUnit -Identity $AccountOUDN)
      $UserPrincipalName = $LogonName + "@" + $((Get-ADDomain).Forest)
      $NewAccount = New-ADUser `
      -Description $($AccountDescription) `
      -DisplayName $("[TE ADM] " + $FirstName + " " + $LastName) `
      -GivenName $($FirstName) `
      -Surname $($LastName) `
      -Name $("[TE ADM] " + $FirstName + " " + $LastName) `
      -Path $TargetOU `
      -SamAccountName $($LogonName) `
      -CannotChangePassword $false `
      -PasswordNeverExpires $false `
      -ChangePasswordAtLogon $False `
      -UserPrincipalName $UserPrincipalName `
      -PassThru
  
      $AccountPW = New-TSxRandomPassword -PasswordLength 14
      $SecurePassword = ConvertTo-SecureString -String $AccountPW -AsPlainText -Force
      $Return = Set-ADAccountPassword $NewAccount -NewPassword $SecurePassword -PassThru -ErrorAction Stop
      $Return = Enable-ADAccount $NewAccount
  
      $ADGroups = "Domain TierEndpoints Jumpstation Remote Desktop Users"
      foreach($ADGroup in $ADGroups){
          $Group = Get-ADGroup $ADGroup
          Add-ADGroupMember -Identity $Group -Members $NewAccount
      }
  
      $Object = New-Object PSCustomObject
      $object | Add-Member NoteProperty DisplayName $NewAccount.Name
      $object | Add-Member NoteProperty SamAccountName $NewAccount.SamAccountName
      $object | Add-Member NoteProperty UserPrincipalName $NewAccount.UserPrincipalName
      $Object | Add-Member NoteProperty Password $AccountPW
      Return $Object
  }
  Function New-TSxAdminAccountCon{
      [cmdletbinding(SupportsShouldProcess=$True)]
  
      Param
      (
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LogonName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $FirstName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LastName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $AccountDescription
      )
      if((Test-TSxAdminAccount -SamAccountName $LogonName) -eq $True){
          Write-Warning "$LogonName already exist"
          Return
      }
  
      $CurrentDomain = Get-ADDomain
      $AccountOUDN = "OU=ConnectionAccounts,OU=Admin,$((Get-ADDomain).DistinguishedName)"
      $TargetOU = (Get-ADOrganizationalUnit -Identity $AccountOUDN)
      $UserPrincipalName = $LogonName + "@" + $((Get-ADDomain).Forest)
      $NewAccount = New-ADUser `
      -Description $($AccountDescription) `
      -DisplayName $("[Con ADM] " + $FirstName + " " + $LastName) `
      -GivenName $($FirstName) `
      -Surname $($LastName) `
      -Name $("[Con ADM] " + $FirstName + " " + $LastName) `
      -Path $TargetOU `
      -SamAccountName $($LogonName) `
      -CannotChangePassword $false `
      -PasswordNeverExpires $false `
      -ChangePasswordAtLogon $False `
      -UserPrincipalName $UserPrincipalName `
      -PassThru
  
      $AccountPW = New-TSxRandomPassword -PasswordLength 14
      $SecurePassword = ConvertTo-SecureString -String $AccountPW -AsPlainText -Force
      $Return = Set-ADAccountPassword $NewAccount -NewPassword $SecurePassword -PassThru -ErrorAction Stop
      $Return = Enable-ADAccount $NewAccount
  
      $ADGroups = "Domain Remote Admin Users"
      foreach($ADGroup in $ADGroups){
          $Group = Get-ADGroup $ADGroup
          Add-ADGroupMember -Identity $Group -Members $NewAccount
      }
  
      $Object = New-Object PSCustomObject
      $object | Add-Member NoteProperty DisplayName $NewAccount.Name
      $object | Add-Member NoteProperty SamAccountName $NewAccount.SamAccountName
      $object | Add-Member NoteProperty UserPrincipalName $NewAccount.UserPrincipalName
      $Object | Add-Member NoteProperty Password $AccountPW
      Return $Object
  }
  Function New-TSxAdminAccount{
      Param
      (
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $ShortName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $FirstName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $LastName,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $Description,
  
          [parameter(mandatory=$True)]
          [ValidateNotNullOrEmpty()]
          $AccountType,
  
          [parameter(mandatory=$True)]
          [boolean]$AddToSilo,
  
          [parameter(mandatory=$false)]
          [switch]$Limited
      )
  
      switch ($AccountType)
      {
          'T0' {
              New-TSxAdminAccountT0 -LogonName "$($ShortName + "T0")" -FirstName "$FirstName" -LastName "$LastName" -AccountDescription "$("T0 Admin " + $Description)" -AddToSilo $AddToSilo
          }
          'T1' {
              New-TSxAdminAccountT1 -LogonName "$($ShortName + "T1")" -FirstName "$FirstName" -LastName "$LastName" -AccountDescription "$("T1 Admin " + $Description)" -AddToSilo $AddToSilo -Limited $Limited
          }
          'T2' {
              New-TSxAdminAccountT2 -LogonName "$($ShortName + "T2")" -FirstName "$FirstName" -LastName "$LastName" -AccountDescription "$("T2 Admin " + $Description)" -AddToSilo $AddToSilo -Limited $Limited
          }
          'TE' {
              New-TSxAdminAccountTE -LogonName "$($ShortName + "TE")" -FirstName "$FirstName" -LastName "$LastName" -AccountDescription "$("TE Admin " + $Description)"
          }
          'Con' {
              New-TSxAdminAccountCon -LogonName "$($ShortName + "Con")" -FirstName "$FirstName" -LastName "$LastName" -AccountDescription "$("Con Admin " + $Description)"
          }
          Default {
          }
      }
  }
  Function Test-TSxAdminAccount{
      Param(
         $SamAccountName 
      )
      $User = $(try{Get-ADUser $SamAccountName}catch{$null})
      If ($User -ne $Null) { 
          Return $True
      } Else {
          Return $False
      }
  }
  Function Set-TSxAdminADAuthenticationPolicySiloForUser{
      Param(
          $ADUserIdentity,
          $Tier
      )
      $AuthenticationPolicySiloName = "Restricted_$($Tier)Admin_Logon"
      $UserDistinguishedName = (Get-ADUser -Identity $ADUserIdentity -ErrorAction Stop).DistinguishedName
      $AuthenticationPolicySilo = (Get-ADAuthenticationPolicySilo -Identity $AuthenticationPolicySiloName -ErrorAction Stop).DistinguishedName
      Grant-ADAuthenticationPolicySiloAccess -Identity $AuthenticationPolicySilo -Account $UserDistinguishedName
      Set-ADAccountAuthenticationPolicySilo -Identity $UserDistinguishedName -AuthenticationPolicySilo $AuthenticationPolicySilo
  }
  Function Set-TSxAdminADAuthenticationPolicySiloForComputer{
      Param(
          $ADComputerIdentity,
          $Tier
      )
      $AuthenticationPolicySiloName = "Restricted_$($Tier)Admin_Logon"
      $ComputerDistinguishedName = (Get-ADComputer -Identity $ADComputerIdentity -ErrorAction Stop).DistinguishedName
      $AuthenticationPolicySilo = (Get-ADAuthenticationPolicySilo -Identity $AuthenticationPolicySiloName -ErrorAction Stop).DistinguishedName
      Grant-ADAuthenticationPolicySiloAccess -Identity $AuthenticationPolicySilo -Account $ComputerDistinguishedName
      Set-ADAccountAuthenticationPolicySilo -Identity $ComputerDistinguishedName -AuthenticationPolicySilo $AuthenticationPolicySilo
  }
  Function New-TSxAuthenticationPolicy{
      Param(
          $Tier
      )
      $pdc = (Get-ADDomain).PDCEmulator
      Try {
          Get-ADGroup -Identity 'Domain Controllers' -Server $pdc -ErrorAction Stop | Out-Null
      }
      Catch {
          Write-Error "Can't query $pdc. Verify it responds and try again. ErrorMessage: $($_.Exception.Message)" -Verbose
          Break
      }
  
      Try {
          New-ADAuthenticationPolicy -Name "1hr_$($Tier)Admin_TGT" -Description "1hr_$($Tier)Admin_TGT" -UserTGTLifetimeMins 60 -Server $pdc -ErrorAction Stop
      Do {
              $authpolicy = Get-ADAuthenticationPolicy -Identity "1hr_$($Tier)Admin_TGT" -Server $pdc
              Start-Sleep -Seconds 5
          } Until ($authpolicy)
      }
      Catch {
          Write-Error "Unable to create Authentication Policy 1hr_$($Tier)Admin_TGT. ErrorMessage: $($_.Exception.Message)" -Verbose
      }
  
      Try {
          New-ADAuthenticationPolicySilo -Name "Restricted_$($Tier)Admin_Logon" -Description "Restricted_$($Tier)Admin_Logon" -UserAuthenticationPolicy "1hr_$($Tier)Admin_TGT" -ComputerAuthenticationPolicy "1hr_$($Tier)Admin_TGT" -ServiceAuthenticationPolicy "1hr_$($Tier)Admin_TGT" -Server $pdc -ErrorAction Stop
       Do {
              $authpolicysilo = Get-ADAuthenticationPolicySilo -Identity "Restricted_$($Tier)Admin_Logon" -Server $pdc
              Start-Sleep -Seconds 5
          } Until ($authpolicysilo)
      }
      Catch {
          Write-Error "Unable to create Authentication Policy Silo Restricted_$($Tier)Admin_Logon. ErrorMessage: $($_.Exception.Message)" -Verbose
      }
  
      Set-ADAuthenticationPolicy -Identity "1hr_$($Tier)Admin_TGT" -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == ""Restricted_$($Tier)Admin_Logon""))" -Enforce $true -Server $pdc -ErrorAction Stop -UserAllowedNTLMNetworkAuthentication $true
      Set-ADAuthenticationPolicySilo -Identity "Restricted_$($Tier)Admin_Logon" -Enforce $true -Server $pdc -ErrorAction Stop
  }
  function New-TSxSubOU {
    param (
    [Parameter(Position=0,Mandatory)]
      [ValidateSet('T0','Tier0','T1','Tier1','T2','Tier2','T9','Tier9','TE','TierEndpoints')]
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
      if ($Tier -eq 'T9' -or $Tier -eq 'Tier9') {
        $Tier = 'Tier9'
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
  Function New-TSxGPLink {
    Param(
      $Id,
      $Target,
      $LinkEnabled
    )
  
    Try {
      New-GPLink -Id $Id -Target "$Target" -LinkEnabled $LinkEnabled -ErrorAction Stop
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
  
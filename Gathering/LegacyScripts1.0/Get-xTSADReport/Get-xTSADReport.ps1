<#
License:

The MIT License (MIT)

Copyright (c) 2017 Peter Lofgren

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#TODO: ADD LAPS Check
#TODO: ADD KCC last reset

#>

Param(

    [Parameter(Mandatory=$false)]
    $ReportPath = "C:\setup\HealthChecks\Reports"
)
begin {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    Catch {
        Write-Warning "Failed to import Active Directory Module"
        Break
    }
}
process {
    # Set the basic's
    $htmlreport = @()
    $htmlbody = @()
    $spacer = "<br />"
    
    try {
        $subhead = "<h2>Devices</h2>"
        $htmlbody += $subhead

        $Computers = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate
        
        $subhead = "<h3>Total Devices</h3>"
        $htmlbody += $subhead

        $ComputersData = [ordered] @{
            'Number of Devices' = $($Computers.Count);
            'Number of Clients' = $(($Computers | Where-Object OperatingSystem -NotLike "*Server*").Count);
            'Number of Servers' = $(($Computers | Where-Object OperatingSystem -Like "*Server*").Count);
        }
        $ComputersReport = New-Object PSObject -Property $ComputersData

        $htmlbody += $ComputersReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Active/Passive Devices</h3>"
        $htmlbody += $subhead

        $ComputersEnabled = $Computers | Where-Object Enabled -EQ $true
        $ComputersDisabled = $Computers | Where-Object Enabled -EQ $false

        $ActiveComputersData = [ordered] @{
            'Enabled Devices' = $($ComputersEnabled.Count);
            'Disabled Devices' = $($ComputersDisabled.Count);
            'Enabled Clients' = $(($ComputersEnabled | Where-Object OperatingSystem -NotLike "*Server*").Count);
            'Disabled Clients' = $(($ComputersDisabled | Where-Object OperatingSystem -NotLike "*Server*").Count);
            'Enabled Servers' = $(($ComputersEnabled | Where-Object OperatingSystem -Like "*Server*").Count);
            'Disabled Servers' = $(($ComputersDisabled | Where-Object OperatingSystem -Like "*Server*").Count);
        }
        $ActiveComputersReport = New-Object PSObject -Property $ActiveComputersData

        $htmlbody += $ActiveComputersReport | ConvertTo-Html -Fragment 
        $htmlbody += $spacer

        $subhead = "<h3>Devices per OS</h3>"
        $htmlbody += $subhead

        $ComputersOSs = $Computers | Select-Object OperatingSystem -Unique
        $ComputersOSReport = Foreach ($ComputerOS in $ComputersOSs) {
            Clear-Variable ComputerCount -ErrorAction SilentlyContinue
            [array]$ComputerCount = ($Computers | Where-Object OperatingSystem -like "$($ComputerOS.OperatingSystem)")
            
            $ComputersOSData = [ordered] @{
                OS = $(($ComputerOS | Select-Object @{
                    Name="OperatingSystem";Expression={ 
                        if ($_.OperatingSystem -like "") {
                            Return "Unknown"
                        }
                        Else {
                            return $_.OperatingSystem
                        }
                    }
                }).OperatingSystem);
                Count = $($ComputerCount.Count);
            }
            New-Object PSObject -Property $ComputersOSData
        }

        $htmlbody += $ComputersOSReport | Sort-Object OS | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h2>Users</h2>"
        $htmlbody += $subhead

        $Users = Get-ADUser -Filter * -Properties LastLogonDate,PasswordNeverExpires,PasswordNotRequired,SmartcardLogonRequired,CannotChangePassword,AllowReversiblePasswordEncryption,PasswordLastSet
        $MaximumPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        
        $subhead = "<h3>Total Users</h3>"
        $htmlbody += $subhead

        $UsersData = [ordered] @{
            'Users' = $($Users.Count);
            'Enabled users' = $(($Users | Where-Object Enabled -EQ $true).Count);
            'Disabled users' = $(($USers| Where-Object Enabled -EQ $false).Count);
            "Password never Expires" = $(($Users | Where-Object PasswordNeverExpires -eq $true).Count);
            "Password not required" = $((($Users | Where-Object PasswordNotRequired -EQ $true) | Measure-Object).Count);
            "Cannot Change Password" = $(($Users | Where-Object CannotChangePassword -EQ $true).Count);
            "Smartcard required" = $(($Users | Where-Object SmartcardLogonRequired -EQ $true).Count);
            "Unencrypted Password" = $(($Users | Where-Object AllowReversiblePasswordEncryption -EQ $true).Count);
            "Not logged on for 90 days" = $(($Users | Where-Object LastLogonDate -le $(Get-date).AddDays(-90)).Count);
            "Not set password for $MaximumPasswordAge days" = $(($Users | Where-Object PasswordLastSet -le $(Get-Date).AddDays(-$MaximumPasswordAge)).Count)
        }
        $UsersReport = New-Object PSObject -Property $UsersData

        $htmlbody += $UsersReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Priveledged Users</h3>"
        $htmlbody += $subhead

        $DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive
        $EnterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive
        $SchemaAdmins = Get-ADGroupMember -Identity "Schema Admins" -Recursive
        $Administrators = Get-ADGroupMember -Identity "Administrators" -Recursive
        try {
            $ProtectedUsers = Get-ADGroupMember -Identity "Protected Users" -Recursive
        }
        Catch {
            $ProtectedUsers = $null
        }
        if ($ProtectedUsers -eq $null) {
            $ProtectedUsersInfo = "No Group Found"        
        }
        else {
            $ProtectedUsersInfo = $ProtectedUsers.Count
        }

        $PrivUsersData = [ordered] @{
            "Administrators"  = $($Administrators.Count);
            "Domain Admins" = $($DomainAdmins.Count);
            "Enterprise Admins" = $($EnterpriseAdmins.Count);
            "Schema Admins" = $($SchemaAdmins.Count);
            "Protected Users" = $($ProtectedUsersInfo);
        }
        
        $PrivUsersReport = New-Object PSObject -Property $PrivUsersData
        
        $htmlbody += $PrivUsersReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Administrators</h3>"
        $htmlbody += $subhead
        
        $AdministratorsReport = foreach ($Administrator in $Administrators) {
            If ($Administrator.objectClass -eq "user") {
                $Object = Get-ADUser -Identity $Administrator.distinguishedName
            }
            elseif ($Administrator.objectClass -eq "group") {
                $Object = Get-ADGroup -Identity $Administrator.distinguishedName
            }
            elseif ($Administrator.objectClass -eq "computer") {
                $Object = Get-ADComputer -Identity $Administrator.distinguishedName
            }
            else {
                $Object = Get-ADObject -Identity $Administrator.distinguishedName
            }
            $AdministratorsData = [ordered] @{ 
                GivenName = $($Object.GivenName);
                SurName = $($Object.Surname);
                SAMAccountName = $($Object.SamAccountName);
                Enabled = $($Object.Enabled);
                Type = $($Object.ObjectClass)
            }
            New-Object PSobject -Property $AdministratorsData
        }

        $htmlbody += $AdministratorsReport | sort SamAccountName,SurName | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Domain Admins</h3>"
        $htmlbody += $subhead
        
        $DomainAdminsReport = Foreach ($DomainAdmin in $DomainAdmins) {
            If ($DomainAdmin.objectClass -eq "user") {
                $Object = Get-ADUser -Identity $DomainAdmin.distinguishedName
            }
            elseif ($DomainAdmin.objectClass -eq "group") {
                $Object = Get-ADGroup -Identity $DomainAdmin.distinguishedName
            }
            else {
                $Object = Get-ADObject -Identity $DomainAdmin.distinguishedName
            }
            $DomainAdminsData = [ordered] @{ 
                GivenName = $($Object.GivenName);
                SurName = $($Object.Surname);
                SAMAccountName = $($Object.SamAccountName);
                Enabled = $($Object.Enabled);
                Type = $($Object.ObjectClass)
            }
            New-Object PSobject -Property $DomainAdminsData
        }

        $htmlbody += $DomainAdminsReport | sort SamAccountName,SurName | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Enterprise Admins</h3>"
        $htmlbody += $subhead
        
        $EnterpriseAdminsReport = Foreach ($EnterpriseAdmin in $EnterpriseAdmins) {
            If ($EnterpriseAdmin.objectClass -eq "user") {
                $Object = Get-ADUser -Identity $EnterpriseAdmin.distinguishedName
            }
            elseif ($EnterpriseAdmin.objectClass -eq "group") {
                $Object = Get-ADGroup -Identity $EnterpriseAdmin.distinguishedName
            }
            else {
                $Object = Get-ADObject -Identity $EnterpriseAdmin.distinguishedName
            }
            $EnterpriseAdminsData = [ordered] @{ 
                GivenName = $($Object.GivenName);
                SurName = $($Object.Surname);
                SAMAccountName = $($Object.SamAccountName);
                Enabled = $($Object.Enabled);
                Type = $($Object.ObjectClass)
            }
            New-Object PSobject -Property $EnterpriseAdminsData
        }

        $htmlbody += $EnterpriseAdminsReport | sort SamAccountName,SurName | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Schema Admins</h3>"
        $htmlbody += $subhead
        
        $SchemaAdminsReport = Foreach ($SchemaAdmin in $SchemaAdmins) {
            If ($SchemaAdmin.objectClass -eq "user") {
                $Object = Get-ADUser -Identity $SchemaAdmin.distinguishedName
            }
            elseif ($SchemaAdmin.objectClass -eq "group") {
                $Object = Get-ADGroup -Identity $SchemaAdmin.distinguishedName
            }
            else {
                $Object = Get-ADObject -Identity $SchemaAdmin.distinguishedName
            }
            $SchemaAdminsData = [ordered] @{ 
                GivenName = $($Object.GivenName);
                SurName = $($Object.Surname);
                SAMAccountName = $($Object.SamAccountName);
                Enabled = $($Object.Enabled);
                Type = $($Object.ObjectClass)
            }
            New-Object PSobject -Property $SchemaAdminsData
        }

        $htmlbody += $SchemaAdminsReport | sort SamAccountName,SurName | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        if ($ProtectedUsers.Count -ne 0) {
            $subhead = "<h3>Protected Users</h3>"
            $htmlbody += $subhead
        
            $ProtectedUsersReport = Foreach ($ProtectedUser in $ProtectedUsers) {
                If ($ProtectedUser.objectClass -eq "user") {
                    $Object = Get-ADUser -Identity $ProtectedUser.distinguishedName
                }
                elseif ($ProtectedUser.objectClass -eq "group") {
                    $Object = Get-ADGroup -Identity $ProtectedUser.distinguishedName
                }
                else {
                    $Object = Get-ADObject -Identity $ProtectedUser.distinguishedName
                }
                $ProtectedUsersData = [ordered] @{ 
                    GivenName = $($Object.GivenName);
                    SurName = $($Object.Surname);
                    SAMAccountName = $($Object.SamAccountName);
                    Enabled = $($Object.Enabled);
                    Type = $($Object.ObjectClass)
                }
                New-Object PSobject -Property $ProtectedUsersData
            }

            $htmlbody += $ProtectedUsersReport | sort SamAccountName,SurName | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h2>Groups</h2>"
        $htmlbody += $subhead

        $subhead = "<h3>Total Groups</h3>"
        $htmlbody += $subhead

        $Groups = Get-ADGroup -Filter * -Properties Description
        $GroupsData = [ordered] @{
            "Total Groups" = $($Groups.Count)
            "Domain Local - Distribution" = $(($Groups | Where-Object GroupCategory -eq "Distribution" | Where-Object GroupScope -eq DomainLocal).Count);
            "Domain Local - Security" = $(($Groups | Where-Object GroupCategory -eq "Security" | Where-Object GroupScope -eq DomainLocal).Count);
            "Global - Distribution" = $(($Groups | Where-Object GroupCategory -eq "Distribution" | Where-Object GroupScope -eq Global).Count);
            "Global - Security" = $(($Groups | Where-Object GroupCategory -eq "Security" | Where-Object GroupScope -eq Global).Count);
            "Universal - Distribution" = $(($Groups | Where-Object GroupCategory -eq "Distribution" | Where-Object GroupScope -eq Universal).Count);
            "Universal - Security" = $(($Groups | Where-Object GroupCategory -eq "Security" | Where-Object GroupScope -eq Universal).Count);
        }
        $GroupsReport = New-Object PSObject -Property $GroupsData

        $htmlbody += $GroupsReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer
        
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h2>Organizational Units</h2>"
        $htmlbody += $subhead
        
        $subhead = "<h3>Total OUs</h3>"
        $htmlbody += $subhead

        $OUs = Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion,CanonicalName

        $OUsData = [ordered] @{
            "Total OUs" = $($OUs.Count);
            "Protected From Accidental Deletion" = $(($OUs | Where-Object ProtectedFromAccidentalDeletion -eq $true).Count)
        }

        $OUsReport = New-Object PSObject -Property $OUsData

        $htmlbody += $OUsReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        $subhead = "<h3>Unprotected OUs</h3>"
        $htmlbody += $subhead

        $UnProtectedOUs = $OUs | Where-Object ProtectedFromAccidentalDeletion -NE $true | Select-Object @{Name="OU Name";Expression={ $_.CanonicalName} } | Sort-Object "OU Name"
        
        $htmlbody += $UnProtectedOUs | ConvertTo-Html -Fragment -Property "OU Name"
        $htmlbody += $spacer


    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    Try {
        $subhead = "<h2>Group Policy</h2>"
        $htmlbody += $subhead

        $subhead = "<h3>Total GPOs</h3>"
        $htmlbody += $subhead

        $GPOs = Get-GPO -All | Select *
        $GPOData = [ordered] @{ 
            "Total GPOs" = $($GPOs.Count);
            "All Settings Enabled" = $(($GPOs | Where-Object GPOStatus -EQ "AllSettingsEnabled" | Measure-Object).Count);
            "Computer Settings Disabled" = $(($GPOs | Where-Object GPOStatus -EQ "ComputerSettingsDisabled" | Measure-Object).Count);
            "User Settings Disabled" = $(($GPOs | Where-Object GPOStatus -EQ "UserSettingsDisabled" | Measure-Object).Count);
            "All Settings Disabled" = $(($GPOs | Where-Object GPOStatus -EQ "AllSettingsDisabled" | Measure-Object).Count);
        }
        $GPOReport = New-Object PSObject -Property $GPOData

        $htmlbody += $GPOReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h3>Central Store</h3>"
        $htmlbody += $subhead

        If (Test-Path -Path "filesystem::\\$((Get-ADDomain).Forest)\Sysvol\$((Get-ADDomain).Forest)\Policies\PolicyDefinitions") {
            $CentralStore = $True
        }
        Else {
            $CentralStore = $false
        }
        $CentralStoreData = [ordered] @{
            CentralStore = $CentralStore
        }
        $CentralStoreReport = New-Object PSObject -Property $CentralStoreData
        
        $htmlbody += $CentralStoreReport | ConvertTo-Html -Fragment -Property CentralStore
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

        try {
        $ADFineGrainedPasswordPolicys = Get-ADFineGrainedPasswordPolicy -Filter *
        if ($($ADFineGrainedPasswordPolicys | Measure-Object).Count -ge 1) {
            $subhead = "<h3>Fine Grained Password Policy</h3>"
            $htmlbody += $subhead

            $ADFineGrainedPasswordPolicyReport = foreach ($ADFineGrainedPasswordPolicy in $ADFineGrainedPasswordPolicys) {
                [string]$AppliesToResult = foreach ($AppliesTo in $ADFineGrainedPasswordPolicy.AppliesTo) {
                    $ObjectClass = (Get-ADObject -Identity $AppliesTo).objectClass
                    If ($ObjectClass -eq "user") {
                        $Object = Get-ADUser -Identity $AppliesTo
                    }
                    elseif ($ObjectClass -eq "group") {
                        $Object = Get-ADGroup -Identity $AppliesTo
                    }
                    "$($ObjectClass)=$($Object.SamAccountName)"
                }
                if ($ADFineGrainedPasswordPolicy.LockoutDuration.Minutes -eq 0) {
                    $LockOutDuration = "Manual"
                }
                Else {
                    $LockOutDuration = $ADFineGrainedPasswordPolicy.LockoutDuration.Minutes
                }
                $ADFineGrainedPasswordPolicysData = [ordered] @{
                    Name = $($ADFineGrainedPasswordPolicy.Name);
                    "Precedence" = $($ADFineGrainedPasswordPolicy.Precedence);
                    "PasswordHistoryCount" = $($ADFineGrainedPasswordPolicy.PasswordHistoryCount);
                    "MinPasswordLength" = $($ADFineGrainedPasswordPolicy.MinPasswordLength);
                    "MinPasswordAge" = $($ADFineGrainedPasswordPolicy.MinPasswordAge.Days);
                    "MaxPasswordAge" = $($ADFineGrainedPasswordPolicy.MaxPasswordAge.Days);
                    "Lockout Duration" = $($LockOutDuration);
                    "Lockout Window" = $($ADFineGrainedPasswordPolicy.LockoutObservationWindow.Minutes);
                    "Lockout Threshold" = $($ADFineGrainedPasswordPolicy.LockoutThreshold);
                    "Complexity" = $($ADFineGrainedPasswordPolicy.ComplexityEnabled);
                    "Applies To" = $($AppliesToResult)
                }
                New-Object PSObject -Property $ADFineGrainedPasswordPolicysData
            }
            
            $htmlbody += $ADFineGrainedPasswordPolicyReport | Sort-Object Precedence, Name | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h3>GPO Details</h3>"
        $htmlbody += $subhead

        $htmlbody += $GPOs | 
            Select-Object DisplayName,ID,
                @{Name="Created";Expression={ $_.CreationTime }},
                @{Name="Modified";Expression={ $_.ModificationTime }},
                @{Name="Status";Expression={ $_.GpoStatus }} | 
                Sort-Object Displayname | 
                ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h3>Unused GPOs</h3>"
        $htmlbody += $subhead

        $Comment = "<p>Number of links show number of locations GPO is linked to but not active in<p>"
        $htmlbody += $Comment
        
        $GPOs = Get-GPO -All
        $GPOLinkResults = foreach ($GPO in $GPOs) {
            [xml]$GPOxml = Get-GPOReport -Name $GPO.DisplayName -ReportType Xml 
            $GPOUsed = 0
            foreach ($Link in $GPOxml.GPO.LinksTo) {
                if ($Link.Enabled -eq $true) {
                    $GPOUsed ++
                }
            }
            if ($GPOUsed -eq 0) {
                $GPOLinksData = [ordered] @{
                    DisplayName = $GPO.DisplayName
                    ID = $GPO.ID
                    NumberOfLinks = $(($GPOxml.GPO.linksTo | Measure-Object).Count);
                }
                New-Object PSObject -Property $GPOLinksData
            }
        }
        $htmlbody += $GPOLinkResults | Sort-Object DisplayName | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }


    #------------------------------------------------------------------------------
    # Generate the HTML report and output to file
    $reportime = Get-Date

    #Common HTML head and styles
    $htmlhead="<html>
			    <style>
			    BODY{font-family: Arial; font-size: 8pt;}
			    H1{font-size: 20px;}
			    H2{font-size: 18px;}
			    H3{font-size: 16px;}
                H4{font-size: 14px;}
			    TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
			    TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
			    TD{border: 1px solid black; background: #ADD8E6; padding: 5px; color: #000000;}
			    td.pass{background: #7FFF00;}
			    td.warn{background: #FFE600;}
			    td.fail{background: #FF0000; color: #ffffff;}
                td.info{background: #85D4FF;}
			    </style>
			    <body>
			    <h1 align=""center"">Report - Active Directory</h1>
			    <h3 align=""center"">Generated: $reportime</h3>"
    $htmltail = "</body>
		    </html>"

    $htmlreport = $htmlhead + $htmlbody + $htmltail

    $htmlfile = "$ReportPath" + "\Report_ActiveDirectory.html"
    $htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
}

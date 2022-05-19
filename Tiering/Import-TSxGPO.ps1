Param(
    $Path
)

if (!($Path)) {
    $Path = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
}
else {
    $Path = (Get-Item -Path $Path).FullName # This works with .\ type paths aswell
}

$NewShortDomainName = (Get-ADDomain).NetBIOSName
$NewFQDNDomainName = (Get-ADDomain).DnsRoot
$DomainSID=(Get-ADDomain).DomainSid.Value
$DCDomainGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-516""").Name
$AdministratorUser = (Get-ADUser -Filter "SID -eq ""$DomainSID-500""").Name
$DomainAdminGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-512""").Name
$DomainUsersGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-513""").Name
$GPOCreatorGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-520""").Name
$SchemaAdminsGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-518""").Name
$EnterpriseAdminGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-519""").Name
$KeyAdminGroup = (Get-ADGroup -Filter "SID -eq ""$DomainSID-526""").Name
$CryptoOpGroup = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-569""").Name
$PrintOpGroup = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-550""").Name
$BackupOpGroup = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-551""").Name
$ServerOpGroup = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-549""").Name
$AccountOpGroup = (Get-ADGroup -Filter "SID -eq ""S-1-5-32-548""").Name

# Extract GPOExport.zip if not extracted
$Path = $Path.Trim('\')
if (!(Test-Path $Path\GPOBackup -PathType Container)) {
    if (Test-Path $Path\GPOBackup.zip -PathType Leaf) {
        Expand-Archive $Path\GPOBackup.zip -DestinationPath $Path
    }
    else {
        Write-Error "Could not find $Path\GPOBackup folder or $Path\GPOBackup.zip. Specify path manually!" -Verbose
        Exit
    }
} 

# Update groups.xml GPO Preference for each GPO with new domain and group SID
$PrefGroupXMLs = Get-ChildItem -Path $Path -Recurse -Filter groups.xml
foreach ($PrefGroupXML in $PrefGroupXMLs){
    [XML]$XMLFile = Get-Content -Path $PrefGroupXML.FullName
    foreach($Member in $XMLFile.Groups.Group.Properties.Members.Member){
        $Object = $Member.name.Replace("AD\","$NewShortDomainName\")
        $Member.name = $Object

        $GroupName = $Object.Replace("$NewShortDomainName\","")

        if ($GroupName -like '*Domain Admins') {
           $GroupName = $GroupName.Replace("Domain Admins","$DCDomainGroup")
        }
        if ($GroupName -like '*Domain Users') {
           $GroupName = $GroupName.Replace("Domain Users","$DomainUsersGroup")
        }

        $NewSid = (Get-ADObject -Filter 'Name -EQ $GroupName' -Properties objectSid).objectSid.value
        if ($NewSid) {
            $Member.sid = $NewSid
        }
        else {
            Write-Warning "Could not find group: $GroupName" -Verbose
        }
    }
    $XMLFile.Save($PrefGroupXML.FullName)
}

# Update migration table with new NETBIOS and domain name
$MigTable = Get-Content -Path $Path\GPOBackup\MigTable.migtable
$MigTable = $MigTable -replace "customer.domain.fqdn", "$NewFQDNDomainName"
$MigTable = $MigTable -replace "DOMAIN_NETBIOS", "$NewShortDomainName"
$MigTable = $MigTable -replace "<Destination>Domain Controllers", "<Destination>$DCDomainGroup"
$MigTable = $MigTable -replace "<Destination>Domain Admins", "<Destination>$DomainAdminGroup"
$MigTable = $MigTable -replace "<Destination>Domain Users", "<Destination>$DomainUsersGroup"
$MigTable = $MigTable -replace "<Destination>Print Operators", "<Destination>$PrintOpGroup"
$MigTable = $MigTable -replace "<Destination>Enterprise Admins", "<Destination>$EnterpriseAdminGroup"
$MigTable = $MigTable -replace "<Destination>Group Policy Creator Owners", "<Destination>$GPOCreatorGroup"
$MigTable = $MigTable -replace "<Destination>Schema Admins", "<Destination>$SchemaAdminsGroup"
$MigTable = $MigTable -replace "<Destination>Backup Operators", "<Destination>$BackupOpGroup"
$MigTable = $MigTable -replace "<Destination>Server Operators", "<Destination>$ServerOpGroup"
$MigTable = $MigTable -replace "<Destination>Account Operators", "<Destination>$AccountOpGroup"
$MigTable = $MigTable -replace "<Destination>Key Admins", "<Destination>$KeyAdminGroup"
$MigTable = $MigTable -replace "<Destination>Cryptograpic Operators", "<Destination>$CryptoOpGroup"
$MigTable = $MigTable -replace "<Destination>Administrator", "<Destination>$AdministratorUser"

# Remove Tier 2 groups from migration table if it does not exist
$DomainDistinguishedName = (Get-ADDomain).DistinguishedName
$EAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$Tier2OU = Get-ADOrganizationalUnit -Identity "OU=Tier2,OU=Admin,$DomainDistinguishedName"
$ErrorActionPreference = $EAP
if (!($Tier2OU)) {
    $rows = $MigTable -match "^    <Destination>Domain Tier2"
    foreach ($row in $rows) {
        $MigTable = $MigTable -replace "$row", "    <DestinationNone />"
    }
}

# Write new migration table
$MigTable | Set-Content -Path $Path\GPOBackup\UpdatedMigTable.migtable -Encoding UTF8

# Import GPOs with new migration table
$GPOs = Get-GPO -All
$GPOBackups = Get-ChildItem -Path $Path\GPOBackup -Directory
foreach ($GPO in $GPOs){
    $GPOBackup = $GPOBackups | Where-Object Name -eq $GPO.DisplayName
    if ($GPOBackup) {
        Import-GPO -Path $GPOBackup.fullname -BackupGpoName $GPOBackup.Name -MigrationTable $Path\GPOBackup\UpdatedMigTable.migtable -Verbose -TargetName $GPOBackup.Name -ErrorAction SilentlyContinue
    }
}

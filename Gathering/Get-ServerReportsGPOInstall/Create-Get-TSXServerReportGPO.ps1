<#
.VERSION 1.1
1.0 - Initial release

.DESCRIPTION
>> Description of the script. Add as much info as possible. 

>> Good to make notes to read the disclamer etc: 
Ensure that the disclaimer is read and understood before execution!

.PARAMETER GPOName
The name for the GPO to create, use Incident name as prefix (WhiteLightning-IncidentJob)

.PARAMETER ExecPath
Path to the folder where the script is located (\\domain.tld\netlogon\incidentjob)

.PARAMETER LogPath
Path to where to copy the result when the job is executed

.PARAMETER LinkGPO
If defined, the GPO will be linked in the root of the domain

.EXAMPLE
Create-IncidentCollectionGPO-ps1 -GPOName "WhiteLightning-IncidentJob" -ExecPath "\\domain.tld\netlogon\incidentjob" -LogPath "\\fqdn\incidentlogs\IncidentJob"

.NOTES
Author: Truesec Cyber Security Incident Response Team
Website: https://truesec.com/
>> Created: 2021-11-15

Compatibility: The script has been tested and verified on PowerShell version 3 and 5 (change if needed)

.DISCLAIMER (change to match script function)
Any of use of this script should be performed by qualified professionals with the necessary knowledge and skills to make independent conclusions.
The script does not guarantee or in any way ensure, promise or indicate that after successful execution, a system can be declared as safe.
The script should be used as a tool to help identify indicators of ..... precense on the system it is executed on.

#>

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory, GroupPolicy

[CmdletBinding()]
Param(
    [string]$GPOName = 'Run TSXServerReport',    
    [string]$ScriptPath,
    [string]$LogPath,
    [switch]$LinkGPO
)

$ADDomain = Get-ADDomain

# Create GPO and Import settings
$GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if (!($GPO)) {
    $GPO = New-GPO -Name $GPOName
    Write-Verbose "Created GPO $($GPO.DisplayName)"
}
$WorkPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$XMLPath = Get-ChildItem -Path $WorkPath\ExtractedGPO -Recurse -Filter ScheduledTasks.xml
$XML = Get-Content $XMLPath.FullName
$XML = $XML.Replace("\\DOMAIN\netlogon\Apps\TSXServerReport\TSxServerGather.ps1", "$ScriptPath")
$XML = $XML.Replace("\\SERVER\ReportData", "$LogPath")
$XML | Set-Content $XMLPath.FullName
Write-Verbose "Updated $($XMLPath.FullName)"
Write-Verbose "ScriptPath is now: $ScriptPath"
Write-Verbose "LogPath is now: $LogPath"

Try {
    Import-GPO -Path "$WorkPath\ExtractedGPO" -BackupGpoName "Computer - InventoryData" -TargetName $GPO.DisplayName -ErrorAction Stop
    Write-Verbose "Imported settings from GPOBackup to $($GPO.DisplayName)"
}
Catch {
    Write-Error "Unable to import GPO"
    Throw
}


# If LinkGPO is set then link GPO to Domain Root
if ($LinkGPO) {
    New-GPLink -ID $GPO.Id -Target $ADDomain.DistinguishedName -LinkEnabled Yes
    Write-Verbose "Created GPLink in $($ADDomain.DistinguishedName) for GPO $($GPO.DisplayName)"
}
else {
    Write-Warning "Link GPO ""$($GPO.DisplayName)"" manually!"
}

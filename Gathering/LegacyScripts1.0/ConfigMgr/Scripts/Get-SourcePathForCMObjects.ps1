<#
Created:    2018-06-21
Updated:    2018-06-21
Version:    1.0
Author :    Peter Lofgren, Johan Arwidmark
Twitter:    @LofgrenPeter
Blog   :    http://syscenramblings.wordpress.com

Disclaimer:
This script is provided "AS IS" with no warranties, confers no rights and
is not supported by the author

Updates
1.0 - Initial release

License:

The MIT License (MIT)

Copyright (c) 2018 Peter Lofgren

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
#>

[CMDLETBINDING()]
param (
    [Parameter(Mandatory=$True)]
    $Path,
    
    [Parameter(Mandatory=$true)]
    $SiteCode,

    [Parameter(Mandatory=$false)]
    $SiteServer = $env:COMPUTERNAME
)

$CMModule = $env:SMS_ADMIN_UI_PATH.Substring(0,$env:SMS_ADMIN_UI_PATH.Length-5) + "\ConfigurationManager.psd1"
Import-Module $CMModule -ErrorAction Stop
$Drive = (Get-PSDrive -PSProvider CMSite).Name
Set-Location $($Drive + ":")

function GetInfoPackages() {
    Get-CMPackage | Select-object Name, PkgSourcePath, PackageID
}

function GetInfoDriverPackage() {
    Get-CMDriverPackage | Select-object Name, PkgSourcePath, PackageID
}
 
function GetInfoBootimage() {
    Get-CMBootImage | Select-object Name, PkgSourcePath, PackageID
}
 
function GetInfoOSImage() {
    Get-CMOperatingSystemImage | Select-object Name, PkgSourcePath, PackageID
}
 
function GetInfoDriver() {
    Get-CMDriver | Select-object LocalizedDisplayName, ContentSourcePath, PackageID
}
 
function GetInfoSWUpdatePackage() {
    Get-CMSoftwareUpdateDeploymentPackage | Select-object Name, PkgSourcePath, PackageID
}
 
function GetInfoApplications() {
    $Applications = Get-WmiObject -ComputerName $SiteServer -Namespace root\SMS\site_$SiteCode -class SMS_Application | Where-Object {$_.IsLatest -eq $True}
    $Result = ForEach ($Application in $Applications) {
        $CheckApplication = [wmi]$Application.__PATH
        $CheckApplicationXML = [Microsoft.ConfigurationManagement.ApplicationManagement.Serialization.SccmSerializer]::DeserializeFromString($CheckApplication.SDMPackageXML,$True)
        foreach ($CheckDeploymentType in $CheckApplicationXML.DeploymentTypes) {
            $object = New-Object -TypeName PSObject
            $CheckInstaller = $CheckDeploymentType.Installer
            $CheckContents = $CheckInstaller.Contents[0]
            $object | Add-Member -MemberType NoteProperty  -Name Application -Value $Application.LocalizedDisplayName
            $object | Add-Member -MemberType NoteProperty  -Name SourceDir -Value $CheckContents.Location
            $object
        }
    }
    $Result
}

# Set maxiumum result to 5000
Set-CMQueryResultMaximum -Maximum 5000
 
# Get the Data
Write-OutPut "Applications" -ForegroundColor Yellow
GetInfoApplications | Export-Csv $Path\Objects-Applications.csv -NoTypeInformation
 
Write-OutPut "Driver Packages" -ForegroundColor Yellow
GetInfoDriverPackage | Export-Csv $Path\Objects-DriverPackages.csv -NoTypeInformation
 
Write-OutPut "Drivers" -ForegroundColor Yellow
GetInfoDriver | Export-Csv $Path\Objects-Drivers.csv -NoTypeInformation

Write-OutPut "Boot Images" -ForegroundColor Yellow
GetInfoBootimage | Export-Csv $Path\Objects-OSImages.csv -NoTypeInformation

Write-OutPut "OS Images" -ForegroundColor Yellow
GetInfoOSImage  | Export-Csv $Path\Objects-OSImages.csv -NoTypeInformation
 
Write-OutPut "Software Update Package Groups" -ForegroundColor Yellow
GetInfoSWUpdatePackage | Export-Csv $Path\Objects-SoftwareUpdatePackages.csv -NoTypeInformation
 
Write-OutPut "Packages" -ForegroundColor Yellow
GetInfoPackages | Export-Csv $Path\Objects-Packages.csv -NoTypeInformation

Write-OutPut ""
Write-OutPut "Check the CSV files in $Path"
Write-OutPut ""
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
#>

Param(
    [Parameter(Mandatory=$false)]
    $ReportPath = "C:\Setup\HealthChecks\Reports"
)

# Set the basic's
$htmlreport = @()
$htmlbody = @()
$spacer = "<br />"

#Get MPs and SiteCode
$strFilter = "(&(objectClass=mSSMSManagementPoint))"
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.Filter = $strFilter
$objSearcher.SearchScope = "Subtree"
$mSMSManagementPoints = $objSearcher.FindAll()

if ($mSMSManagementPoints.Count -eq 0) {
    Write-Output "No ConfigMgr Servers Found, exiting"
    Break
}

$subhead = "<h3>Management Points</h3>"
$htmlbody += $subhead

$MPs = foreach ($mSMSManagementPoint in $mSMSManagementPoints) { 
    $Sitecode = $mSMSManagementPoint.Path.Substring(10).Split(",")[0].SubString(7).SubString(0,3)
    $ServerName = $mSMSManagementPoint.Path.Substring(10).Split(",")[0].SubString(11)
    $Hash =  [ordered]@{ 
        SiteCode = $($Sitecode); 
        ServerName = $($ServerName)
        }
    New-Object PSObject -Property $Hash
}

try {
        $htmlbody += $MPs | ConvertTo-Html -Fragment
        $htmlbody += $spacer
}
Catch {
    Write-Warning $_.Exception.Message
    $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $htmlbody += $spacer
}

$subhead = "<h3>Site Servers</h3>"
$htmlbody += $subhead

#Get Primary Site
[array]$SiteServers = Foreach ($MP in $MPs) { 
    Clear-Variable MPConnection, PrimaryConnection, PrimaryStatus, DBName, DBServer, PrimarySiteServer -ErrorAction SilentlyContinue
    if (Test-Connection -ComputerName $MP.ServerName) {
        $MPConnection = "Success"
        try {
            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $MP.ServerName)
            $RegKey= $Reg.OpenSubKey("SOFTWARE\\Microsoft\\SMS\\Identification")
            $PrimarySiteServer = $RegKey.GetValue("Site Server")
            $PrimaryStatus = "Success"
        }
        catch {
            $PrimaryStatus = "Failed"
        }
        if ($PrimaryStatus -eq "Success") {
            try {
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $PrimarySiteServer)
                $RegKey= $Reg.OpenSubKey("SOFTWARE\\Microsoft\\SMS\\SQL Server")
                $DBServer = $RegKey.GetValue("Server")
                $DBName = $RegKey.GetValue("Database Name")
                $PrimaryConnection = "Success"
            }
            Catch {
                $PrimaryConnection = "Failed"
            }
        }
    }
    Else {
        $MPConnection = "Failed"
    }
    $Hash2 =  [ordered]@{ 
        "SiteCode" = $Mp.SiteCode
        "ManagementPoint" = $MP.ServerName
        "ConnectionStatus" = $MPConnection
        "PrimarySiteServer" = $PrimarySiteServer
        "DatabaseServer" = $DBServer
        "DatabaseName" = $DBName
    }
    New-Object PSObject -Property $Hash2
}

try {
    $htmlbody += $SiteServers | ConvertTo-Html -Fragment
    $htmlbody += $spacer
}
Catch {
    Write-Warning $_.Exception.Message
    $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $htmlbody += $spacer
}


#Get Server roles
$subhead = "<h3>Site Server Roles</h3>"
$htmlbody += $subhead

$SiteServersMod = $SiteServers | select PrimarySiteServer, SiteCode -Unique | Where-Object PrimarySiteServer -NE $null
$ServerRoles = Foreach ($SiteServer in $SiteServersMod) {
    Get-WmiObject -ComputerName $SiteServer.PrimarySiteServer -Namespace "root\SMS\site_$($SiteServer.SiteCode)" -Class SMS_SystemResourceList -ErrorAction SilentlyContinue | Select SiteCode, Servername, RoleName
}

try {
    $htmlbody += $ServerRoles | ConvertTo-Html -Fragment
    $htmlbody += $spacer
}
Catch {
    Write-Warning $_.Exception.Message
    $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $htmlbody += $spacer
}


$SiteServers = $ServerRoles | Select-Object ServerName -Unique

$ServerRoles = Foreach ($SiteServer in $SiteServers) {
    $subhead = "<h3>Computer System Information - $($SiteServer.Servername)</h3>"
    $htmlbody += $subhead

    try {
        $csinfo = Get-WmiObject Win32_ComputerSystem -ComputerName $SiteServer.Servername -ErrorAction STOP |
            Select-Object Manufacturer,Model,
                @{Name='Physical Processors';Expression={$_.NumberOfProcessors}},
                @{Name='Logical Processors';Expression={$_.NumberOfLogicalProcessors}},
                @{Name='Total Physical Memory (Gb)';Expression={
                    $tpm = $_.TotalPhysicalMemory/1GB;
                    "{0:F0}" -f $tpm
                }},
                DnsHostName,Domain

        $RelMetrics = Get-WmiObject -Class Win32_ReliabilityStabilityMetrics -ComputerName $SiteServer.Servername -ErrorAction Stop | 
        Select-Object @{N="TimeGenerated"; E={$_.ConvertToDatetime($_.TimeGenerated)}},SystemStabilityIndex | Select-Object -First 1

        $ServerDetailReport = [Ordered]@{
            Manufacturer = $csinfo.Manufacturer
            Model = $csinfo.Model
            "Physical Processors" = $csinfo.'Physical Processors' 
            "Logical Processors" = $csinfo.'Logical Processors'
            "Total Physical Memory (Gb)" = $csinfo.'Total Physical Memory (Gb)'
            SystemStabilityIndex = $RelMetrics.SystemStabilityIndex
        }
        $ServerObject = New-Object PSObject -Property $ServerDetailReport
        $htmlbody += $ServerObject | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    Write-Verbose "Collecting operating system information"

    $subhead = "<h3>Operating System Information - $($SiteServer.Servername)</h3>"
    $htmlbody += $subhead
    
    try {
        $osinfo = Get-WmiObject Win32_OperatingSystem -ComputerName $SiteServer.Servername -ErrorAction STOP | 
            Select-Object @{Name='Operating System';Expression={$_.Caption}},
                    @{Name='Architecture';Expression={$_.OSArchitecture}},
                    Version,Organization,
                    @{Name='Install Date';Expression={
                        $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0,8),"yyyyMMdd",$null);
                        $installdate.ToShortDateString()
                    }},
                    WindowsDirectory

            $htmlbody += $osinfo | ConvertTo-Html -Fragment
            $htmlbody += $spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    
    Write-Verbose "Collecting logical disk information"

    $subhead = "<h3>Logical Disk Information - $($SiteServer.Servername)</h3>"
    $htmlbody += $subhead
    
    try {
        $diskinfo = Get-WmiObject Win32_LogicalDisk -ComputerName $SiteServer.Servername -ErrorAction STOP | 
            Select-Object DeviceID, FileSystem, VolumeName,
            @{Expression={$_.Size /1Gb -as [int]};Label="Total Size (GB)"},
            @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"} | Sort SystemName, DeviceID

        $htmlbody += $diskinfo | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }
}

# Generate the HTML report and output to file
$reportime = Get-Date

#Common HTML head and styles
$htmlhead="<html>
			<style>
			BODY{font-family: Arial; font-size: 8pt;}
			H1{font-size: 20px;}
			H2{font-size: 18px;}
			H3{font-size: 16px;}
			TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
			TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
			TD{border: 1px solid black; background: lightgreen; padding: 5px; color: #000000;}
			td.pass{background: #7FFF00;}
			td.warn{background: #FFE600;}
			td.fail{background: #FF0000; color: #ffffff;}
			td.info{background: #85D4FF;}
			</style>
			<body>
			<h1 align=""center"">Overview - ConfigMgr Servers</h1>
			<h3 align=""center"">Generated: $reportime</h3>"

$htmltail = "</body>
		</html>"

$htmlreport = $htmlhead + $htmlbody + $htmltail

$htmlfile = "$ReportPath" + "\Overview_ConfigMgrServers.html"
$htmlreport | Out-File $htmlfile -Encoding Utf8 -Force

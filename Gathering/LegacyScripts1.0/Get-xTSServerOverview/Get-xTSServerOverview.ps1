<#
License:

The MIT License (MIT)

Copyright (c) 2017 Mikael Nystrom

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
    $ReportPath = "C:\Setup\HealthChecks\Reports"
)

Function Get-VIAComputerSystemInfo
{
    param(
        $ComputerName
    )
    try
    {
    
    $Index = Get-WmiObject -Class Win32_ReliabilityStabilityMetrics -ComputerName $ComputerName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | 
        Select-Object @{N="TimeGenerated"; E={$_.ConvertToDatetime($_.TimeGenerated)}},SystemStabilityIndex | Select-Object -First 1
    
    $ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    $BIOS = Get-WmiObject -Class Win32_BIOS -ComputerName $ComputerName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    
    $OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | 
        Select-Object @{N="LastBootUpTime"; E={$_.ConvertToDatetime($_.LastBootUpTime)}},Version,Caption
    
    $LogicalDisk = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName -ErrorAction STOP | 
        Select-Object DeviceID,FileSystem,VolumeName,
        @{Expression={$_.Size /1Gb -as [int]};Label="TotalSize"},
        @{Expression={$_.Freespace / 1Gb -as [int]};Label="FreeSpace"} | Where-Object DeviceID -EQ C:
    
    $Plupp = [ordered]@{ 
            ComputerName = $($ComputerName)
            Index =  $([math]::Round($Index.SystemStabilityIndex))
            TimeGenerated = $($Index.TimeGenerated)
            Make = $($ComputerSystem.Manufacturer)
            Model = $($ComputerSystem.Model)
            OSVersion = $($OperatingSystem.Version)
            OSName = $($OperatingSystem.Caption)
            SerialNumber = $($BIOS.SerialNumber)
            UpTimeInDays = $([math]::round(((Get-Date) - ($OperatingSystem.LastBootUpTime)).TotalDays))
            OSDiskFreeSpaceInGB = $([Math]::Round($LogicalDisk.FreeSpace))
            }
    RETURN New-Object PSObject -Property $Plupp
    }
    catch{
    }
}

$ADComputers = Get-ADComputer -Filter * -Property * | Where-Object OperatingSystem -Like *Server*

$WarningPreference = "SilentlyContinue"
$StopPreference = "SilentlyContinue"

# Set the basic's
$htmlreport = @()
$htmlbody = @()
$spacer = "<br />"

# Get Software installed on all servers

$subhead = "<h3>Installed software</h3>"
$htmlbody += $subhead

$VIAComputerSystemInfo = foreach($Computer in $ADComputers.dnshostname){
    try
    {
        Get-VIAComputerSystemInfo -ComputerName $Computer
    }
    catch
    {
    }
}
$Result = $VIAComputerSystemInfo| Select-Object ComputerName,Make,Model,OSVersion,OSName,OSDiskFreeSpaceInGB,UpTimeInDays,Index | Sort-Object ComputerName

$htmlbody += $Result | ConvertTo-Html -Fragment
$htmlbody += $spacer

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
			<h1 align=""center"">Installed Software</h1>
			<h3 align=""center"">Generated: $reportime</h3>"

$htmltail = "</body>
		</html>"

$htmlreport = $htmlhead + $htmlbody + $htmltail

$htmlfile = "$ReportPath" + "\" + "ServerHardwareOveriew.html"
$htmlreport | Out-File $htmlfile -Encoding Utf8 -Force

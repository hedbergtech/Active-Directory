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

Function Get-VIASoftWare {
    param(
        $ComputerName = $env:COMPUTERNAME
    )
    $scriptBlock = {
        try{
            $InstalledSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
            $InstalledSoftware += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
        } catch {
            Write-warning "Error while trying to retreive installed software from inventory: $($_.Exception.Message)"
        }

        $InstalledMSIs = @()
        foreach ($App in $InstalledSoftware){
            if($App.PSChildname -match "\A\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}\z"){
                $InstalledMSIs += New-Object PSObject -Property @{
                    DisplayName = $App.DisplayName;
                    DisplayVersion = $App.DisplayVersion;
                    Publisher = $App.Publisher;
                    InstallDate = $App.InstallDate;
                    GUID = $App.PSChildName;    
                }
            }
        }
    $InstalledMSIs
    }
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
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

$VIASoftWare = foreach($Computer in $ADComputers.dnshostname){
    try
    {
        Get-VIASoftWare -ComputerName $Computer
    }
    catch
    {
    }
}

$Result = $VIASoftWare | Select-Object DisplayName,DisplayVersion,Publisher -Unique | Sort-Object DisplayName

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
			TD{border: 1px solid black; background: #ADD8E6; padding: 5px; color: #000000;}
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

$htmlfile = "$ReportPath" + "\" + "ServerSoftwareOveriew.html"
$htmlreport | Out-File $htmlfile -Encoding Utf8 -Force

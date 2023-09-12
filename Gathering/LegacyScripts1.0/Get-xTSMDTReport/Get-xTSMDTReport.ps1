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
    $ReportPath = "C:\Setup\HealthChecks\Reports",

    [Parameter(Mandatory=$true)]
    $MDTserver
)

# Set the basic's
$htmlreport = @()
$htmlbody = @()
$spacer = "<br />"

if ((Test-NetConnection -ComputerName $MDTserver).PingSucceeded -eq $true) {
    $subhead = "<h3>MDT General Info</h3>"
    $htmlbody += $subhead
    try {
        $MDTProduct = Get-WmiObject -ComputerName $MDTserver -Class Win32_Product -ErrorAction Stop | Where-Object -Property Name -like -Value "Microsoft Deployment Toolkit*"
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
        break
    }

    if (($MDTProduct.Name).count -ge 1) {
        $MDTName = $MDTProduct.Name
        $MDTVersion = $MDTProduct.Version

        $Result = Invoke-Command -ComputerName $MDTserver -ScriptBlock {
            $Drives = Get-WmiObject Win32_Volume | Where-Object { $_.DriveType -eq "3" -and ($_.Name).Length -le 4 }
            Foreach ($Drive in $Drives) {
                Clear-Variable MDTShare -ErrorAction SilentlyContinue
                $XMLPath = Get-ChildItem -Path $Drive.Name -Recurse -ErrorAction SilentlyContinue | Where-Object -Property Name -eq "Settings.xml"
                Foreach ($Path in $XMLPath) {
                    $MDTShare = Split-Path (Get-ChildItem -Path $Path.FullName) -Parent | Where-Object { $_ -like "*Control" }
                    if ($MDTShare.count -ge 1) {
                        [XML]$XMLContent = Get-Content -Path "$MDTShare\Settings.xml"
                        if (($XMLContent.Settings.UNCPath).Count -ge 1 -and $XMLContent.Settings.UNCPath -ne "") {
                            $UNCPath = $XMLContent.Settings.UNCPath
                            $PhysicalPath = $XMLContent.Settings.PhysicalPath
                            $Hash =  [ordered]@{ 
                                XMLPath = $Path.FullName;
                                PhysicalPath = $($PhysicalPath); 
                                UNCPath = $($UNCPath);
                            }
                        New-Object PSObject -Property $Hash
                        }
                    }
                }
            }
        }
        try {
            $ServerData = [ordered] @{
                ServerName = $MDTserver
                MDTName = $MDTName
                MDTVersion = $MDTVersion
            }
            $ServerDataResult = New-Object PSObject -Property $ServerData

            $htmlbody += $ServerDataResult | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
        Catch {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }
        
    
        $subhead = "<h3>MDT Details</h3>"
        $htmlbody += $subhead
        try {
            $ReportData = $Result | select XmlPath, PhysicalPath, UNCPath
                       
            $htmlbody += $ReportData | ConvertTo-Html -Fragment
            $htmlbody += $spacer
        }
       Catch {
            Write-Warning $_.Exception.Message
            $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
            $htmlbody += $spacer
        }
    }
    Else {
        $htmlbody += "<p>$MDTserver`: MDT Not found</p>"
        $htmlbody += $spacer
        Break
    }

    try {
        $Roles = Get-WindowsFeature -ComputerName $MDTserver | Where-Object -Property Name -Like "UpdateServices*" | where InstallState -EQ "Installed"
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }
    if ($Roles.count -gt 1) {
        foreach ($Role in $Roles) {
            switch ($role.Name) {
                "UpdateServices-WidDB" { $DBType = "Windows Internal" }
                "UpdateServices-DB" { $DBType = "SQL Server" }
            }
        }
    
        $WSUSConfig = Invoke-Command -ComputerName $MDTserver -ScriptBlock {
            $Temp = [reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
            $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer() 
            $ContentPath = $wsus.GetConfiguration().LocalContentCachePath
            $SyncFromMU = $wsus.GetConfiguration().SyncFromMicrosoftUpdate
            $StoreUpdatesLocaly = $wsus.GetConfiguration().DownloadUpdateBinariesAsNeeded
            $WSUSPort = $wsus.GetConfiguration().UpstreamWsusServerPortNumber
            $WSUSSSL = $wsus.GetConfiguration().UpstreamWsusServerUseSsl
            $Hash2 =  [ordered]@{ 
                StoreUpdatesLocally = $StoreUpdatesLocaly
                ContentPath = $ContentPath 
                SyncFromMU = $SyncFromMU
                WsusPort = $WSUSPort
                UseSSL = $WSUSSSL
            }
            New-Object PSObject -Property $Hash2

        }
        $WSUSReportData = [ordered] @{
            WSUSInstalled = $($true);
            WSUSDBType = $($DBType);
            StoreUpdatesLocally = $($WSUSConfig.StoreUpdatesLocally);
            ContentPath = $($WSUSConfig.ContentPath);
            SyncFromMU = $($WSUSConfig.SyncFromMU);
            WSUSPort = $($WSUSConfig.WsusPort);
            UseSSL = $($WSUSConfig.UseSSL)
        }
        $WSUSReport = New-Object PSobject -Property $WSUSReportData

        $subhead = "<h3>WSUS Details</h3>"
        $htmlbody += $subhead

        $htmlbody += $WSUSReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    else {
        $htmlbody += "<p>WSUS Not Installed</p>"
        $htmlbody += $spacer
    }
}
Else {
    $htmlbody += "<p>$MDTserver not available</p>"
    $htmlbody += $spacer
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
			<h1 align=""center"">MDT - $MDTserver</h1>
			<h3 align=""center"">Generated: $reportime</h3>"

$htmltail = "</body>
		</html>"

$htmlreport = $htmlhead + $htmlbody + $htmltail

$htmlfile = "$ReportPath" + "\Report_MDT_$MDTServer.html"
$htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
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
begin {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        if (-not (Test-Path $ReportPath -PathType Container)) {
            throw "No Report Path"
        }
    }
    Catch {
        Write-Warning $_.Exception.Message
        Break
    }
}
process {
    # Set the basic's
    $htmlreport = @()
    $htmlbody = @()
    $spacer = "<br />"
    
    $subhead = "<h3>SQL Overview</h3>"
    $htmlbody += $subhead
    try {
        $Servers = Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object OperatingSystem -like "*server*" | Sort Name
        $SQLDetails = foreach ($Server in $Servers) {
            try {
                $NotUsed = Get-WmiObject -ComputerName $server.Name -class Win32_ComputerSystem -ErrorAction Stop
                try {
                    Clear-Variable NameSpace,SQLWMI -ErrorAction SilentlyContinue
                    $NameSpace = Get-WmiObject -ComputerName $Server.Name -Namespace root\microsoft\sqlserver -Class __Namespace -ErrorAction Stop | Where-Object Name -like "ComputerManagement*"
                    $SQLWMI = Get-WmiObject -ComputerName $Server.Name -Namespace root\microsoft\sqlserver\$($NameSpace.Name) -Class sqlServiceAdvancedProperty -ErrorAction Stop
            
                    $SQLWmiResult = foreach ($Object in $SQLWMI) {
                        $SQLWMIData = [ordered] @{ 
                            ServerName = $($Server.Name);
                            Name = $($Object.PropertyName);
                            Value = $($Object.PropertyStrValue);
                            ServiceName = $($Object.ServiceName);
                            ServiceState = $((Get-Service -ComputerName $Server.Name -Name $Object.ServiceName).Status);
                        }
                        New-Object PSObject -Property $SQLWMIData
                    }
                    $SQLWmiResult = $SQLWmiResult | Where-Object Value -notlike ""
                    $SQLServices = $SQLWmiResult.ServiceName | select -Unique
                    $SQLServicesResult = foreach ($SqlService in $SQLServices) {
                        Clear-Variable SQLVerion -ErrorAction SilentlyContinue
                        Switch -Wildcard ($(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq Version).Value)) {
                            "9.*" { $SQLVersion = "SQL 2005" }
                            "10.*" { $SQLVersion = "SQL 2008" }
                            "10.5*" { $SQLVersion = "SQL 2008 R2" }
                            "11.*" { $SQLVersion = "SQL 2012" }
                            "12.*" { $SQLVersion = "SQL 2014" }
                            "13.*" { $SQLVersion = "SQL 2016" }
                            "14.*" { $SQLVersion = "SQL 2017" }
                            Default { $SQLVersion = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq Version).Value) }
                        }
                    
                        $SQLData = [ordered] @{
                            ServerName = $($SQLWmiResult.ServerName | Select-Object -First 1);
                            Version = $($SQLVersion);
                            SkuName = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq SkuName).Value);
                            FileVersion = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq FileVersion).Value);
                            InstanceID = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq InstanceID).Value);
                            InstallPath = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq InstallPath).Value);
                            DataPath = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq DataPath).Value);
                            ServiceName = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService).ServiceName | Select-Object -First 1);
                            ServiceState = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService).ServiceState | Select-Object -First 1);
                            RegRoot = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq RegRoot).Value);
                            StartUpParameters = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq StartUpParameters).Value);
                            DumpDir = $(($SQLWmiResult | Where-Object ServiceName -EQ $SQLService | Where-Object Name -eq DumpDir).Value);
                        }
                        New-Object PSObject -Property $SQLData
                    }
                    $SQLServicesResult
  
                    $SQLDetailsVersions = $SQLDetails | Where-Object Version -notlike ""  | Select-Object Version,SkuName -Unique
                    $SQLOverview = foreach ($SQLDetailsVersion in $SQLDetailsVersions) { 
                        $SQLDetailsVersionData = [ordered] @{
                            Version = $($SQLDetailsVersion.Version);
                            Sku = $($SQLDetailsVersion.SkuName);
                            Count = $((($SQLDetails | Where-Object { $_.Version -eq $SQLDetailsVersion.Version -and $_.SkuName -eq $SQLDetailsVersion.SkuName }).ServerName | Select-Object -Unique | Measure-Object).Count)
                        }
                        New-Object PSObject -Property $SQLDetailsVersionData
                    }
                }
                Catch {
                    Write-Verbose "No SQL found on: $($Server.Name)"
                }
            }
            Catch {
                Write-Warning "Unable to connect to host: $($Server.Name)"
            }
        }
        $SQLDetailsVersionData2 = [ordered] @{
            Version = $("All Versions");
            Sku = $("All SKus");
            Count = $((($SQLDetails).ServerName | Select-Object -Unique | Measure-Object).Count)
        }
        $SQLOverview2 = New-Object PSObject -Property $SQLDetailsVersionData2
        $SQLOverview = $SQLOverview + $SQLOverview2

        $htmlbody += $SQLOverview | Sort-Object Version,Sku | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h3>SQL Servers</h3>"
        $htmlbody += $subhead

        $SQLServers = $SQLDetails | Select-Object Servername -Unique

        $htmlbody += $SQLServers | ConvertTo-Html -Fragment -Property ServerName
        $htmlbody += $spacer

    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {

        $subhead = "<h3>SQL Details</h3>"
        $htmlbody += $subhead

        $htmlbody += $SQLDetails | Sort-Object Servername,ServiceName | ConvertTo-Html -Fragment
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
			    <h1 align=""center"">Overview - SQLServers</h1>
			    <h3 align=""center"">Generated: $reportime</h3>"
    $htmltail = "</body>
		    </html>"

    $htmlreport = $htmlhead + $htmlbody + $htmltail

    $htmlfile = "$ReportPath" + "\Overview_SQLServers.html"
    $htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
}
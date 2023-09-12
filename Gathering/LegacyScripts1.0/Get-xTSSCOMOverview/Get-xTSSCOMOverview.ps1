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
    
    $Computers = Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object -Property Operatingsystem -like "*server*" | Where-Object -Property enabled -EQ $true | Sort-Object Name
    
    $subhead = "<h3>Operations Manager Servers Used</h3>"
    $htmlbody += $subhead
        
    try {
        $ComputersDataResult = Foreach ($Computer in $Computers) {
            $HKLM = 2147483650
            $RegKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Agent Management Groups"
            $RegValue = "NetworkName"
            Write-Verbose "Working on: $($Computer.Name)"
            try {
                $WMIObject = Get-WmiObject -list "StdRegProv" -namespace root\default -computername $Computer.Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                $ManagementGroups = $WMIObject.EnumKey($HKLM,$RegKey).sNames
                $OpsMgrServers = foreach ($ManagementGroup in $ManagementGroups) {
                    $WMIObject.GetStringValue($HKLM,$("$RegKey\$ManagementGroup\Parent Health Services\0"),$RegValue).sValue
                }
                $AgentKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
                $AgentVersion = $WMIObject.GetStringValue($HKLM,$AgentKey,"AgentVersion").sValue
                $Product = $WMIObject.GetStringValue($HKLM,$AgentKey,"Product").sValue
                $ComputersHash = [ordered] @{
                    ComputerName = $($Computer.Name);
                    Servers = $($OpsMgrServers);
                    Product = $($Product);
                    AgentVersion = $($AgentVersion);
                    ManagementGroups = $($ManagementGroups);
                }
                New-Object PSObject -Property $ComputersHash
            }
            catch {
                Write-Verbose "Failed to connect to: $($Computer.Name)"
            }
        }
        $OpsMgrServers = $ComputersDataResult.Servers | Select-Object -Unique
        
        $htmlbody += $ComputersDataResult | Select-Object Servers -Unique | Where-Object Servers -NotLike "" | ConvertTo-Html -Fragment -Property Servers
        $htmlbody += $spacer

    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }


    $subhead = "<h3>Operations Manager Servers Overview</h3>"
    $htmlbody += $subhead
    try {
        $OpsMgrServerResult = foreach ($OpsMgrServer in $OpsMgrServers) { 
            $HKLM = 2147483650
            $RegKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Setup"
            $MgmtGroupKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups"
            $WMIObject = Get-WmiObject -list "StdRegProv" -namespace root\default -computername $OpsMgrServer -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $OpsMgrData = [ordered] @{ 
                ServerName = $($OpsMgrServer);
                ManagementGroup = $($WMIObject.EnumKey($HKLM,$MgmtGroupKey).sNames);
                DatabaseServerName = $($WMIObject.GetStringValue($HKLM,$RegKey,"DatabaseServerName").sValue);
                DataWarehouseDBServerName = $($WMIObject.GetStringValue($HKLM,$RegKey,"DataWarehouseDBServerName").sValue);
                InstallDirectory = $($WMIObject.GetStringValue($HKLM,$RegKey,"InstallDirectory").sValue);
                CurrentVersion = $($WMIObject.GetStringValue($HKLM,$RegKey,"CurrentVersion").sValue);
                DatabaseName = $($WMIObject.GetStringValue($HKLM,$RegKey,"DatabaseName").sValue);
                DataWarehouseDBName = $($WMIObject.GetStringValue($HKLM,$RegKey,"DataWarehouseDBName").sValue);
                Product = $($WMIObject.GetStringValue($HKLM,$RegKey,"Product").sValue);
                InstalledOn = $($WMIObject.GetStringValue($HKLM,$RegKey,"InstalledOn").sValue);
                ServerVersion = $($WMIObject.GetStringValue($HKLM,$RegKey,"ServerVersion").sValue);
                ManagementServerPort = $($WMIObject.GetStringValue($HKLM,$RegKey,"ManagementServerPort").sValue);
                UIVersion = $($WMIObject.GetStringValue($HKLM,$RegKey,"UIVersion").sValue);
            }
            New-Object PSObject -Property $OpsMgrData
        }

        $htmlbody += $OpsMgrServerResult | ConvertTo-Html -Fragment
        $htmlbody += $spacer

    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    $subhead = "<h3>Operations Manager Reporting Overview</h3>"
    $htmlbody += $subhead
    try {
        $OpsMgrReportingResult = foreach ($OpsMgrServer in $OpsMgrServers) { 
            $HKLM = 2147483650
            $RegKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Reporting"
            $MgmtGroupKey = "SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Server Management Groups"
            $WMIObject = Get-WmiObject -list "StdRegProv" -namespace root\default -computername $OpsMgrServer -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $OpsMgrReportData = [ordered] @{
                ServerName = $($OpsMgrServer);
                ManagementGroup = $($WMIObject.EnumKey($HKLM,$MgmtGroupKey).sNames);
                DWDBInstance = $($WMIObject.GetStringValue($HKLM,$RegKey,"DWDBInstance").sValue);
                DWDBName = $($WMIObject.GetStringValue($HKLM,$RegKey,"DWDBName").sValue);
                SRSInstance = $($WMIObject.GetStringValue($HKLM,$RegKey,"SRSInstance").sValue);
                ReportingServerUrl = $($WMIObject.GetStringValue($HKLM,$RegKey,"ReportingServerUrl").sValue);
            }
            New-Object PSObject -Property $OpsMgrReportData
        }

        $htmlbody += $OpsMgrReportingResult | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    $subhead = "<h3>Operations Manager Management Groups in use</h3>"
    $htmlbody += $subhead
    
    try {
        $OpsMgrManagementGroupsResult = foreach ($Item in $ComputersDataResult.ManagementGroups) { 
            $OpsMgrManagementGroupsData = @{
                Name = $Item
            }
            New-Object PSObject -Property $OpsMgrManagementGroupsData
        }
        

        $htmlbody += $OpsMgrManagementGroupsResult | Where-Object Name -notlike "" | Select-Object @{Name="Management Group Name";Expression={$_.Name}} | Get-Unique | ConvertTo-Html -Fragment -Property "Management Group Name"
        $htmlbody += $spacer

    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    $subhead = "<h3>Operations Manager Agents</h3>"
    $htmlbody += $subhead
    
    try {
        $OpsMgrManagementGroupsResult = foreach ($Item in $ComputersDataResult.ManagementGroups) { 
            $OpsMgrManagementGroupsData = @{
                Name = $Item
            }
            New-Object PSObject -Property $OpsMgrManagementGroupsData
        }
        
        $OpsMgrAgents = $ComputersDataResult | Select-Object ComputerName,AgentVersion,@{Name="Management Group";Expression={$_.ManagementGroups}} | Where-Object AgentVersion -notlike "" | sort ComputerName

        $htmlbody += $OpsMgrAgents | ConvertTo-Html -Fragment
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

    $htmlfile = "$ReportPath" + "\Overview_OpsMgr.html"
    $htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
}
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
    $ReportPath
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
    
    Write-Verbose "Working on Domain data"
    $subhead = "<h3>Domain Data</h3>"
    $htmlbody += $subhead
    try {
        $Domain = Get-ADDomain -Current LocalComputer
        $Forest = Get-ADForest -Current LocalComputer
        $Hash = [Ordered]@{ 
            ForestName = $Forest.Name
            ForestLevel = $Forest.ForestMode
            DomainName = $Domain.Name
            DomanNetBiosName = $Domain.NetBIOSName
            DomainLevel = $Domain.DomainMode
        }
        $DomainData = New-Object PSobject -Property $Hash
        $htmlbody += $DomainData | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
        Break
    }

    $pdcemulator = (Get-ADDomain -Current LocalComputer).pdcemulator


    Write-Verbose "Working on FSMO Roles"
    $subhead = "<h3>FSMO Roles</h3>"
    $htmlbody += $subhead

    try {
        Clear-Variable Hash, DomainData -ErrorAction SilentlyContinue
        $Hash = [Ordered]@{ 
            PDCEmulator = $Domain.PDCEmulator
            RidMaster = $domain.RIDMaster
            SchemMaster = $Forest.SchemaMaster
            InfrastructureMaster = $Domain.InfrastructureMaster
            DomainNamningMaster = $Forest.DomainNamingMaster
        }
        $DomainData = New-Object PSobject -Property $Hash
        $htmlbody += $DomainData | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    Write-Verbose "Working on Domain Controllers"
    $subhead = "<h3>Domain Controllers</h3>"
    $htmlbody += $subhead

    try { 
        
        $DCs = Get-ADDomainController -Filter * | Sort-Object Name
        $DCsData = Foreach ($DC in $DCs) {
            Write-Verbose "Working on $($DC.HostName)"
            $DCComputer = Get-ADDomainController -Server $DC.HostName
            $DCData = [ordered] @{
                Name = $DCComputer.Name
                OperatingSystem = $DCComputer.OperatingSystem
                OperatingSystemServicePack = $DCComputer.OperatingSystemServicePack
                IPv4 = $DCComputer.IPv4Address
                IPv6 = $DCComputer.IPv6Address
                GlobalCatalog = $DCComputer.IsGlobalCatalog
                RODC = $DCComputer.IsReadOnly
                Site = $DCComputer.Site
            }
            New-Object PSObject -Property $DCData
        }
        
        $htmlbody += $DCsData | ConvertTo-Html -Fragment
        $htmlbody += $spacer
        
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    Write-Verbose "Working on Replication Summary"
    $subhead = "<h3>Replication Summary</h3>"
    $htmlbody += $subhead

    try {
        $ReplicationData = Get-ADReplicationPartnerMetadata -Scope Forest -Partition * -EnumerationServer $pdcemulator | Select-Object Server,Partition,@{Name="Partner";Expression={($_.Partner).Split(",")[1].SubString(3) }},ConsecutiveReplicationFailures,LastReplicationSuccess | Sort Server,Partner 

        $htmlbody += $ReplicationData | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    Write-Verbose "Working on Sysvol Information"
    $subhead = "<h3>SysVol Information</h3>"
    $htmlbody += $subhead

    try {
        $SYSVOLData = Foreach ($DC in $DCs) {
            $DCData = Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
                $SysVolPath = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name SysVol
                if ((Get-ItemProperty -Path "HKLM:System\CurrentControlSet\Services\DFSR\Parameters\SysVols\Migrating Sysvols" -Name "Local State")."Local State" -eq "3") {
                    $sysVolState = "DFSR"
                }
                else {
                   $sysVolState = "FRS"
                }
                Clear-Variable TestName, TestStatus -ErrorAction SilentlyContinue
                $Dcdiag = (Dcdiag.exe /test:Sysvolcheck) -split ('[\r\n]')
                $SysVolReport = Foreach ($Test in $Dcdiag) {
                    Switch -RegEx ($Test) { 
                        "Starting test:" { $TestName = $Test.trim().Substring(15) } 
                        "passed test" { $TestStatus = "Passed" } 
                        "failed test" { $TestStatus = "Failed" }
                        Default { }
                    }
                    if (-not [string]::IsNullOrEmpty($TestName)) {
                        if (-not [string]::IsNullOrEmpty($TestStatus)) {
                            $SysVolHash = [ordered] @{
                                TestName = $($TestName);
                                TestStatus = $($TestStatus)
                            }
                            New-Object PSObject -Property $SysVolHash
                        }
                    }
                }
                Clear-Variable TestName, TestStatus -ErrorAction SilentlyContinue
                $Dcdiag = (Dcdiag.exe /test:netlogons) -split ('[\r\n]')
                $NetLogonsReport = Foreach ($Test in $Dcdiag) {
                    Switch -RegEx ($Test) { 
                        "Starting test:" { $TestName = $Test.trim().Substring(15) } 
                        "passed test" { $TestStatus = "Passed" } 
                        "failed test" { $TestStatus = "Failed" }
                        Default { }
                    }
                    if (-not [string]::IsNullOrEmpty($TestName)) {
                        if (-not [string]::IsNullOrEmpty($TestStatus)) {
                            $NetLogonsHash = [ordered] @{
                                TestName = $($TestName);
                                TestStatus = $($TestStatus)
                            }
                            New-Object PSObject -Property $NetLogonsHash
                        }
                    }
                }
                If ($sysVolState -eq "DFSR") {
                    Switch ((Get-WmiObject -Namespace root/MicrosoftDfs -Class dfsrreplicatedfolderinfo | Where-Object ReplicatedFolderName -Like *sysvol*).State) {
                        "0" { $SysVolInfo = "Uninitialized" }
                        "1" { $SysVolInfo = "Initialized" }
                        "2" { $SysVolInfo = "Initial Sync" }
                        "3" { $SysVolInfo = "Auto Recovery" }
                        "4" { $SysVolInfo = "Normal" }
                        "5" { $SysVolInfo = "In Error" }
                    }
                    $OSversion = ((Get-WmiObject -Class win32_operatingsystem).Version)
                    $OsVersion = $OSVersion.Substring(0,3)
                    switch ($OSversion) {
                        "6.1" {
                            If ($(Get-WmiObject win32_QuickfixEngineering | Where-Object HotfixID -eq "KB2663685" | Measure-Object).Count -ge 1) {
                                $Default = "Disabled"
                            }
                            Else {
                                $Default = "Enabled"
                            }
                        }
                        "6.2" { $Default = "Disabled" }
                        Default { $Default = "Enabled" }
                    }
                    try {
                        $AutoRecoverValue = (Get-ItemProperty -Path HKLM:SYSTEM\CurrentControlSet\Services\DFSR\Parameters -Name StopReplicationOnAutoRecovery -ErrorAction Stop).StopReplicationOnautoRecovery
                    }
                    Catch {
                        $AutoRecoverValue = "NoValue"
                    }

                    switch ($AutoRecoverValue) {
                        "0" { $AutoRecoverConfig = "Enabled" }
                        "1" { $AutoRecoverConfig = "Disabled" }
                        "NoValue" { $AutoRecoverConfig = $Default }
                        Default { $AutoRecoverConfig = "Unknown" }
                    }
                    

                }
                                              
                $DCHash = [ordered] @{
                    SysVolPath = $SysVolPath.SysVol
                    SysVolReplicationEngine = $sysVolState
                    SysVolReplicationState = $SysVolInfo
                    LastSuccessfulSynctime = $LastSuccessfulSyncTime
                    SysvolCheck = ($SysvolReport | select TestName,TestStatus -Unique)[1].TestStatus
                    NetLogonCheck = ($NetlogonsReport | select TestName,TestStatus -Unique)[1].TestStatus
                    ReplicationAutoRecovery = $($AutoRecoverConfig);
                    
                }
                New-Object PSObject -Property $DCHash
            }
            $DCData | Select @{Name="Server Name";Expression={$_.PSComputerName}}, SysVolPath,SysVolReplicationEngine, SysVolReplicationState, LastSuccessfulSynctime, SysVolCheck, NetLogonCheck, ReplicationAutoRecovery
        }

        $htmlbody += $SYSVOLData | ConvertTo-Html -Fragment
        $htmlbody += $spacer
        
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    try {
        $subhead = "<h3>SysVol Replication time</h3>"
        $htmlbody += $subhead
        $ConnectionDataReport = Foreach ($DC in $DCs) { 
            $ConnectionInfos = Get-WmiObject -ComputerName $DC.HostName -Namespace root/MicrosoftDFS -Class DFSRConnectionInfo | Where-Object Inbound -eq $true
            $ConnectionData = foreach ($ConnectionInfo in $ConnectionInfos) {
                $ConnectionInfoData = [ordered] @{
                    ServerName = $($DC.HostName)
                    Partner = $($ConnectionInfo.PartnerName);
                    LastSuccessfulSyncTime = $($ConnectionInfo.LastSuccessfulSynctime | ForEach-Object { [System.Management.ManagementDateTimeConverter]::ToDateTime($_) })
                }
                New-Object PSObject -Property $ConnectionInfoData
            }
            $ConnectionData
        }

        $htmlbody += $ConnectionDataReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer

    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }


    $subhead = "<h3>Sites and Services</h3>"
    $htmlbody += $subhead
    Try {
        Write-Verbose "Working on Sites"
        $subhead = "<h4>Sites</h4>"
        $htmlbody += $subhead
        
        $Sites = Get-ADReplicationSite -Filter *
        $Sites[3].InterSiteTopologyGenerator -eq $null
        
        $htmlbody += $Sites | Select-Object Name,@{
            Name="HasServer";Expression={ 
                    if ($_.InterSiteTopologyGenerator -eq $null) {
                        return $false
                    }
                    Else {
                        return $true
                    }
                }
            } | ConvertTo-Html -Fragment -Property Name
        $htmlbody += $spacer

        Write-Verbose "Working on Subnets"
        $subhead = "<h4>Subnets</h4>"
        $htmlbody += $subhead
        
        $Subnets = Get-ADReplicationSubnet -Filter *
        $SubNetReport = Foreach ($Subnet in $Subnets) {
            $SubNetHash = [ordered] @{ 
                Subnet = $($Subnet.Name);
                Location = $($Subnet.Location);
                Site = $($Subnet.Site.Split(","))[0].Substring(3)
            }
            New-Object PSObject -Property $SubNetHash
        }

        $htmlbody += $SubNetReport | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        Write-Verbose "Working on SiteLinks"
        $subhead = "<h4>SiteLinks</h4>"
        $htmlbody += $subhead
        
        $SiteLinks = Get-ADReplicationSiteLink -Filter *
        
        $htmlbody += $SiteLinks | Select Name,ReplicationFrequencyInMinutes | ConvertTo-Html -Fragment
        $htmlbody += $spacer

        Write-Verbose "Working on Replication Partners"
        $subhead = "<h4>Replications Partners</h4>"
        $htmlbody += $subhead
               
        $ReplicationConnections = Foreach ($DC in $DCs) {
            $ReplicationPartners = Get-ADReplicationConnection -Server $DC.HostName
            $ReplicationPartnersReport = foreach ($ReplicationPartner in $ReplicationPartners) {
                $ReplicationHash = [ordered] @{ 
                    ServerName = $DC.HostName
                    ReplicateFrom = $ReplicationPartner.ReplicateToDirectoryServer.Split(",")[0].Substring(3)
                    ReplicateTo = $ReplicationPartner.ReplicateFromDirectoryServer.Split(",")[1].Substring(3)
                    AutoGenerated = $ReplicationPartner.AutoGenerated
                }
                New-Object PSObject -Property $ReplicationHash
            }
            $ReplicationPartnersReport
        }
        
        $htmlbody += $ReplicationConnections | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    
    }
    Catch {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    Try {
        foreach ($DC in $DCs) {
            Clear-Variable NetLogonReport -ErrorAction SilentlyContinue
            Write-Verbose "Working on Domain Controller - $($DC.HostName)"
            $subhead = "<h3>Domain Controller - $($DC.HostName)</h3>"
            $htmlbody += $subhead
            $NetLogonReport = Invoke-Command -ComputerName $DC.HostName -ScriptBlock {
                Clear-Variable NetLogonHash -ErrorAction SilentlyContinue
                $NetLogonLog = Get-Content "$env:windir\Debug\Netlogon.log"
                if (-not [string]::IsNullOrEmpty($NetLogonLog)) {
                    $NetLogonData = foreach ($Entry in $($NetLogonLog -split ('[\r\n]'))) { 
                        if ($Entry -match "NO_CLIENT_SITE:") {
                            $EntryCount = $($Entry -split " ").Count
                            $NetLogonHash = [ordered] @{
                                ComputerName = $($Entry -split " ")[$($EntryCount-2)];
                                Date = $($Entry -split " ")[0];
                                Time = $($Entry -split " ")[1];
                                IPAddress = $($Entry -split " ")[$($EntryCount-1)];
                                DebugInformation = ""
                            }
                        }
                        Else { 
                            $NetLogonHash = [ordered] @{
                                ComputerName = ""
                                Date = $($Entry -split " ")[0];
                                Time = $($Entry -split " ")[1];
                                IPAddress = ""
                                DebugInformation = $($Entry.Substring(15))
                            }                            
                        }
                        New-Object PSObject -Property $NetLogonHash
                    }
                }
                Else {
                    $NetLogonHash = [ordered] @{
                        ServerName = $($env:COMPUTERNAME)
                        Information = $("No entries in Netlogon.log")
                }
                New-Object PSObject -Property $NetLogonHash
                }
                $NetLogonData
            }
            if (-not [string]::IsNullOrWhiteSpace((Get-Variable NetLogonReport).Value.Information)) {
                $htmlbody += $NetLogonReport | Select ServerName,Information | ConvertTo-Html -Fragment
                $htmlbody += $spacer
            }
            else {
                
                if (-not [string]::IsNullOrWhiteSpace((Get-Variable NetLogonReport).Value.ComputerName)) {
                    $htmlbody += $NetLogonReport | Select ComputerName,IPAddress -Unique | Sort-Object ComputerName | Where-Object ComputerName -ne "" | Where-Object ComputerName -NE $null | ConvertTo-Html -Fragment
                    $htmlbody += $spacer
                }
                
                if (-not [string]::IsNullOrWhiteSpace((Get-Variable NetLogonReport).Value.DebugInformation)) {
                    $htmlbody += $NetLogonReport | Select Date,Time,DebugInformation | Sort-Object Date | Where-Object DebugInformation -ne "" | Where-Object DebugInformation -NE $null | ConvertTo-Html -Fragment
                    $htmlbody += $spacer
                }
            }
        }
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
			    <h1 align=""center"">Overview - Active Directory</h1>
			    <h3 align=""center"">Generated: $reportime</h3>"
    $htmltail = "</body>
		    </html>"

    $htmlreport = $htmlhead + $htmlbody + $htmltail

    $htmlfile = "$ReportPath" + "\Overview_ActiveDirectory.html"
    $htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
}
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

$DHCPServers = Get-DhcpServerInDC

$WarningPreference = "SilentlyContinue"
$StopPreference = "SilentlyContinue"

foreach($DHCPServer in $DHCPServers){

    # Set the basic's
    $ComputerName = $DHCPServer.DnsName
    $htmlreport = @()
    $htmlbody = @()
    $spacer = "<br />"

    # Get Basic Computer Info

    $subhead = "<h3>BasicComputer System Information</h3>"
    $htmlbody += $subhead
    try
    {
        $Win32_ComputerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop -ComputerName $ComputerName |
            Select-Object Name,Manufacturer,Model,
                        @{Name='Memory (Gb)';Expression={
                            $tpm = $_.TotalPhysicalMemory/1GB;
                            "{0:F0}" -f $tpm
                        }},
                        DnsHostName,Domain
       
        $htmlbody += $Win32_ComputerSystem | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get status of the DHCP service

    $subhead = "<h3>DHCP Service</h3>"
    $htmlbody += $subhead
    
    try
    {
        $Win32_Service = Get-WmiObject Win32_Service -ErrorAction Stop -ComputerName $ComputerName |
            Where-Object Name -EQ DHCPServer |
            Select-Object Name,State,Status,StartMode

        $htmlbody += $Win32_Service | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get-DhcpServerVersion

    $subhead = "<h3>Dhcp Server Version</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerSetting = Get-DhcpServerVersion -ComputerName $ComputerName |
            Select-Object MajorVersion,MinorVersion

        $htmlbody += $DhcpServerSetting | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get-DhcpServerSetting

    $subhead = "<h3>Dhcp Server Setting</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerSetting = Get-DhcpServerSetting -ComputerName $ComputerName |
            Select-Object ActivatePolicies,ConflictDetectionAttempts,DynamicBootp,IsAuthorized,IsDomainJoined,NapEnabled,NpsUnreachableAction,RestoreStatus

        $htmlbody += $DhcpServerSetting | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get-DhcpServerv4DnsSetting

    $subhead = "<h3>Dhcp Server v4 Dns Setting</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerv4DnsSetting = Get-DhcpServerv4DnsSetting -ComputerName $ComputerName |
            Select-Object DynamicUpdates,DeleteDnsRROnLeaseExpiry,UpdateDnsRRForOlderClients,DnsSuffix,DisableDnsPtrRRUpdate,NameProtection

        $htmlbody += $DhcpServerv4DnsSetting | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get-DhcpServerDnsCredential

    $subhead = "<h3>Dhcp Server Dns Credential</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerDnsCredential = Get-DhcpServerDnsCredential -ComputerName $ComputerName |
            Select-Object UserName,DomainName

        $htmlbody += $DhcpServerDnsCredential | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }


    # Get-DhcpServerv4Statistics

    $subhead = "<h3>Dhcp Server v4 Statistics</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerSetting = Get-DhcpServerv4Statistics -ComputerName $ComputerName |
            Select-Object InUse,Available,Acks,AddressesAvailable,AddressesInUse,Declines,DelayedOffers,Discovers,Naks,Offers,PendingOffers,PercentageAvailable,PercentageInUse,PercentagePendingOffers,Releases,Requests,ScopesWithDelayConfigured,ServerStartTime,TotalAddresses,TotalScopes

        $htmlbody += $DhcpServerSetting | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get-DhcpServerv4Scope

    $subhead = "<h3>Dhcp Server v4 Scope</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerSetting = Get-DhcpServerv4Scope -ComputerName $ComputerName |
            Select-Object ScopeId,SubnetMask,StartRange,EndRange,ActivatePolicies,Delay,Description,LeaseDuration,MaxBootpClients,Name,NapEnable,NapProfile,State,SuperscopeName,Type

        $htmlbody += $DhcpServerSetting | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }

    # Get-DhcpServerv4ScopeStatistics

    $subhead = "<h3>Dhcp Server v4 Scope Statistics</h3>"
    $htmlbody += $subhead

    try{
        $DhcpServerSetting = Get-DhcpServerv4ScopeStatistics -ComputerName $ComputerName |
            Select-Object ScopeId,Free,InUse,Reserved,Pending,AddressesFree,AddressesFreeOnPartnerServer,AddressesFreeOnThisServer,AddressesInUse,AddressesInUseOnPartnerServer,AddressesInUseOnThisServer,PendingOffers,PercentageInUse,ReservedAddress,SuperscopeName

        $htmlbody += $DhcpServerSetting | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch{
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
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
				TD{border: 1px solid black; background: #ADD8E6; padding: 5px; color: #000000;}
				td.pass{background: #7FFF00;}
				td.warn{background: #FFE600;}
				td.fail{background: #FF0000; color: #ffffff;}
				td.info{background: #85D4FF;}
				</style>
				<body>
				<h1 align=""center"">Server Info: $ComputerName</h1>
				<h3 align=""center"">Generated: $reportime</h3>"

    $htmltail = "</body>
			</html>"

    $htmlreport = $htmlhead + $htmlbody + $htmltail

    $htmlfile = "$ReportPath" + "\Overview_DHCP.html"
    $htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
}

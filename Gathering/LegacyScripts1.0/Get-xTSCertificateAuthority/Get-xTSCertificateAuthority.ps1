<#
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

Param(

    [Parameter(Mandatory=$false)]
    $ReportPath = "C:\Assesment\Reports"
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

    $subhead = "<h3>Root CA Information</h3>"
    $htmlbody += $subhead

    $DomainDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    

    $CAs = [ADSI]"LDAP://CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
    $CADataResults = Foreach ($CA in $CAs.Children) {
        $CN = $CA | Select-Object -ExpandProperty CN
        $CDPs = [ADSI]"LDAP://CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DomainDN"
        Foreach ($CDP in $CDPs.Children) {
            Foreach ($Object in $CDP.Children) {
                #$Object | Where-Object -Property Name -like $CN | Select-Object *
                $ServerName = ($Object | Where-Object -Property Name -like $CN | Select-Object -ExpandProperty distinguishedName)
                if ($ServerName.Length -ne 0) {
                    $CAData = [ordered] @{
                        RootCA = $CN;
                        ServerName = $ServerName.Split(",")[1].Substring(3);
                    }
                    New-Object PSObject -Property $CAData
                }
            }
        }
    }
    
    $CAResults = foreach ($Server in $CADataResults) {
        $Connection = Test-NetConnection -ComputerName $Server.ServerName
        $CAData = [ordered] @{
            RootCA = $Server.RootCA;
            ServerName = $Server.ServerName;
            RemoteAddress = $Connection.RemoteAddress;
            Reachable = $Connection.PingSucceeded;            
        }
        New-Object PSObject -Property $CAData
    }
    
    $htmlbody += $CAResults | ConvertTo-Html -Fragment
    $htmlbody += $spacer

    $subhead = "<h3>Issuing CA Information</h3>"
    $htmlbody += $subhead
              
    try
    {
        $CAPublisherServers = Get-ADGroup -Identity "Cert Publishers" | Get-ADGroupMember
        $PublishResults = foreach ($Server in $CAPublisherServers) {
            $ConnectionTest = Test-NetConnection -ComputerName $Server.name
            Clear-Variable CAInfo -Force
            if ($ConnectionTest.PingSucceeded -eq $true) {
                $CAInfo = Invoke-Command -ComputerName $Server.name -ScriptBlock {
                    $Active = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration | Select-Object -ExpandProperty Active
                    Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$Active
                }
            }
            $PublishData = [ordered] @{
                IssuingCA = $ConnectionTest.ComputerName
                RemoteIP = $ConnectionTest.RemoteAddress
                CAType = $(
                    Switch ($CAInfo.CAType) {
                        0 { "Enterprise Root CA" }
                        1 { "Enterprise Subordinate CA" }
                        3 { "Stand Alone CA" }
                        4 { "Stand Alone Subordinate CA" }
                    }
                )
                CAName = $CAInfo.CommonName
                ValidityPeriod = $("$($CAInfo.ValidityPeriodUnits) $($CAInfo.ValidityPeriod)")
                SHA = $(
                    if (-not([string]::IsNullOrEmpty($CAInfo.CACertHash))) {
                        (Get-ChildItem -Path Cert:\LocalMachine\CA\$($CAInfo.CACertHash.Replace(" ",'')) | Select-Object -Property *).SignatureAlgorithm.FriendlyName
                    }
                )
                RootCA = $(
                    if (-not([string]::IsNullOrEmpty($CAInfo.CACertHash))) {
                        (Get-ChildItem -Path Cert:\LocalMachine\CA\$($CAInfo.CACertHash.Replace(" ",'')) | Select-Object -Property *).Issuer.Split(",")[0].Substring(3)
                    }
                )
                Reachable = $ConnectionTest.PingSucceeded
            }
            New-Object PSObject -Property $PublishData
        }

        $htmlbody += $PublishResults | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch
    {
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
			    <h1 align=""center"">Overview - Certificate Authorities</h1>
			    <h3 align=""center"">Generated: $reportime</h3>"
    $htmltail = "</body>
		    </html>"

    $htmlreport = $htmlhead + $htmlbody + $htmltail

    $htmlfile = "$ReportPath" + "\Overview_CertificateAuthority.html"
    $htmlreport | Out-File $htmlfile -Encoding Utf8 -Force
}


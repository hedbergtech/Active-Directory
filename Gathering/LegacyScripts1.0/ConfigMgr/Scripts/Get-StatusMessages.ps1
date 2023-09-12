<#
Created:    2018-06-21
Updated:    2018-06-21
Version:    1.0
Author :    Peter Lofgren
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


# Increase Query Maximum (default is 1000)
# Set-CMQueryResultMaximum -Maximum 5000
# $Date = "2015-01-16"
# Get-CMSiteStatusMessage -ViewingPeriod $Date | Where-Object { $_.MessageID -eq "11170" } | Select Component, MachineName,Time

Start-Transcript -Path $Path\StatusMessages.txt

$StatusMessages = @()
# Server Health
$StatusMessages += @{"MessageID" = "5203"; "MessageDescription" = "Counts of Active Directory System Discovery: Warning"}
$StatusMessages += @{"MessageID" = "2542"; "MessageDescription" = "Counts of Collection Evaluator failed to update query: Warning"}
$StatusMessages += @{"MessageID" = "2543"; "MessageDescription" = "Counts of Collection Evaluator failed to update the query rule of collectionServer: Warning"}
# Client Health
$StatusMessages += @{"MessageID" = "10815"; "MessageDescription" = "Client(s) reporting certificate maintenance failures"}
# Client deployments
$StatusMessages += @{"MessageID" = "10018"; "MessageDescription" = "Client(s) is reporting Platform is not supported for this advertisement"}
$StatusMessages += @{"MessageID" = "11135"; "MessageDescription" = "Client(s) reported that a task sequence failed to execute an action"}
$StatusMessages += @{"MessageID" = "10803"; "MessageDescription" = "Client(s) reporting failures downloading policy"}
$StatusMessages += @{"MessageID" = "10091"; "MessageDescription" = "Client(s) reporting inability to update Windows Installer package source path(s)"}
$StatusMessages += @{"MessageID" = "10006"; "MessageDescription" = "Client(s) reporting problems executing advertised program(s)"}
$StatusMessages += @{"MessageID" = "10056"; "MessageDescription" = "Client(s) reporting problems executing advertised program(s)"}
# Client Task Sequence progress
$StatusMessages += @{"MessageID" = "11170"; "MessageDescription" = "Client(s) reporting task sequence step failure"}
$StatusMessages += @{"MessageID" = "10093"; "MessageDescription" = "Counts of The Windows Installer source paths failed to update: Warning"}
$StatusMessages += @{"MessageID" = "2302"; "MessageDescription" = "Counts of Distribution Manager failed to process packages"}
$StatusMessages += @{"MessageID" = "2306"; "MessageDescription" = "Counts of Package source folder does not exist or not enough permissions"}
$StatusMessages += @{"MessageID" = "11138"; "MessageDescription" = "Client(s) reporting task sequence step failure"}
$StatusMessages += @{"MessageID" = "11135"; "MessageDescription" = "Client(s) reported that a task sequence failed to execute an action"}

# Output summary
Write-Output ""
Write-Output "----------------- Report Summary -----------------"
Write-Output ""
foreach ($StatusMessage in $StatusMessages) {
    $Status = Get-WmiObject -ComputerName $SiteServer -Query "SELECT * FROM SMS_StatusMessage WHERE MessageID=$($StatusMessage.MessageID)" -Namespace "root\sms\site_$SiteCode" | Select-Object Component,MachineName,@{label='Time';expression={$_.ConvertToDateTime($_.Time)}} 
    Write-Output "MessageID: $($StatusMessage.MessageID) - $($Status.Count) $($StatusMessage.MessageDescription)"
    Write-Output ""
}

# Output details
Write-Output ""
Write-Output "----------------- Report Details -----------------"
Write-Output ""

foreach ($StatusMessage in $StatusMessages) {
    Write-Host "$($StatusMessage.MessageID) - $($StatusMessage.MessageDescription)"
    Get-WmiObject -ComputerName $SiteServer -Query "SELECT * FROM SMS_StatusMessage WHERE MessageID=$($StatusMessage.MessageID)" -Namespace "root\sms\site_$SiteCode" | Select-Object Component,MachineName,@{label='Time';expression={$_.ConvertToDateTime($_.Time)}} 
    Write-Output ""
}

Stop-Transcript
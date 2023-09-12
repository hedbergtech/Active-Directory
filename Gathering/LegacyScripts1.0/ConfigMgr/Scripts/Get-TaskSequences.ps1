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

# List Task Sequences
Get-WmiObject -ComputerName $SiteServer SMS_TaskSequencePackage -Namespace root\sms\site_$SiteCode  | Select-Object *

# Export Task Sequences
Set-Location $Path
$TsList = Get-WmiObject -ComputerName $SiteServer SMS_TaskSequencePackage -Namespace root\sms\site_$SiteCode
ForEach ($Ts in $TsList) {
    $Ts = [wmi]"$($Ts.__PATH)"
    Set-Content -Path "$($ts.PackageId).xml" -Value $Ts.Sequence
}

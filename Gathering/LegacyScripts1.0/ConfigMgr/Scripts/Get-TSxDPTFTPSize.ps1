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
Param (
    [Parameter(Mandatory=$true,HelpMessage="Enter full path to outputfile")]    
    $OutPut
)


$CMModule = $env:SMS_ADMIN_UI_PATH.Substring(0,$env:SMS_ADMIN_UI_PATH.Length-5) + "\ConfigurationManager.psd1"
Import-Module $CMModule -ErrorAction Stop
$Drive = (Get-PSDrive -PSProvider CMSite).Name
Set-Location $($Drive + ":")


$DPs = Get-CMDistributionPoint
$DPResult = Foreach ($DP in $DPs) {
    $Propslist = $DP.Props
    
    $PropResult = Foreach ($Prop in $Propslist) {
    
        if ($Prop.PropertyName -eq "isPXE") {
    
            if ($Prop.Value -eq "1") {
                $DPName = $DP.NetworkOSPath.Replace("\\","")
    
                if ($DPName -match $env:COMPUTERNAME) {
                    try {
                            $BlockSize = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\SMS\DP -Name RamDiskTFTPBlockSize -ErrorAction Stop).RamDiskTFTPBlockSize
                        }
                        Catch {
                            $BlockSize = "NA"
                        }
                        try {
                            $WindowSize = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\SMS\DP -Name RamDiskTFTPWindowSize -ErrorAction Stop).RamDiskTFTPWindowSize
                        }
                        Catch {
                            $WindowSize = "NA"
                        }
                        $SizeData = [ordered] @{
                           ComputerName = $env:COMPUTERNAME;
                           BlockSize = $BlockSize;
                           WindowSize = $WindowSize;
                        }
                        New-Object PSObject -Property $SizeData
                    }
                else {
                    $Result = Invoke-Command -ComputerName $DPName -ScriptBlock {
                        try {
                            $BlockSize = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\SMS\DP -Name RamDiskTFTPBlockSize -ErrorAction Stop).RamDiskTFTPBlockSize
                        }
                        Catch {
                            $BlockSize = "NA"
                        }
                        try {
                            $WindowSize = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\SMS\DP -Name RamDiskTFTPWindowSize -ErrorAction Stop).RamDiskTFTPWindowSize
                        }
                        Catch {
                            $WindowSize = "NA"
                        }
                        $SizeData = [ordered] @{
                           ComputerName = $env:COMPUTERNAME;
                           BlockSize = $BlockSize;
                           WindowSize = $WindowSize;
                        }
                        New-Object PSObject -Property $SizeData
                    }
                    $Result
                }
            }
            else {
                $PropData = [ordered] @{
                    ComputerName = $env:COMPUTERNAME;
                    BlockSize = "No PXE";
                    WindowSize = "No PXE";
                }
                New-Object PSObject -Property $PropData
            }
        }
    }
    $DPData = [ordered] @{
        ComputerName = $PropResult.ComputerName;
        BlockSize = $PropResult.BlockSize
        WindowSize = $PropResult.WindowSize;  
    }
    New-Object PSObject -Property $DPData
}

$DPResult | Format-Table -AutoSize | Out-File $OutPut
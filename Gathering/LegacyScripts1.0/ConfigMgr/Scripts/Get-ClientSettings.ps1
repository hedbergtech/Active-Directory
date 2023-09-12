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
	[Parameter(Mandatory=$True,HelpMessage="Please enter full path to output file")]
	$OutPut
)

Start-Transcript -Path $OutPut

#Get module and import
$CMModule = $env:SMS_ADMIN_UI_PATH.Substring(0,$env:SMS_ADMIN_UI_PATH.Length-5) + "\ConfigurationManager.psd1"
Import-Module $CMModule -ErrorAction Stop
$Drive = (Get-PSDrive -PSProvider CMSite).Name
Set-Location $($Drive + ":")

# Get the different Client settings Names
$CMClientSettings = Get-CMClientSetting | Select-Object Name

foreach ($Setting in $CMClientSettings) {
	# Get all possible values for the Get-CMClientSetting -Setting parameter
	$xsettings = [Enum]::GetNames([Microsoft.ConfigurationManagement.Cmdlets.ClientSettings.Commands.SettingType])

	# dump the detailed configuration settings
	foreach ($xsettings in $xsettings ) {
        	write-output $Setting.Name
	        Get-CMClientSetting -Setting $xsettings -Name $Setting.Name | format-table
    }
}

Stop-Transcript
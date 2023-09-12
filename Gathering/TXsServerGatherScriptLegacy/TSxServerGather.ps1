<#

#>

Param(
    $Path = ""
)


if((Get-WmiObject Win32_OperatingSystem).ProductType -eq 1){
    Return
}


$WarningPreference = "SilentlyContinue"
$StopPreference = "SilentlyContinue"
$Path = $Path.TrimEnd('\')

if(!(Test-Path -Path $Path)){
    Write-Error "Unable to access $Path"
    Break
}

function Export-TSxData{
    Param(
        $obj,
        $Path,
        $Name
    )
    $obj | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $($path + "\" + "$env:COMPUTERNAME" + "_" + $Name + ".csv")
}

#---------------------------------------------------------------------
# Process the computer
#---------------------------------------------------------------------
Write-Verbose "=====> Processing $env:COMPUTERNAME <====="
$OutPath = $Path + "\" + $env:COMPUTERNAME

if(Test-Path -Path $OutPath){
    Write-Warning "Folder exists"
    Return
}
else{
    New-Item -Path $OutPath -ItemType Directory
}

#---------------------------------------------------------------------
# Collecting computer system information
#---------------------------------------------------------------------
Write-Verbose "Collecting computer system information"
try{

    $ComputerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction STOP |
        Select-Object Name,Manufacturer,Model,NumberOfProcessors,NumberOfLogicalProcessors,
            @{Name='TotalPhysicalMemoryinGb';Expression={
                $tpm = $_.TotalPhysicalMemory/1GB;
                "{0:F0}" -f $tpm
            }},
            DnsHostName,Domain

    $Win32ReliabilityStabilityMetrics = Get-WmiObject -Class Win32_ReliabilityStabilityMetrics -ErrorAction Stop | 
    Select-Object @{N="TimeGenerated"; E={$_.ConvertToDatetime($_.TimeGenerated)}},SystemStabilityIndex | Select-Object -First 1

    $Win32OperatingSystem = Get-WmiObject Win32_OperatingSystem -ErrorAction STOP | 
    Select-Object @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},
                    @{Name='OperatingSystem';Expression={$_.Caption}},
                    @{Name='Architecture';Expression={$_.OSArchitecture}},
                    Version,Organization,RegisteredUser,
                    @{Name='InstallDate';Expression={([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate).ToString("yyyy-MM-dd")
                    }},
                    WindowsDirectory,
                    @{Name='FreePhysicalMemoryinGB';Expression={[math]::round((Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory/1MB,2)}},
                    OSLanguage

    $Win32TimeZone = Get-WmiObject Win32_TimeZone

    $NetFirewallProfile = Get-NetFirewallProfile
    
    try{
        $OSDiskBitlocker = (Get-BitLockerVolume -MountPoint C -ErrorAction Stop).VolumeStatus
    }catch{
        $OSDiskBitlocker = "NA"
    }

    $DefenderState = (Get-WindowsFeature | Where-Object Name -EQ Windows-Defender).InstallState


    $LocalInfo = @{}

    $LocalInfo['IsServerCoreOS'] = "False"
	$LocalInfo['IsServerOS'] = "False"

	# Look up OS details
	Get-WmiObject Win32_OperatingSystem | ForEach-Object { $LocalInfo['OSCurrentVersion'] = $_.Version; $LocalInfo['OSCurrentBuild'] = $_.BuildNumber }
	if (Test-Path HKLM:System\CurrentControlSet\Control\MiniNT) {
		$LocalInfo['OSVersion'] = "WinPE"
	}
	else {
		$LocalInfo['OSVersion'] = "Other"
		if (!(Test-Path -Path "$env:WINDIR\Explorer.exe")) {
			$LocalInfo['IsServerCoreOS'] = "True"
		}
		if (Test-Path -Path HKLM:\System\CurrentControlSet\Control\ProductOptions) {
			$productType = (Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\ProductOptions).ProductType
			if ($productType -eq "ServerNT" -or $productType -eq "LanmanNT") {
				$LocalInfo['IsServerOS'] = "True"
			}
		}
	}

	# Look up network details
	$ipList = @()
	$macList = @()
	$gwList = @()
	Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 1" | ForEach-Object {
		$_.IPAddress | ForEach-Object { $ipList += $_ }
		$_.MacAddress | ForEach-Object { $macList += $_ }
		if ($_.DefaultIPGateway) {
			$_.DefaultIPGateway | ForEach-Object { $gwList += $_ }
		}
	}
	$LocalInfo['IPAddress'] = $ipList
	$LocalInfo['MacAddress'] = $macList
	$LocalInfo['DefaultGateway'] = $gwList


	Get-WmiObject Win32_BIOS | ForEach-Object {
		$LocalInfo['SerialNumber'] = $_.SerialNumber.Trim()
	}


	Get-WmiObject Win32_Processor | ForEach-Object {
		$LocalInfo['ProcessorSpeed'] = $_.MaxClockSpeed
		$LocalInfo['SupportsSLAT'] = $_.SecondLevelAddressTranslationExtensions
	}

	# UEFI
	try {
		Get-SecureBootUEFI -Name SetupMode | Out-Null
		$LocalInfo['IsUEFI'] = "True"
		$LocalInfo['SetupMode'] = "UEFI"
	}
	catch {
		$LocalInfo['IsUEFI'] = "False"
		$LocalInfo['SetupMode'] = "BIOS"
	}

	# TPM
	try {
		$TPM = Get-CimInstance -Namespace "root/cimv2/Security/MicrosoftTPM" -ClassName "Win32_TPM"
        IF($TPM -eq $null){
            $LocalInfo['TPM'] = "False"
        }
        else{
            $LocalInfo['TPM'] = "True"
        }
	}
	catch {
		$LocalInfo['TPM'] = "False"
	}

	# IPMI
    if($Win32OperatingSystem.Version -like "*6*"){
        $BMCIPV4Addr = "NA"
    }
    else{
	    $BMCIPV4Addr = (Get-PcsvDevice -ErrorAction SilentlyContinue).IPv4Address
        if($BMCIPV4Addr -eq $null){
            $BMCIPV4Addr = "NA"
        }
    }



    function Convert-WuaResultCodeToName{
        param( [Parameter(Mandatory=$true)]
            [int] $ResultCode
        )
        $Result = $ResultCode
        switch($ResultCode){
            2{$Result = "Succeeded"}
            3{$Result = "Succeeded With Errors"}
            4{$Result = "Failed"}
        }
        $Result
    }

    function Get-WuaHistory{
        $session = (New-Object -ComObject 'Microsoft.Update.Session')
        $history = $session.QueryHistory("",0,50) | ForEach-Object {
            $Result = Convert-WuaResultCodeToName -ResultCode $_.ResultCode
            # Make the properties hidden in com properties visible.
            $_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
            $Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
            $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
            $_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
            $_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
        }
        #Remove null records and only return the fields we want
        $history | Where-Object {![String]::IsNullOrWhiteSpace($_.title)} | Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
    }


    $WUAHistoryLast = Get-WuaHistory | Select-Object -First 1    


    $OS = Get-WmiObject Win32_OperatingSystem
    $Uptime = (Get-Date) - $OS.ConvertToDateTime($OS.LastBootUpTime)
    $SystemUpTime = [PSCustomObject]@{
        LastBoot      = $OS.ConvertToDateTime($OS.LastBootUpTime)
        Uptime        = ([String]$Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes")
    }

    $CS = New-Object PSObject
    $CS | Add-Member NoteProperty -Name "TSSystemID" -Value $env:COMPUTERNAME
    $CS | Add-Member NoteProperty -Name "Name" -Value $ComputerSystem.Name
    $CS | Add-Member NoteProperty -Name "Manufacturer" -Value $ComputerSystem.Manufacturer
    $CS | Add-Member NoteProperty -Name "Model" -Value $ComputerSystem.Model
    $CS | Add-Member NoteProperty -Name "NumberOfProcessors" -Value $ComputerSystem.NumberOfProcessors
    $CS | Add-Member NoteProperty -Name "NumberOfLogicalProcessors" -Value $ComputerSystem.NumberOfLogicalProcessors
    $CS | Add-Member NoteProperty -Name "TotalPhysicalMemoryinGb" -Value $ComputerSystem.TotalPhysicalMemoryinGb
    $CS | Add-Member NoteProperty -Name "FreePhysicalMemoryinGb" -Value $Win32OperatingSystem.FreePhysicalMemoryinGB
    $CS | Add-Member NoteProperty -Name "DnsHostName" -Value $ComputerSystem.DnsHostName
    $CS | Add-Member NoteProperty -Name "Domain" -Value $ComputerSystem.Domain
    $CS | Add-Member NoteProperty -Name "ReliabilityStabilityIndex" -Value $Win32ReliabilityStabilityMetrics.SystemStabilityIndex
    $CS | Add-Member NoteProperty -Name "ToolkitUsed" -Value $(Test-Path -Path HKLM:\SOFTWARE\HydrationKit)
    $CS | Add-Member NoteProperty -Name "OperatingSystem" -Value $Win32OperatingSystem.OperatingSystem
    $CS | Add-Member NoteProperty -Name "Architecture" -Value $Win32OperatingSystem.Architecture
    $CS | Add-Member NoteProperty -Name "Version" -Value $Win32OperatingSystem.Version
    $CS | Add-Member NoteProperty -Name "Organization" -Value $Win32OperatingSystem.Organization
    $CS | Add-Member NoteProperty -Name "RegisteredUser" -Value $Win32OperatingSystem.RegisteredUser
    $CS | Add-Member NoteProperty -Name "InstallDate" -Value $Win32OperatingSystem.InstallDate
    $CS | Add-Member NoteProperty -Name "WindowsDirectory" -Value $Win32OperatingSystem.WindowsDirectory
    $CS | Add-Member NoteProperty -Name "OSLanguage" -Value $Win32OperatingSystem.OSLanguage
    $CS | Add-Member NoteProperty -Name "TimeZoneName" -Value $Win32TimeZone.Caption
    $CS | Add-Member NoteProperty -Name "OSDiskSizeinGB" -Value $([Math]::Round($(Get-Volume -DriveLetter $($($Win32OperatingSystem.WindowsDirectory).Split(":")[0])).Size/1GB))
    $CS | Add-Member NoteProperty -Name "OSDiskSizeRemaninginGB" -Value $([Math]::Round($(Get-Volume -DriveLetter $($($Win32OperatingSystem.WindowsDirectory).split(":")[0])).SizeRemaining/1GB))
    $CS | Add-Member NoteProperty -Name "DomainFirewallProfileEnabled" -Value ($NetFirewallProfile | Where-Object Name -EQ Domain).Enabled
    $CS | Add-Member NoteProperty -Name "OSDiskBitlocker" -Value $OSDiskBitlocker
    $CS | Add-Member NoteProperty -Name "IsServerOS" -Value $LocalInfo.IsServerOS
    $CS | Add-Member NoteProperty -Name "IPAddress" -Value $([system.String]::Join(" ", $LocalInfo.IPAddress))
    $CS | Add-Member NoteProperty -Name "OSCurrentBuild" -Value $LocalInfo.OSCurrentBuild
    $CS | Add-Member NoteProperty -Name "MacAddress" -Value $([system.String]::Join(" ", $LocalInfo.MacAddress))
    $CS | Add-Member NoteProperty -Name "ComputerFirmwareType" -Value $LocalInfo.SetupMode
    $CS | Add-Member NoteProperty -Name "UEFI" -Value $LocalInfo.IsUEFI
    $CS | Add-Member NoteProperty -Name "OSCurrentVersion" -Value $LocalInfo.OSCurrentVersion
    $CS | Add-Member NoteProperty -Name "ProcessorSpeed" -Value $LocalInfo.ProcessorSpeed
    $CS | Add-Member NoteProperty -Name "SupportsSLAT" -Value $LocalInfo.SupportsSLAT
    $CS | Add-Member NoteProperty -Name "DefaultGateway" -Value $([system.String]::Join(" ", $LocalInfo.DefaultGateway))
    $CS | Add-Member NoteProperty -Name "IsServerCoreOS" -Value $LocalInfo.IsServerCoreOS
    $CS | Add-Member NoteProperty -Name "SerialNumber" -Value $LocalInfo.SerialNumber
    $CS | Add-Member NoteProperty -Name "WUAHistoryLastStatus" -Value $WUAHistoryLast.Result
    $CS | Add-Member NoteProperty -Name "WUAHistoryLastDate" -Value $WUAHistoryLast.Date
    $CS | Add-Member NoteProperty -Name "Uptime" -Value $SystemUpTime.Uptime
    $CS | Add-Member NoteProperty -Name "TPMChip" -Value $LocalInfo.TPM
    $CS | Add-Member NoteProperty -Name "BMC" -Value $BMCIPV4Addr
    
    Export-TSxData -obj $CS -Path $OutPath -Name ComputerSystem
    
}
catch{
        Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect physical memory information
#---------------------------------------------------------------------
Write-Verbose "Collecting physical memory information"
try{
    $memorybanks = @()
    $Win32PhysicalMemory = @(Get-WmiObject Win32_PhysicalMemory -ErrorAction STOP |
        Select-Object DeviceLocator,Manufacturer,Speed,Capacity)

    foreach ($bank in $Win32PhysicalMemory)
    {
        $memObject = New-Object PSObject
        $memObject | Add-Member NoteProperty -Name "TSSystemID" -Value $env:COMPUTERNAME
        $memObject | Add-Member NoteProperty -Name "Device Locator" -Value $bank.DeviceLocator
        $memObject | Add-Member NoteProperty -Name "Manufacturer" -Value $bank.Manufacturer
        $memObject | Add-Member NoteProperty -Name "Speed" -Value $bank.Speed
        $memObject | Add-Member NoteProperty -Name "Capacity (GB)" -Value ("{0:F0}" -f $bank.Capacity/1GB)
        $memorybanks += $memObject
    }

    Export-TSxData -obj $memorybanks -Path $OutPath -Name Memory
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect pagefile information
#---------------------------------------------------------------------
Write-Verbose "Collecting pagefile information"
try{
    $Win32PageFileUsage = Get-WmiObject Win32_PageFileUsage -ErrorAction STOP |
        Select-Object @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},
                      @{Name='Pagefile Name';Expression={$_.Name}},
                      @{Name='Allocated Size (Mb)';Expression={$_.AllocatedBaseSize}}

    Export-TSxData -obj $Win32PageFileUsage -Path $OutPath -Name PageFileUsage
}
catch{
    Write-Warning $_.Exception.Message
}


#---------------------------------------------------------------------
# Collect BIOS information and convert to HTML fragment
#---------------------------------------------------------------------
Write-Verbose "Collecting BIOS information"
try{
    $Win32Bios = Get-WmiObject Win32_Bios -ErrorAction STOP |
        Select-Object @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},
                      Status,Version,Manufacturer,
                      @{Name='Release Date';Expression={
                        $releasedate = [datetime]::ParseExact($_.ReleaseDate.SubString(0,8),"yyyyMMdd",$null);
                        $releasedate.ToShortDateString()
                      }},
                      @{Name='Serial Number';Expression={$_.SerialNumber}}

    Export-TSxData -obj $Win32Bios -Path $OutPath -Name BIOS
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect logical disk information and convert to HTML fragment
#---------------------------------------------------------------------
Write-Verbose "Collecting logical disk information"
try{
    $Win32LogicalDisk = Get-WmiObject Win32_LogicalDisk -ErrorAction STOP | 
        Select-Object   @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},
                        DeviceID,FileSystem,VolumeName,
                        @{Expression={$_.Size /1Gb -as [int]};Label="Total Size (GB)"},
                        @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"}

    Export-TSxData -obj $Win32LogicalDisk -Path $OutPath -Name LogicalDisk
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect volume information and convert to HTML fragment
#---------------------------------------------------------------------
Write-Verbose "Collecting volume information"
try{
   
    $Win32Volume = Get-WmiObject Win32_Volume -ErrorAction STOP | 
        Select-Object   @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},
                        Label,Name,DeviceID,SystemVolume,
                        @{Expression={$_.Capacity /1Gb -as [int]};Label="Total Size (GB)"},
                        @{Expression={$_.Freespace / 1Gb -as [int]};Label="Free Space (GB)"}

    Export-TSxData -obj $Win32Volume -Path $OutPath -Name Volume
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect network interface information and convert to HTML fragment
#---------------------------------------------------------------------    
Write-Verbose "Collecting network interface information"
try{
    $nics = @()
    $Win32NetworkAdapters = @(Get-WmiObject Win32_NetworkAdapter -ErrorAction STOP | Where {$_.PhysicalAdapter} |
        Select-Object Name,AdapterType,MACAddress,
        @{Name='ConnectionName';Expression={$_.NetConnectionID}},
        @{Name='Enabled';Expression={$_.NetEnabled}},
        @{Name='Speed';Expression={$_.Speed/1000000}})

    $Win32NetworkAdapterConfiguration = Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction STOP |
        Select-Object Description, DHCPServer,  
        @{Name='IpAddress';Expression={$_.IpAddress -join '; '}},  
        @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}},  
        @{Name='DefaultIPgateway';Expression={$_.DefaultIPgateway -join '; '}},  
        @{Name='DNSServerSearchOrder';Expression={$_.DNSServerSearchOrder -join '; '}}

    foreach ($Win32NetworkAdapter in $Win32NetworkAdapters){
        $Win32NetworkAdapterObject = New-Object PSObject
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "TSSystemID" -Value $env:COMPUTERNAME
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "Connection Name" -Value $Win32NetworkAdapter.connectionname
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "Adapter Name" -Value $Win32NetworkAdapter.Name
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "Type" -Value $Win32NetworkAdapter.AdapterType
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "MAC" -Value $Win32NetworkAdapter.MACAddress
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "Enabled" -Value $Win32NetworkAdapter.Enabled
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "Speed (Mbps)" -Value $Win32NetworkAdapter.Speed
        
        $ipaddress = ($Win32NetworkAdapterConfiguration | Where {$_.Description -eq $Win32NetworkAdapter.Name}).IpAddress
        $Win32NetworkAdapterObject | Add-Member NoteProperty -Name "IPAddress" -Value $ipaddress

        $nics += $Win32NetworkAdapterObject

        Export-TSxData -obj $nics -Path $OutPath -Name Network
    }
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect software information and convert to HTML fragment
#---------------------------------------------------------------------
Write-Verbose "Collecting software information"
try{
    $Win32Product = Get-WmiObject Win32_Product -ErrorAction STOP | 
        Select-Object   @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},
                        Vendor,Name,Version | Sort-Object Vendor,Name

    Export-TSxData -obj $Win32Product -Path $OutPath -Name Applications
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect local admins
#---------------------------------------------------------------------
Write-Verbose "Collect local admins"
try{
    $AdministratorsGroup = Get-CimInstance -ClassName win32_group -Filter "name = 'administrators'" | Get-CimAssociatedInstance -Association win32_groupuser
    $Localadmins = $AdministratorsGroup.caption | foreach {[PSCustomObject] @{TSSystemID=$env:COMPUTERNAME;Account = $_}}

    Export-TSxData -obj $localadmins -Path $OutPath -Name localadmins
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect local shares
#---------------------------------------------------------------------
Write-Verbose "Collect local shares"
try{
    $LocalFileShares = Get-WmiObject Win32_share | Where {$_.name -NotLike "*$"} |
        Select-Object   @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},Name,Path,Description

    Export-TSxData -obj $LocalFileShares -Path $OutPath -Name FileShares
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect local UserProfiles
#---------------------------------------------------------------------
Write-Verbose "Collect local profiles"
try{
    $LocalUserProfiles = Get-WmiObject -Class win32_userprofile -Filter "Special='False'" | 
        Select-Object @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},LocalPath,SID,RoamingConfigured,
        @{Name='LastUsed';Expression={$_.ConvertToDateTime($_.LastUseTime)}
        }

    Export-TSxData -obj $LocalUserProfiles -Path $OutPath -Name LocalUserProfiles
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect Toolkit Flag
#---------------------------------------------------------------------
Write-Verbose "Collect Toolkit Flag"
try{
    if(Test-Path -Path HKLM:\SOFTWARE\HydrationKit){
                
    }
    else{
        
    }

    $LocalFileShares = Get-WmiObject Win32_share | Where {$_.name -NotLike "*$"} |
        Select-Object   @{Name='TSSystemID';Expression={$env:COMPUTERNAME}},Name,Path,Description

    Export-TSxData -obj $LocalFileShares -Path $OutPath -Name FileShares
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect local users
#---------------------------------------------------------------------
Write-Verbose "Collect local users"
try{
    $LocalUsers = Get-WmiObject -Class "Win32_UserAccount" -filter {LocalAccount = True } | foreach {
             $strADSI =[ADSI]"WinNT://localhost/$($_.Name),user"
                 $intPasswordAge = $strADSI.PasswordAge[0] / 86400
                 $strLastLogin = $strADSI.LastLogin[0]
                 $intMaxPasswordAge = $strADSI.MaxPasswordAge[0] / 86400
             If ($intPasswordAge -gt $intMaxPasswordAge){
             $strPasswordStatus = "Password has Expired"
             }
             Else {
             $strPasswordStatus = "Password will expire in " + [Math]::Round($intMaxPasswordAge - $intPasswordAge) + " days."
             } 
 
             $strPasswordData = New-Object -TypeName PSObject
             $strPasswordData | Add-Member -TypeName NoteProperty -Name TSSystemID -Value $env:COMPUTERNAME
             $strPasswordData | Add-Member -TypeName NoteProperty -Name Username -Value $_.Name 
             $strPasswordData | Add-Member -TypeName NoteProperty -Name AccountType -Value $_.AccountType 
             $strPasswordData | Add-Member -TypeName NoteProperty -Name Disabled -Value $_.Disabled 
             $strPasswordData | Add-Member -TypeName NoteProperty -Name Lockout -Value $_.Lockout 
             $strPasswordData | Add-Member -TypeName NoteProperty -Name Status -Value $_.Status 
             $strPasswordData | Add-Member -TypeName NoteProperty -Name PasswordRequired -Value $_.PasswordRequired
             $strPasswordData | Add-Member -TypeName NoteProperty -Name PasswordChangeable -Value $_.PasswordChangeable
             $strPasswordData | Add-Member -TypeName NoteProperty -Name PasswordSet -Value ((Get-Date).AddSeconds(-$intPasswordAge)) 
             $strPasswordData | Add-Member -TypeName NoteProperty -Name PasswordAge -Value ([Math]::Round($intPasswordAge))
             $strPasswordData | Add-Member -TypeName NoteProperty -Name MaxPasswordAge -Value ([Math]::Round($intMaxPasswordAge ))
             $strPasswordData | Add-Member -TypeName NoteProperty -Name PasswordStatus -Value $strPasswordStatus
             $strPasswordData | Add-Member -TypeName NoteProperty -Name LastLogin -Value $strLastLogin
             $strPasswordData
    }

    Export-TSxData -obj $LocalUsers -Path $OutPath -Name LocalUsers
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect roles and features
#---------------------------------------------------------------------
Write-Verbose "Collect roles and features"
try{
    
    $RolesandFeatures = Get-WindowsFeature | Where-Object InstallState -EQ Installed
    $RolesandFeaturesData = foreach($RolesandFeature in $RolesandFeatures){
        $CS = New-Object PSObject
        $CS | Add-Member NoteProperty -Name "TSSystemID" -Value $env:COMPUTERNAME
        $CS | Add-Member NoteProperty -Name "RoleOrFeature" -Value $([system.String]::Join(" ", $RolesandFeature.DisplayName))
        $CS
    }

    Export-TSxData -obj $RolesandFeaturesData -Path $OutPath -Name RolesandFeatures
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect Logons
#---------------------------------------------------------------------
Write-Verbose "Collect Logons"
try{
    $RDPAuths = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
    [xml[]]$xml=$RDPAuths | Foreach{$_.ToXml()}

    $LogonsData = Foreach ($event in $xml.Event){
        $LD = New-Object PSObject
        $LD | Add-Member NoteProperty -Name "TSSystemID" -Value $env:COMPUTERNAME
        $LD | Add-Member NoteProperty -Name "TimeCreated" -value $((Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm:ss K'))
        $LD | Add-Member NoteProperty -Name "User" -Value $event.UserData.EventXML.Param1
        $LD | Add-Member NoteProperty -Name "Domain" -Value $event.UserData.EventXML.Param2
        $LD | Add-Member NoteProperty -Name "Client" -Value $event.UserData.EventXML.Param3
        $LD
    }

    Export-TSxData -obj $LogonsData -Path $OutPath -Name Logons
}
catch{
    Write-Warning $_.Exception.Message
}

#---------------------------------------------------------------------
# Collect Console PowerShell History
#---------------------------------------------------------------------
Write-Verbose "Console PowerShell History"
try{
    $ConsoleHistory = New-Object System.Collections.Generic.List[object]
    $ProfilePaths = Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {$_.GetValue('ProfileImagePath')}
    foreach($dutt in $ProfilePaths) {
        $ConsoleFile = Get-ChildItem -Path $dutt -Recurse -Force -File ConsoleHost_history.txt -ErrorAction Ignore
        if($ConsoleFile.count -eq "1"){
            $Content = Get-Content -Path $ConsoleFile.FullName
            foreach($item in $Content){
                $CPH = New-Object PSObject
                $CPH | Add-Member NoteProperty -Name "TSSystemID" -Value $env:COMPUTERNAME
                $CPH | Add-Member NoteProperty -Name "User" -Value $($dutt | Split-Path -Leaf)
                $CPH | Add-Member NoteProperty -Name "Command" -Value $item
                $ConsoleHistory.Add($CPH)
            }
        }
    }
    Export-TSxData -obj $ConsoleHistory -Path $OutPath -Name ConsolePowerShellHistory
}
catch{
    Write-Warning $_.Exception.Message
}
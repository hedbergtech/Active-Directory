Param(
    $CustomerName = "ViaMonstra",
    $SourceFolderPath = "E:\Kurt",
    $DestinationPath = "E:\KurtReport",
)


$DataFiles = @(
"BIOSInformation",
"ComputerInformation",
"ConsolePowerShellHistoryInformation",
"DefenderInformation",
"LocalAdminInformation",
"LocalShareInformation",
"LocalUserInformation",
"LogicalDiskInformation",
"NetworkInformation",
"PagefileInformation",
"PhysicalMemoryInformation",
"RDPLoginInformation",
"RolesAndFeaturesInformation",
"SoftwareInformation",
"UserProfileInformation",
"VolumeInformation"
)

New-Item -Path $DestinationPath -ItemType Directory -Force -ErrorAction Stop
New-Item -Path $DestinationPath\$CustomerName -ItemType Directory -Force -ErrorAction Stop

foreach ($DataFile in $DataFiles){
    Write-Verbose -Message "Working on $DataFile" -Verbose
    $Content = "*$DataFile*"
    $Result = foreach($Item in (Get-ChildItem -Path $SourceFolderPath -Recurse -Filter $Content)){
        Get-Content -Path $Item.FullName | ConvertFrom-Csv
    }
    $Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath "$DestinationPath\$CustomerName\$DataFile.csv" -Encoding ascii
}

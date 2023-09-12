# 
$CustName = "ViaMonstra"
$DataPath = "E:\Kurt"
$ReportPath = "E:\KurtReport"

# Get ComputerInfo
$Content = "*ComputerInformation*"
$OutputFile = "$ReportPath\ComputerSystem$CustName.csv"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}

$Selection = $Result | Out-GridView -PassThru
$Selection | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSComputers$CustName.csv -Encoding ascii

$Content = "*Applications*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSApplications$CustName.csv -Encoding ascii

$Content = "*Memory*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSMemory$CustName.csv -Encoding ascii

$Content = "*FileShare*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSFileShare$CustName.csv -Encoding ascii

$Content = "*localadmins*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Sort-Object -Property Account -Unique | Out-GridView -PassThru
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSLocalAdmins$CustName.csv -Encoding ascii


$Content = "*localuserprofiles*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSLocalUserProfiles$CustName.csv -Encoding ascii

$Content = "*RolesandFeatures*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru | Select-Object -Unique
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSLocalUsers$CustName.csv -Encoding ascii

$Content = "*PowerShellHistory*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru | Select-Object -Unique
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSLocalUsers$CustName.csv -Encoding ascii

$Content = "*Logons*"
$Result = foreach($DataFile in (Get-ChildItem -Path $DataPath -Recurse -Filter $Content)){
    Get-Content -Path $DataFile.FullName | ConvertFrom-Csv
}
$Result | Out-GridView -PassThru | Select-Object -Unique
$Result | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath C:\TS\Reports\TSLocalUsers$CustName.csv -Encoding ascii





C:\TS\Reports\TSComputers.csv



foreach($computer in $Selection.Name){
    Invoke-Command -ComputerName $computer -ScriptBlock {Hostname}
}

$VMhosts = Get-ADComputer -Filter * -SearchBase "OU=VirtualMachineHostServers,OU=Servers,OU=Tier0,OU=Admin,DC=ha-ad,DC=net"
$result = foreach($VMhost in $hosts){
    Get-VM -ComputerName $VMhost.Name | Select Name,Computername
}
$result | Out-GridView -PassThru

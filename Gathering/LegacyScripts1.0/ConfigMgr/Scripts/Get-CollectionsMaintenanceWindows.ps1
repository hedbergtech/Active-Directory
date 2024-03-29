<#
.Synopsis
   This script creates Collections Maintenance Windows REPORT
.DESCRIPTION
.EXAMPLE
    Get-CollectionsMaintenanceWindows.ps1 -SiteCode PR1 -SiteServer Localhost -CSV -output c:\scripts\Collections\CollectionsMaintenanceWindows.csv
.EXAMPLE
    Get-CollectionsMaintenanceWindows.ps1 -SiteCode PR1 -SiteServer Localhost -HTML -output c:\scripts\Collections\CollectionsMaintenanceWindows.HTML
.NOTES
    Developed by Kaido Järvemets
    Version 2.0

#>
[CMDLETBINDING()]
Param(
    [Parameter(Mandatory=$True,HelpMessage="Please Enter CM SiteCode",ParameterSetName='HTML')]
    [Parameter(Mandatory=$True,HelpMessage="Please Enter CM SiteCode",ParameterSetName='CSV')]
        $SiteCode,
    [Parameter(Mandatory=$True,HelpMessage="Please Enter CM Site Server",ParameterSetName='HTML')]
    [Parameter(Mandatory=$True,HelpMessage="Please Enter CM Site Server",ParameterSetName='CSV')]
        $SiteServer,
    [Parameter(Mandatory=$True,ParameterSetName='CSV')]
        [Switch]$CSV,
    [Parameter(Mandatory=$True,ParameterSetName='HTML')]
        [Switch]$HTML,
    [Parameter(Mandatory=$True,HelpMessage="Please specify file location",ParameterSetName='HTML')]
    [Parameter(Mandatory=$True,HelpMessage="Please specify file location",ParameterSetName='CSV')]
        $OutPut
)

Function Convert-DayNumbersToDayName {
    [CmdletBinding()]
    Param(
        [String]$DayNumber
    )
        
    Switch ($DayNumber) {
        "1" {$DayName = "Sunday"}
        "2" {$DayName = "Monday"}
        "3" {$DayName = "Tuesday"}
        "4" {$DayName = "Wednesday"}
        "5" {$DayName = "Thursday"}
        "6" {$DayName = "Friday"}
        "7" {$DayName = "Saturday"}
    }
    Return $DayName
}
Function Convert-MonthToNumbers {
    [CmdletBinding()]
    Param(
        [String]$MonthNumber
    )
        
    Switch ($MonthNumber) {
        "1" {$MonthName = "January"}
        "2" {$MonthName = "Feburary"}
        "3" {$MonthName = "March"}
        "4" {$MonthName = "April"}
        "5" {$MonthName = "May"}
        "6" {$MonthName = "June"}
        "7" {$MonthName = "July"}
        "8" {$MonthName = "August"}
        "9" {$MonthName = "September"}
        "10" {$MonthName = "October"}
        "11" {$MonthName = "November"} 
        "12" {$MonthName = "December"}
    }
    Return $MonthName
}

Function Convert-WeekOrderNumber {
    [CmdletBinding()]
    Param(
        [String]$WeekOrderNumber
    )
        
    Switch ($WeekOrderNumber) {
        0 {$WeekOrderName = "Last"}
        1 {$WeekOrderName = "First"}
        2 {$WeekOrderName = "Second"}
        3 {$WeekOrderName = "Third"}
        4 {$WeekOrderName = "Fourth"}
    }
    Return $WeekOrderName
}

Function Convert-CMMWType {
    [CmdletBinding()]
    Param(
        [String]$MWType
    )
       
    Switch ($MWType) {
        1 {$MWTypeText = "General"}
        5 {$MWTypeText = "OSD"}
    }
    Return $MWTypeText
}

Function Convert-ScheduleString {
    Param(
        $ScheduleString,
        $SiteCode,
        $SiteServer
    )
     
    $Class = "SMS_ScheduleMethods"
    $Method = "ReadFromString"
    $Colon = ":"
    $WMIConnection = [WMIClass]"\\$SiteServer\root\SMS\Site_$SiteCode$Colon$Class"
    $String = $WMIConnection.psbase.GetMethodParameters($Method)
    $String.StringData = $ScheduleString
    $ScheduleData = $WMIConnection.psbase.InvokeMethod($Method,$String,$null)
    $ScheduleClass = $ScheduleData.TokenData

    switch($ScheduleClass[0].__CLASS) {
        "SMS_ST_RecurWeekly" {
            $ContentValidationShedule = "Occurs every: $($ScheduleClass[0].ForNumberOfWeeks) weeks on " + (Convert-DayNumbersToDayName -DayNumber $ScheduleClass[0].Day)
            Return $ContentValidationShedule
        }
        "SMS_ST_RecurInterval" {
            $ContentValidationShedule = "Occures every $($ScheduleClass[0].DaySpan) days"
            Return $ContentValidationShedule
        }
        "SMS_ST_RecurMonthlyByDate" {
            If($ScheduleClass[0].MonthDay -eq 0) {
                $ContentValidationShedule = "Occures the last day of every " + (Convert-MonthToNumbers -MonthNumber $ScheduleClass[0].ForNumberOfMonths)
                Return $ContentValidationShedule
            }
            Else {
                $ContentValidationShedule = "Occures day $($ScheduleClass[0].MonthDay) of every " + (Convert-MonthToNumbers -MonthNumber $ScheduleClass[0].ForNumberOfMonths)
                Return $ContentValidationShedule
            }
        }
       "SMS_ST_RecurMonthlyByWeekday" {
            $ContentValidationShedule = "Occures the " + (Convert-WeekOrderNumber -weekordernumber $ScheduleClass[0].WeekOrder) + " " + (Convert-DayNumbersToDayName -DayNumber $ScheduleClass[0].Day) + " of every " + (Convert-MonthToNumbers -MonthNumber $ScheduleClass[0].ForNumberOfMonths)
            Return $ContentValidationShedule
        }                 
      "SMS_ST_NonRecurring" {
            $ContentValidationShedule = "No Schedule"
            Return $ContentValidationShedule
        }
     }
}

$EmptyArray = @()
$ColSettingsQuery = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class "SMS_CollectionSettings" -ErrorAction STOP -ComputerName $SiteServer

foreach($Item in $ColSettingsQuery) {
    $Item.Get()
    $ColName = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class "SMS_Collection" -Filter "CollectionID='$($Item.CollectionID)'"-ErrorAction STOP -ComputerName $SiteServer
    Foreach($MW in $Item.ServiceWindows) {
        if($MW.Count -ne 0){
            $DObject = New-Object PSObject
            $DObject | Add-Member -MemberType NoteProperty -Name "Collection Name" -Value $($ColName.Name)
            $DObject | Add-Member -MemberType NoteProperty -Name "CollectionID" -Value $($Item.CollectionID)
            $DObject | Add-Member -MemberType NoteProperty -Name "Start Date" -Value (Get-Date ([System.Management.ManagementDateTimeConverter]::ToDateTime($MW.StartTime)) -Format "dd.MM.yyyy H:mm")
            $DObject | Add-Member -MemberType NoteProperty -Name "Duration in minutes" -Value ($MW.Duration) 
            $DObject | Add-Member -MemberType NoteProperty -Name "Maintenance Window Name" -Value $($MW.Name)
            $DObject | Add-Member -MemberType NoteProperty -Name "Maintenance Window Date/Time" -Value (Convert-ScheduleString -SiteCode $SiteCode -SiteServer $SiteServer -ScheduleString $MW.ServiceWindowSchedules)
            $DObject | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $($MW.IsEnabled)
            $DObject | Add-Member -MemberType NoteProperty -Name "Type" -Value (Convert-CMMWType -MWType $MW.ServiceWindowType)
            $EmptyArray += $DObject
        }
    }
}  
    
If($CSV) {
    Try {
        $EmptyArray | Export-Csv $OutPut -NoTypeInformation -ErrorAction Stop
    }
    Catch {
        Write-Host "Failed to export CSV to $OutPut"
    }
}

If($HTML) {
    $CurrentDate = Get-Date

    #HTML style
    $HeadStyle = "<style>"
    $HeadStyle = $HeadStyle + "BODY{background-color:peachpuff;}"
    $HeadStyle = $HeadStyle + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
    $HeadStyle = $HeadStyle + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
    $HeadStyle = $HeadStyle + "TD{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
    $HeadStyle = $HeadStyle + "</style>"   

    Try {
        $EmptyArray | ConvertTo-Html -Head $HeadStyle -Body "<h2>Maintenance Windows Date/Time Report: $CurrentDate</h2>" -ErrorAction STOP | Out-File $OutPut
    }
    Catch {
        Write-Host "Failed to export HTML to $OutPut"
    }
}
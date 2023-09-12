﻿<#
.Synopsis
   This script reads Collection Refresh Schedule date/time
.DESCRIPTION
.EXAMPLE
    Get-CollectionsRefreshSchedules.ps1 -SiteCode PR1 -SiteServer Localhost -CSV -output c:\scripts\Collections\CollectionRefresh.csv
.EXAMPLE
    Get-CollectionsRefreshSchedules.ps1 -SiteCode PR1 -SiteServer Localhost -HTML -output c:\scripts\Collections\CollectionRefresh.HTML
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

$Collections = @()
$RefreshScheduleCollection = @()
Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Query "Select * from SMS_Collection where CollectionID like '$SiteCode%'" -ComputerName $SiteServer | ForEach-Object {$Collections +=[WMI]$_.__PATH}

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

foreach($item in $Collections) {
    $DObject = New-Object PSObject
    $DObject | Add-Member -MemberType NoteProperty -Name "Collection Name" -Value $item.Name
    
    if($item.RefreshType -eq 1){
        $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType
        $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value "NO Date"
        $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value "NO Time"
        $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
    }
    Else {
        switch($item.RefreshSchedule.__CLASS) {
            "SMS_ST_RecurWeekly" {
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value ("Occures every: $($item.RefreshSchedule.ForNumberOfWeeks) weeks on " + (Convert-DayNumbersToDayName -DayNumber $item.RefreshSchedule.Day))
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value ([System.Management.ManagementDateTimeConverter]::ToDateTime($item.RefreshSchedule.StartTime))
                $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
            }
           "SMS_ST_RecurInterval" {
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType

                if($item.RefreshSchedule.DaySpan -ne 0){
                    $text = "Occures every $($item.RefreshSchedule.DaySpan) days"
                }
                if($item.RefreshSchedule.HourSpan -ne 0){
                    $text = "Occures every $($item.RefreshSchedule.HourSpan) hours"
                }
                if($item.RefreshSchedule.MinuteSpan -ne 0){
                    $text = "Occures every $($item.RefreshSchedule.MinuteSpan) minutes"
                }
                
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value $text
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value ([System.Management.ManagementDateTimeConverter]::ToDateTime($item.RefreshSchedule.StartTime))
                $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
            }
           "SMS_ST_RecurMonthlyByDate" {
                If ($item.RefreshSchedule.MonthDay -eq 0) {
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value "Occures the last day of every $($item.RefreshSchedule.ForNumberOfMonths) months"
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value ([System.Management.ManagementDateTimeConverter]::ToDateTime($item.RefreshSchedule.StartTime))
                $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
                }
                Else {
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value "Occures day $($item.RefreshSchedule.MonthDay) of every $($item.RefreshSchedule.ForNumberOfMonths) months"
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value ([System.Management.ManagementDateTimeConverter]::ToDateTime($item.RefreshSchedule.StartTime))
                $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
                }
            }
           "SMS_ST_RecurMonthlyByWeekday" {
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value ("Occures the " + (Convert-WeekOrderNumber -weekordernumber $item.RefreshSchedule.WeekOrder) + " " + (Convert-DayNumbersToDayName -DayNumber $item.RefreshSchedule.Day) + " of every " + (Convert-MonthToNumbers -MonthNumber $item.RefreshSchedule.ForNumberOfMonths))
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value ([System.Management.ManagementDateTimeConverter]::ToDateTime($item.RefreshSchedule.StartTime))
                $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
            }                 
           "SMS_ST_NonRecurring" {
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Type" -Value $item.RefreshType
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Date" -Value "No Recurrence. The Scheduled event Occures once at the specific time"
                $DObject | Add-Member -MemberType NoteProperty -Name "Refresh Time" -Value ([System.Management.ManagementDateTimeConverter]::ToDateTime($item.RefreshSchedule.StartTime))
                $DObject | Add-Member -MemberType NoteProperty -Name "Limiting Collection Name" -Value $item.LimitToCollectionName
            }              
         }
    }
    $RefreshScheduleCollection += $DObject
}

If($CSV) {
    Try {
        $RefreshScheduleCollection | Export-Csv $OutPut -NoTypeInformation -ErrorAction Stop
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
        $RefreshScheduleCollection | ConvertTo-Html -Head $HeadStyle -Body "<h2>Collections Refresh Schedule Date/Time Report: $CurrentDate</h2>" -ErrorAction STOP | Out-File $OutPut
    }
    Catch {
        Write-Host "Failed to export HTML to $OutPut"
    }
}
<#
    .SYNOPSIS
        Check for detections by Azure Ad Password Protection agent, and add users to $ADgroup
    
    .DESCRIPTION
        Check for detections by Azure Ad Password Protection agent, and add users to $ADgroup
        Need Microsoft-AzureADPasswordProtection-DCAgent installed on domain controllers
        Need an $ADGroup to keep track of detected users
        Need sufficient rights in AD. Domain admin or delegated on Microsoft-AzureADPasswordProtection-DCAgent/Admin

    .PARAMETER Output
        $True to force output to screen

    .PARAMETER Hours
        Number of hours to evaluate from eventlog

    .NOTES
        Author: Bard Holtbakk
        Version 1.2 - Cleanup
        Version 1.1 - Swapped days for hours
        Version 1.0 - Added logging to file
        Version 0.9 - Added Try/Catch for domain controllers

    .EXAMPLE
        Run the script and output to screen. Evaluate data from past 14 days
        .\check-aadpp-events-enforce.ps1 -Output:$True -Hours:336

        Run the script with no output. Evaluate data from past 24 hours
        .\check-aadpp-events-enforce.ps1 -Hours:24
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$False)]
    [ValidateSet($False,$True)]
    [Bool]$Output = $False,

    [Parameter(Mandatory=$False)]
    [ValidateRange(1,8760)]
    [Int]$Hours = 12
)

BEGIN {

    # Initiate timer
    $StartScript = Get-Date
    # Modify this to match your AD group name
    $ADGroup = "SG-Users-AzureAdPasswordProtection-Detected"
    # Modify this to retrieve all domain controllers
    Try { $DomainControllers = (Get-ADComputer -SearchBase "OU=Domain Controllers,DC=NMBU,DC=NO" -Filter *).Name } Catch { Write-Host -ForegroundColor Red "Domain controllers unreachable!" ; break }
    # Table of event ids to monitor
    $EventIds = @('30009')

}

PROCESS {

    # Fetch relevant log events
    $PasswordEvents = $DomainControllers | ForEach-Object { 
        Get-WinEvent -FilterHashtable @{
            ProviderName = 'Microsoft-AzureADPasswordProtection-DCAgent'
            LogName = 'Microsoft-AzureADPasswordProtection-DCAgent/Admin'
            Id = $EventIds
            StartTime =  (Get-Date).AddHours(-$Hours)
            EndTime = Get-Date
        } -ComputerName $_ -ErrorAction SilentlyContinue 
    } | Select-Object Id,TimeCreated,Message | Sort-Object TimeCreated

    # Checking if DomainControllers and $ADGroup are accessable
    If (($DomainControllers) -and ($DomainControllers.Count -ge "1") -and (Get-ADGroup -Filter "Name -eq '$($ADGroup)'")) {

        if ($Output) { Write-Host -ForegroundColor Yellow Fetching old users from group and evaluating logs for new events. Checking $Hours hours. }

        # Add all users from $ADGroup to a hashtable
        $UsersFromGroup = foreach ($Member in (Get-ADGroupMember -Identity $($ADGroup))) {
            New-Object PSCustomObject -Property @{ UserName = $Member.SamAccountName ; TimeCreated = (Get-Date).AddHours(-$Hours) }
        }

        # Add all users from WinEvent to a hashtable from the last $Hours
        #$UsersFromEvents = foreach ($Event in $PasswordEvents | Where-object TimeCreated -gt (Get-Date).AddHours(-$Hours)) {
        $UsersFromEvents = foreach ($Event in $PasswordEvents) {
            If ($Event.Id -in $EventIds) {
                $ThisUserName = (($event.Message.Split("UserName: "))[1].Split("FullName: ")[0]).Trim()
                $ThisTimeCreated = $Event.TimeCreated
                New-Object PSCustomObject -Property @{ UserName = $ThisUserName ; TimeCreated = $ThisTimeCreated }
            }
        }
        
        # Merging hashtable
        $InsecureUsers = $UsersFromGroup + $UsersFromEvents
        
        # Remove duplicates from hashtable. Keep the latest TimeCreated row for each user
        $InsecureUsers = $InsecureUsers | Group-Object UserName | ForEach-Object { $_.Group | Sort-Object TimeCreated | Select-Object -last 1 }

        # Loop through and check latest timestamp against PasswordLastSet in AD for each user Get-Aduser -Identity $User.UserName -Properties PasswordLastSet
        ForEach ($User in $InsecureUsers) {
            If ($CheckUser = Get-ADUser -Filter "CN -eq '$($User.UserName)'" -Properties PasswordLastSet,Enabled) {
                If ($CheckUser.Enabled -eq 'True') {
                    If ([datetime]($CheckUser).PasswordLastSet -gt [datetime](get-date -Date $User.TimeCreated)) {
                        If ($User.UserName -In $UsersFromGroup.UserName) {
                            if ($Output) { write-host -ForegroundColor Green "User HAS changed password after latest risk detection, removing from group => $($User.UserName)"  }
                            Remove-ADGroupMember -Identity $ADGroup -Members $User.UserName -Confirm:$False
                            [pscustomobject]@{Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") ; Action = 'Removed' ; User = "$($User.UserName)" } | Export-Csv -Encoding UTF8 -Path ($MyInvocation.MyCommand.Name).replace('ps1','log') -Append -NoTypeInformation
                        }
                        Else {
                            if ($Output) { write-host -ForegroundColor Green "User HAS changed password after latest risk detection, but not in group => $($User.UserName)"  }
                        }
                    }
                    Else {
                        If (-not ($User.UserName -In $UsersFromGroup.UserName)) {
                            if ($Output) { Write-Host -ForegroundColor Red "User has NOT changed password after latest risk detection, adding to group => $($User.UserName)" } 
                            Add-ADGroupMember -Identity $ADGroup -Members $User.UserName
                            [pscustomobject]@{Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") ; Action = 'Added' ; User = "$($User.UserName)" } | Export-Csv -Encoding UTF8 -Path ($MyInvocation.MyCommand.Name).replace('ps1','log') -Append -NoTypeInformation
                        }
                        Else {
                            if ($Output) { Write-Host -ForegroundColor Red "User has NOT changed password after latest risk detection, but already in group => $($User.UserName)" }
                        }
                    }
                } 
                Else {
                    If ($User.UserName -In $UsersFromGroup.UserName) {
                        if ($Output) { Write-Host -ForegroundColor Cyan "User is not enabled in AD, removing from group => $($User.UserName)" }
                        Remove-ADGroupMember -Identity $ADGroup -Members $User.UserName -Confirm:$False
                        [pscustomobject]@{Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") ; Action = 'Removed inactive' ; User = "$($User.UserName)" } | Export-Csv -Encoding UTF8 -Path ($MyInvocation.MyCommand.Name).replace('ps1','log') -Append -NoTypeInformation
                    }
                    Else {
                        if ($Output) { Write-Host -ForegroundColor Cyan "User is not enabled in AD, but not in group => $($User.UserName)" }
                    }
                }
            }
            Else {
                if ($Output) { Write-Host -ForegroundColor Cyan "User do no longer exist, do nothing => $($User.UserName)" }
            }
        }

    }
    Else {
        Write-Host -ForegroundColor Red "Error - Domain controllers unreachable or AD group does not exist!"
    }

}

END {

    $EndScript = Get-Date
    if ($Output) { Write-Host -ForegroundColor Yellow "Script executed in $(($EndScript-$StartScript).minutes) minutes and $(($EndScript-$StartScript).seconds) seconds and $(($EndScript-$StartScript).milliseconds) milliseconds." }

}

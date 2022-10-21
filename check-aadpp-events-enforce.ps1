<#
    .SYNOPSIS
        Check for detections by Azure Ad Password Protection agent, and add users to $ADgroup
    
    .DESCRIPTION
        Check for detections by Azure Ad Password Protection agent, and add users to $ADgroup
        Version 0.9
        Need Microsoft-AzureADPasswordProtection-DCAgent installed on DCs
        Need $ADGroup to keep track of detected users.
        Need sufficient rights in AD
S
    .PARAMETER Output
        $True to force output to screen

    .PARAMETER Days
        Number of days to evaluate from eventlog

    .NOTES
        Author: Bard Holtbakk
        Todo: Use Compare-Object to update $ADGroup rather than -clear and repopulate
        Todo: Use Try to fetch DCs by Get-ADComputer block
        Todo: Log to file

    .EXAMPLE
        Run the script and output to screen. Evaluate data from past 7 days
        .\check-aadpp-events-enforce.ps1 -Output:$True -Days:7
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$False)]
    [ValidateSet($False,$True)]
    [Bool]$Output = $False,

    [Parameter(Mandatory=$False)]
    [ValidateRange(1,99)]
    [Int]$Days = 3
)

BEGIN {
    # Initiate timer
    $StartScript = Get-Date
    # Modify this to match your AD group name
    $ADGroup = "SG-Users-AzureAdPasswordProtection-Detected"
    # Modify this to retrieve all domain controllers
    $DomainControllers = (Get-ADComputer -SearchBase "OU=Domain Controllers,DC=NMBU,DC=NO" -Filter *).Name
}

PROCESS {

    # Fetch relevant log events
    $PasswordEvents = $DomainControllers | ForEach-Object { 
        Get-WinEvent -FilterHashtable @{
            ProviderName = 'Microsoft-AzureADPasswordProtection-DCAgent'
            LogName = 'Microsoft-AzureADPasswordProtection-DCAgent/Admin'
            Id = 30008,30007,30010,30009,30029,30028,10024,10025
            StartTime =  (Get-Date).AddDays(-$Days)
            EndTime = Get-Date
        } -ComputerName $_ -ErrorAction SilentlyContinue 
    } | Select-Object Id,TimeCreated,Message | Sort-Object TimeCreated

    # Checking if DomainControllers and $ADGroup are accessable
    If (($DomainControllers) -and ($DomainControllers.Count -ge "1") -and (Get-ADGroup -Filter "Name -eq '$($ADGroup)'")) {

        if ($Output) { Write-Host -ForegroundColor Yellow Fetching old users from group and evaluating logs for new events. Checking $Days days. }

        # Add all users from $ADGroup to a hashtable
        $UsersFromGroup = foreach ($Member in (Get-ADGroupMember -Identity $($ADGroup))) {
            New-Object PSCustomObject -Property @{ UserName = $Member.SamAccountName ; TimeCreated = (Get-Date).AddDays(-$Days) }
        }

        # Add all users from WinEvent to a hashtable from the last $Days
        $UsersFromEvents = foreach ($Event in $PasswordEvents | Where-object TimeCreated -gt (Get-Date).AddDays(-$Days)) {
            If ($Event.Id -eq "30009") {
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
        $NoDuplciatesBackToGroup = foreach ($User in $InsecureUsers) {
            If ($CheckUser = Get-ADUser -Filter "CN -eq '$($User.UserName)' -and Enabled -eq 'True'" -Properties PasswordLastSet) {
                If ([datetime]($CheckUser).PasswordLastSet -gt [datetime](get-date -Date $User.TimeCreated)) {
                    if ($Output) { write-host -ForegroundColor Green "User HAS changed password after latest risk detection => $($User.UserName)"  }
                    # Log - Remove user from Group.
                }
                Else {
                    if ($Output) { Write-Host -ForegroundColor Red "User has NOT changed password after latest risk detection => $($User.UserName)" }
                    $User
                    # Log - Add/keep user to Group.
                }
            } 
            Else {
                if ($Output) { Write-Host -ForegroundColor Cyan "User does not exist or is not enabled in AD => $($User.UserName)" }
                # Log - User does not exist. Remove.
            }
        }
        
        # Clearing group members
        if ($Output) { Write-Host -ForegroundColor Yellow Truncating the AD group. }
        Get-ADGroup $($ADGroup) | Set-ADGroup -Clear member

        # Adding users back
        if ($Output) { Write-Host -ForegroundColor Yellow Populating the AD group with $NoDuplciatesBackToGroup.Count users. }
        foreach ($User in $NoDuplciatesBackToGroup) {
            Add-ADGroupMember -Identity $($ADGroup) -Members $($User.UserName)
        }
    }
    Else {
        Write-Host -ForegroundColor Red "Error - DCs unreachable or non-existing AD group!"
    }
}

END {
    $EndScript = Get-Date
    if ($Output) { Write-Host -ForegroundColor Yellow "Script executed in $(($EndScript-$StartScript).minutes) minutes and $(($EndScript-$StartScript).seconds) seconds and $(($EndScript-$StartScript).milliseconds) milliseconds." }
}

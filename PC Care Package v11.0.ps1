###########################
## Administrative Rights ##
###########################


write-Host "***Requesting elevated permissions***" -ForegroundColor Green -BackgroundColor Black
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}


######################
## Define Functions ##
######################


function DrawMenu {
    ## Support function to the Menu function
    param ($menuItems, $menuPosition, $menuTitle)
    $l = $menuItems.length + 1
    cls
    $menuwidth = $menuTitle.length + 4
    write-Host "`t" -NoNewLine
    write-Host ("*" * $menuwidth) -fore Cyan -back Black
    write-Host "`t" -NoNewLine
    write-Host "* $menuTitle *" -fore Cyan -back Black
    write-Host "`t" -NoNewLine
    write-Host ("*" * $menuwidth) -fore Cyan -back Black
    write-Host ""
    write-debug "L: $l MenuItems: $menuItems MenuPosition: $menuposition"
    for ($i = 0; $i -le $l;$i++) {
        Write-Host "`t" -NoNewLine
        if ($i -eq $menuPosition) {
            Write-Host "$($menuItems[$i])" -fore Black -back Cyan
        } else {
            Write-Host "$($menuItems[$i])" -fore Cyan -back Black
        }
    }
}

function Menu {
    ## Generate a small "DOS-like" menu.
    ## Choose a menu item using up and down arrows, select by pressing ENTER
    param ([array]$menuItems, $menuTitle = "MENU")
    $vkeycode = 0
    $pos = 0
    DrawMenu $menuItems $pos $menuTitle
    While ($vkeycode -ne 13) {
        $press = $host.ui.rawui.readkey("NoEcho,IncludeKeyDown")
        $vkeycode = $press.virtualkeycode
        write-Host "$($press.character)" -NoNewLine
        If ($vkeycode -eq 38) {$pos--}
        If ($vkeycode -eq 40) {$pos++}
        if ($pos -lt 0) {$pos = 0}
        if ($pos -ge $menuItems.length) {$pos = $menuItems.length -1}
        DrawMenu $menuItems $pos $menuTitle
    }
    Write-Output $($menuItems[$pos])
}

function RegSetUser {
    ## Disable start menu suggestions
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SystemPaneSuggestionsEnabled" /D 0 /F
    ## Disable lockscreen suggestions, rotating pictures
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SoftLandingEnabled" /D 0 /F
    ## Disables preinstalled apps; Minecraft, Twitter, etc. - W10 Enterprise only
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "PreInstalledAppsEnabled" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "PreInstalledAppsEverEnabled" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "OEMPreInstalledAppsEnabled" /D 0 /F
    ## Stops MS from quietly installing apps
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SilentInstalledAppsEnabled" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "ContentDeliveryAllowed" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /T REG_DWORD /V "SubscribedContentEnabled" /D 0 /F
    ## Disable ads in File Explorer
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "ShowSyncProviderNotifications" /D 0 /F

    ## Don't let apps share and sync non-explicitly paired wireless devices over uPnP
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /T REG_SZ /V "Value" /D DENY /F
    
    ## Don't ask for feedback
        reg add "$reglocation\SOFTWARE\Microsoft\Siuf\Rules" /T REG_DWORD /V "NumberOfSIUFInPeriod" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Siuf\Rules" /T REG_DWORD /V "PeriodInNanoSeconds" /D 0 /F
    
    ## Privacy settings
        reg add "$reglocation\SOFTWARE\Microsoft\Personalization\Settings" /T REG_DWORD /V "AcceptedPrivacyPolicy" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /T REG_DWORD /V "Enabled" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\InputPersonalization" /T REG_DWORD /V "RestrictImplicitTextCollection" /D 1 /F
        reg add "$reglocation\SOFTWARE\Microsoft\InputPersonalization" /T REG_DWORD /V "RestrictImplicitInkCollection" /D 1 /F
        reg add "$reglocation\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /T REG_DWORD /V "HarvestContacts" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Input\TIPC" /T REG_DWORD /V "Enabled" /D 0 /F
    
    ## Disable Bing search user settings
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "BingSearchEnabled" /D 0 /F
        reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /T REG_DWORD /V "DeviceHistoryEnabled" /D 0 /F
}

function loaddefaulthive {
    ## Loads "Default" user profile
        reg load "$reglocation" c:\users\default\ntuser.dat
}

function unloaddefaulthive {
    ## Unloads "Default" user profile
        [gc]::collect()
        reg unload "$reglocation"
}


#########################
## Begin Menu Sequence ##
#########################

## Menu Usage Example: 
## $activatemenu = "No","Yes"
## $activate = Menu $activatemenu "Activate Windows?" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
## if ($activate -match "Yes") {
##    Do This
## }


#########################
## Management Settings ##
#########################


## Rename Computer
write-Host "Input new computer name:" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
write-Host " " -NoNewline
$newComputerName = Read-Host
if ($newComputerName -notlike $env:computername) {
    write-Host "***Renaming computer***" -ForegroundColor Green -BackgroundColor Black
    Rename-Computer -NewName $newComputerName
}
else {
    write-Host "That's already the name of this computer!" -ForegroundColor Green -BackgroundColor Black
    Start-Sleep -S 2
}

## Local ISCadmin user definition
$Username = "iscadmin"
write-Host "Please input desired password for local user $Username" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
write-Host ":" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
write-Host " " -NoNewline
$SecurePassword = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
write-Host "Please confirm password:" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
write-Host " " -NoNewline
$SecurePassword2 = Read-Host -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword2)
$Password2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
cls
while ($Password -notlike $Password2) {
    write-Host "Those passwords didn't match. Please try again." -ForegroundColor Green -BackgroundColor Black
    write-Host "Please input desired password for local user $Username" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
    write-Host ":" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
    write-Host " " -NoNewline
    $SecurePassword = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    write-Host "Please confirm password:" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
    write-Host " " -NoNewline
    $SecurePassword2 = Read-Host -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword2)
    $Password2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    cls
}

## Creates local ISCAdmin and sets password to never expire
$group = "Administrators"
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$existing = $adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username }
if ($existing -eq $null) {
    write-Host "***Creating local user $Username***" -ForegroundColor Green -BackgroundColor Black
    & NET USER $Username $Password /add /y /expires:never

    write-Host "***Adding local user $Username to $group***" -ForegroundColor Green -BackgroundColor Black -NoNewline
    & NET LOCALGROUP $group $Username /add
}
else {
    write-Host "***Setting password for existing local user $Username***" -ForegroundColor Green -BackgroundColor Black
    $existing.SetPassword($Password)
}

write-Host "***Setting password for $Username to never expire***" -ForegroundColor Green -BackgroundColor Black
& WMIC USERACCOUNT WHERE "Name='$Username'" SET PasswordExpires=FALSE
}

## Sets PC to not auto-reboot on crash
write-Host "***Setting policy for no auto-reboot on BSOD***" -ForegroundColor Green -BackgroundColor Black
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /t REG_DWORD /v AutoReboot /d 0 /f


#######################
## Explorer Settings ##
#######################


write-Host "***Cutting '- Shortcut' from new shortcuts***" -ForegroundColor Green -BackgroundColor Black
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ -Name NamingTemplates -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name "ShortcutNameTemplate" -PropertyType "String" -Value '%s.lnk'

write-Host "***Showing file extensions in Windows Explorer***" -ForegroundColor Green -BackgroundColor Black
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty $key HideFileExt 0
    Set-ItemProperty $key ShowMenus 1
    Stop-Process -processname explorer

write-Host "***Changing default Explorer view to 'This PC'***" -ForegroundColor Green -BackgroundColor Black
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1


####################
## Power Settings ##
####################


write-Host "***Disabling hibernate***" -ForegroundColor Green -BackgroundColor Black
    Start-Process 'powercfg.exe' -Verb runAs -ArgumentList '/h off'

write-Host "***Disabling standby/sleep on AC power***" -ForegroundColor Green -BackgroundColor Black
    powercfg -change -standby-timeout-ac 0

write-Host "***Disabling Fast-Boot***" -ForegroundColor Green -BackgroundColor Black
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /t REG_DWORD /v HiberbootEnabled /d 0 /f


##################
## Junk Cleanup ##
##################


## Disable "Consumer features" and silent install of apps
write-Host "***Setting up the advertising dumpster***" -ForegroundColor Green -BackgroundColor Black
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /t REG_DWORD /v DisableWindowsConsumerFeatures /d 1 /f #pre-anniversary update
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /t REG_DWORD /v SilentInstalledAppsEnabled /d 0 /f #post-anniversary update

## Removes most "junk apps" and prevents all from being installed on new profiles (exclusions listed)
write-Host "***Taking out the trash***" -ForegroundColor Green -BackgroundColor Black
    Get-AppxPackage -AllUsers | where-object {$_.name -notlike "*Store*" -and $_.name -notlike "*Dell*" -and $_.name -notlike "*HP*" -and $_.name -notlike "*Calculator*" -and $_.name -notlike "*Windows.Photos*" -and $_.name -notlike "*SoundRecorder*" -and $_.name -notlike "*MSPaint*" -and $_.name -notlike "*Calendar*" -and $_.name -notlike "*windowscommunicationsapps" -and $_.name -notlike "*Camera*"} | Remove-AppxPackage -erroraction silentlycontinue
    Get-AppxProvisionedPackage -online | where-object {$_.displayname -notlike "*Store*" -and $_.displayname -notlike "*Dell*" -and $_.displayname -notlike "*HP*" -and $_.displayname -notlike "*Calculator*" -and $_.displayname -notlike "*Windows.Photos*" -and $_.displayname -notlike "*SoundRecorder*"  -and $_.displayname -notlike "*MSPaint*" -and $_.displayname -notlike "*Calendar*" -and $_.displayname -notlike "*windowscommunicationsapps" -and $_.name -notlike "*Camera*"} | Remove-AppxProvisionedPackage -online -erroraction silentlycontinue

write-Host "***Disabling 'Featured Software'***" -ForegroundColor Green -BackgroundColor Black
    reg add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /T REG_DWORD /V "EnableFeaturedSoftware" /D 0 /F

write-Host "***Disabling Xbox DVR***" -ForegroundColor Green -BackgroundColor Black
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
	    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0


##################
## System Setup ##
##################


write-Host "***Setting registry for current and default user, and policies for local machine***"  -ForegroundColor Green -BackgroundColor Black
    $reglocation = "HKCU"
    regsetuser
    $reglocation = "HKLM\AllProfile"
    loaddefaulthive; regsetuser; unloaddefaulthive
    $reglocation = $null

write-Host "***Enabling SmartScreen Services***" -ForegroundColor Green -BackgroundColor Black
    reg add "$reglocation\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /T REG_DWORD /V "EnableWebContentEvaluation" /D 1 /F

write-Host "***Disabling Diagnostics Tracking Services, Xbox Services, Distributed Link Tracking, and WMP Network Sharing***" -ForegroundColor Green -BackgroundColor Black
    Get-Service Diagtrack,DmwApPushService,OneSyncSvc,XblAuthManager,XblGameSave,XboxNetApiSvc,WMPNetworkSvc | stop-service -passthru | set-service -startuptype disabled

write-Host "***Enabling RDP Access***" -ForegroundColor Green -BackgroundColor Black
    set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 

write-Host "***Setting Time Zone to EST***" -ForegroundColor Green -BackgroundColor Black
    tzutil.exe /s "Eastern Standard Time"

write-Host "***Setting Privacy Options***" -ForegroundColor Green -BackgroundColor Black			
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass\UserAuthPolicy" /t REG_DWORD /v Enabled /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /t REG_DWORD /v AllowExperimentation /d 0 /f
    reg add	"HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /T REG_DWORD /V "DoNotTrack" /D 1 /F
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /t REG_DWORD /v Enabled /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /t REG_DWORD /v Enabled /d 0  /f
    reg add "HKCU\Control Panel\International\User Profile" /t REG_DWORD /v HttpAcceptLanguageOptOut /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /t REG_SZ /v Value /d DENY /f
    reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /t REG_DWORD /v AcceptedPrivacyPolicy /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /t REG_DWORD /v Enabled /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /t REG_DWORD /v RestrictImplicitTextCollection /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /t REG_DWORD /v RestrictImplicitInkCollection /d 1 /f
    reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /t REG_DWORD /v HarvestContacts /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /t REG_DWORD /v NumberOfSIUFInPeriod /d 0 /f

write-Host "***Stopping and Disabling Diagnostics Tracking Services***" -ForegroundColor Green -BackgroundColor Black
    get-service Diagtrack,DmwApPushService,OneSyncSvc,XblAuthManager,XblGameSave,XboxNetApiSvc,TrkWks,WMPNetworkSvc | stop-service -passthru | set-service -startuptype disabled

write-Host "***Disabling Advertising ID***" -ForegroundColor Green -BackgroundColor Black
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

write-Host "***Disabling Suggested Apps, Feedback, and Lockscreen Spotlight***" -ForegroundColor Green -BackgroundColor Black
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" /t REG_DWORD /v SystemPaneSuggestionsEnabled /d 0 /f
    reg add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\SoftLandingEnabled" /t REG_DWORD /v SoftLandingEnabled /d 0 /f
    reg add "HKCU\Software\Microsoft\CurrentVersion\ContentDeliveryManager\" /t REG_DWORD /v RotatingLockScreenEnable /d 0 /f

write-Host "***Disabling Delivery Optimization***" -ForegroundColor Green -BackgroundColor Black
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /t REG_DWORD /v DODownloadMode /d 0 /f
    reg add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /t REG_DWORD /v "DODownloadMode" /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /t REG_DWORD /v SystemSettingsDownloadMode /d 3 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f	
    
write-Host "***Disabling Telemetry***" -ForegroundColor Green -BackgroundColor Black
    reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /t REG_DWORD /v AllowTelemetry /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f

## Enables old F8 boot options
write-Host "***Enabling F8 boot menu options***" -ForegroundColor Green -BackgroundColor Black
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

## Sets PWSH Script policy back to default of "undefined"
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Undefined -Force

write-Host "       _____________                   ____                  " -ForegroundColor Green -BackgroundColor Black
write-Host "      /  _/ __/ ___/__  ___  ___ __ __/ / /_ _ __  ___ _     " -ForegroundColor Green -BackgroundColor Black
write-Host "     _/ /_\ \/ /__/ _ \/ _ \(_-</ // / / __/ / _ \/ _ '/     " -ForegroundColor Green -BackgroundColor Black
write-Host "    /___/___/\___/\___/_//_/___/\___/_/\__/_/_//_/\_, /      " -ForegroundColor Green -BackgroundColor Black
write-Host "                     Business Computer Solutions /___/       " -ForegroundColor Green -BackgroundColor Black
write-Host "                                                             " -ForegroundColor Black -BackgroundColor Black
write-Host "      Don't forget to run updates and install LOB apps       " -ForegroundColor Cyan -BackgroundColor Black
write-Host "      Startup and Recovery options also need to be set.      " -ForegroundColor Cyan -BackgroundColor Black
write-Host "      Please finish any running installations and restart.   " -ForegroundColor Cyan -BackgroundColor Black
write-Host "            *******(Press any key to exit)*******            " -ForegroundColor White -BackgroundColor Black -NoNewline

$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
sysdm.cpl /,3
Exit

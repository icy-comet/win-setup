$AsciiArt = "
  __  ____  _ ____    _  _  __  __ _       ____  ____  ____  _  _  ____
 / _\(_  _)(// ___)  / )( \(  )(  ( \ ___ / ___)(  __)(_  _)/ )( \(  _ \
/    \ )(    \___ \  \ /\ / )( /    /(___)\___ \ ) _)   )(  ) \/ ( ) __/
\_/\_/(__)   (____/  (_/\_)(__)\_)__)     (____/(____) (__) \____/(__)
"

$border = "==============================================="

Write-Host $border
Write-Host $AsciiArt
Write-Host $border

$ErrorActionPreference = 'SilentlyContinue'

Start-Transcript -Path "~\Desktop\setup_log.txt"

# Check if ran-as-admin otherwise exit
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "Please run the script with Administrator privileges."
    pause
    Exit
}

function CreateRestorePoint {
    Write-Host "Creating a Restore Point..."
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
    Write-Host "Created Restore Point. Moving on..."
}

function InstallCustomSoftware {

    $listFile = "setup_apps.txt"

    If(!Test-Path $listFile) {
        Write-Host "Didn't find the list of apps to install. Skipping apps installation..."
        exit
    }

    If (!Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
        Write-Host "Winget not found."
        Write-Host "Installing winget..."

        Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
        $nid = (Get-Process AppInstaller).Id
        Wait-Process -Id $nid
    }

    If (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
        Write-Host "Found winget. Installing apps..."

        Write-Host "Starting Installing Apps..."

        $appsToInstall = Get-Content $listFile | Select-Object -Skip 2

        ForEach ($app in $appsToInstall) {
            $app = $app.Trim()

            Write-Host "Installing $app..."

            winget install --accept-package-agreements --accept-source-agreements --exact $app | Out-Host

            If ($?) { Write-Host "Installed $app. Moving on..." }
        }

        Write-Host "Finished installing apps. Moving on..."
    } Else {
        Write-Host "Couldn't find/install winget. Skipping apps installation..."
    }
}

# sycnex
function DisableUnnecessaryTasks {
    # Disables scheduled tasks that are considered unnecessary
    Write-Host "Disabling unnecessary scheduled tasks..."
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask  DmClient | Disable-ScheduledTask
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask
    Write-Host "Disabled unnecessary scheduled tasks. Moving on..."
}

function EnableUnnecessaryTasks {
    # Re-enables scheduled tasks that were disabled when running the Debloat switch
    Write-Host "Enabling unnecessary scheduled tasks..."
    Get-ScheduledTask XblGameSaveTaskLogon | Enable-ScheduledTask
    Get-ScheduledTask XblGameSaveTask | Enable-ScheduledTask
    Get-ScheduledTask Consolidator | Enable-ScheduledTask
    Get-ScheduledTask UsbCeip | Enable-ScheduledTask
    Get-ScheduledTask DmClient | Enable-ScheduledTask
    Get-ScheduledTask DmClientOnScenarioDownload | Enable-ScheduledTask
}

function EnableDataCollection {
    Write-Host "Enabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1

    # sycnex undo (custom)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1

    Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

    Write-Host "Enabled Telemetry. Moving on..."
    Write-Host "Enabling Error Reporting..."

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

    Write-Host "Enabled Error Reporting. Moving on..."
    Write-Host "Enabling Diagnostics Tracking Service..."

    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Manual

    Write-Host "Enabled Diagnostics Tracking Service. Moving on..."

    # sycnex
    Write-Host "Enabling Windows Feedback Experience Program..."
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 1
        Write-Host "Enabled Windows Feedback Experience program. Moving on..."
    }

    # sycnex
    Write-Host "Enabling Windows Feedback Experience Program to send Anonymous data..."
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) {
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 1
    Write-Host "Enabled Windows Feedback Experience Program to send Anonymous data. Moving on..."
}

function DisableDataCollection {
    Write-Host "Disabling Telemetry..."

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

    # sycnex
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

    Write-Host "Disabled Telemetry. Moving on..."
    Write-Host "Disabling Error Reporting..."

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

    Write-Host "Disabled Error Reporting. Moving on..."
    Write-Host "Stopping and Disabling Diagnostics Tracking Service..."

    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled

    Write-Host "Disabled Diagnostics Tracking Service. Moving on..."

    # sycnex
    Write-Host "Disabling Windows Feedback Experience program..."
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0
        Write-Host "Disabled Windows Feedback Experience program. Moving on..."
    }

    # sycnex
    Write-Host "Stopping Windows Feedback Experience Program from sending Anonymous data..."
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) {
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0
    Write-Host "Stopped Windows Feedback Experience Program from sending Anonymous data. Moving on..."
}

function UpdateExplorerDefaultLocation {
    Write-Host "Updating Explorer's default open location to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Write-Host "Explorer's default location updated. Moving on..."
}

function RevertExplorerDefaultLocation {
    Write-Host "Updating Explorer's default open location to stock setting..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 0
    Write-Host "Explorer's default location updated. Moving on..."
}

# sycnex
function Hide3DObjectsInExplorer {
    # Removes 3D Objects from the 'My Computer' submenu in explorer
    Write-Host "Removing 3D Objects from explorer 'My Computer' submenu"
    $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    If (Test-Path $Objects32) {
        Remove-Item $Objects32 -Recurse
    }
    If (Test-Path $Objects64) {
        Remove-Item $Objects64 -Recurse
    }
}

function Unhide3DObjectsInExplorer {
    # Restores 3D Objects from the 'My Computer' submenu in explorer
    Write-Host "Restoring 3D Objects from explorer 'My Computer' submenu"
    $Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    $Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    If (!(Test-Path $Objects32)) {
        New-Item $Objects32
    }
    If (!(Test-Path $Objects64)) {
        New-Item $Objects64
    }
}

function DisableWifiSense {
    Write-Host "Disabling Wi-Fi Sense..."

    If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }

    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

    # sycnex
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0

    Write-Host "Disabled Wi-Fi Sense. Moving on..."
}

function EnableWifiSense {
    Write-Host "Enabling Wifi Sense..."

    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
    # sycnex
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 1

    Write-Host "Enabled Wifi Sense. Moving on..."
}

function DisableAppSuggestions {
    Write-Host "Disabling Application suggestions..."

    $OEMRegistry = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $OEMRegistry -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path $OEMRegistry -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

    Write-Host "Disabled Application Suggestions. Moving on..."

    Write-Host "Stoppping Windows UWP Apps from Returning..."

    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

    Write-Host "Windows UWP Apps Stopped from Returning. Moving on..."
}

function EnableAppSuggestions {
    Write-Host "Enabling Application suggestions..."

    $OEMRegistry = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $OEMRegistry -Name "ContentDeliveryAllowed" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-338387Enabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "SubscribedContent-353698Enabled" -Type DWord -Value 1
    Set-ItemProperty -Path $OEMRegistry -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1

    Write-Host "Enabled Application Suggestions. Moving on..."

    Write-Host "Allowing Windows UWP Apps to return..."

    If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent") {
        Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Recurse -ErrorAction SilentlyContinue
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 0
    Write-Host "Allowed Windows UWP Apps to return. Moving on..."
}

function DisableUserActivityHistory {
    Write-Host "Disabling Activity History..."

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-ItemProperty -Path $path -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path $path -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path $path -Name "UploadUserActivities" -Type DWord -Value 0

    Write-Host "Disabled Activity History. Moving on..."
}

function EnableUserActivityHistory {
    Write-Host "Enabling Activity History..."

    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-ItemProperty -Path $path -Name "EnableActivityFeed" -Type DWord -Value 1
    Set-ItemProperty -Path $path -Name "PublishUserActivities" -Type DWord -Value 1
    Set-ItemProperty -Path $path -Name "UploadUserActivities" -Type DWord -Value 1

    Write-Host "Enabled Activity History. Moving on..."
}

function HideTasksViewBtn {
    Write-Host "Hiding Tasks View button..."

    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

    Write-Host "Hid Tasks View Button. Moving on..."
}

function UnhideTasksViewBtn {
    Write-Host "Hiding Tasks View button..."

    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 1

    Write-Host "Hid Tasks View Button. Moving on..."
}

function HideMeetNowBtn {
    Write-Host "Hiding Meet Now Button..."

    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }

    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

    Write-Host "Hid Meet Now Button. Moving on..."
}

function UnhideMeetNowBtn {
    Write-Host "Unhiding Meet Now Button..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 0
    Write-Host "Unhid Meet Now Button. Moving on..."
}

function ShowExpolorerFileExtensions {
    Write-Host "Unhiding file extensions in Explorer..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    Write-Host "Unhid file extensions in Explorer. Moving on..."
}

function HideExpolorerFileExtensions {
    Write-Host "Unhiding file extensions in Explorer..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
    Write-Host "Unhid file extensions in Explorer. Moving on..."
}

function SetBIOSTimeToUTC {
    Write-Host "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host "Set BIOS time to UTC. Moving on..."
}

function SetBIOSTimeToLocal {
    Write-Host "Setting BIOS time to local..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 0
    Write-Host "Set BIOS time to local. Moving on..."
}

function DisableWebSearchInMenu {
    # sycnex
    Write-Host "Disabling Web Search in Start Menu..."
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1
    Write-Host "Disabled Web Search in Start Menu. Moving on..."
}

function EnableWebSearchInMenu {
    # sycnex
    Write-Host "Enabling Web Search in Start Menu..."
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 1
    Set-ItemProperty $WebSearch DisableWebSearch -Value 0
    Write-Host "Enabled Web Search in Start Menu. Moving on..."
}

function HideNewsAndInterests {
    Write-Host "Hiding News and Interests Button..."

    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2

    Write-Host "Hid News and Interests Button. Moving on..."
}

function UnhideNewsAndInterests {
    Write-Host "Unhiding News and Interests Button..."

    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 1
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 0

    Write-Host "Unhid News and Interests Button. Moving on..."
}

function HideSearchButtonAndBox {
    Write-Host "Hiding Search Box / Button..."

    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

    Write-Host "Hid Search Box / Button. Moving on..."
}

function UnhideSearchButtonAndBox {
    Write-Host "Unhiding Search Box / Button..."

    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1

    Write-Host "Unhid Search Box / Button. Moving on..."
}

# sycnex
function StopEdgePDF {

    #Stops edge from taking over as the default .PDF viewer
    Write-Host "Stopping Edge from taking over as the default .PDF viewer..."
    $NoPDF = "HKCR:\.pdf"
    $NoProgids = "HKCR:\.pdf\OpenWithProgids"
    $NoWithList = "HKCR:\.pdf\OpenWithList"
    If (!(Get-ItemProperty $NoPDF  NoOpenWith)) {
        New-ItemProperty $NoPDF NoOpenWith
    }
    If (!(Get-ItemProperty $NoPDF  NoStaticDefaultVerb)) {
        New-ItemProperty $NoPDF  NoStaticDefaultVerb
    }
    If (!(Get-ItemProperty $NoProgids  NoOpenWith)) {
        New-ItemProperty $NoProgids  NoOpenWith
    }
    If (!(Get-ItemProperty $NoProgids  NoStaticDefaultVerb)) {
        New-ItemProperty $NoProgids  NoStaticDefaultVerb
    }
    If (!(Get-ItemProperty $NoWithList  NoOpenWith)) {
        New-ItemProperty $NoWithList  NoOpenWith
    }
    If (!(Get-ItemProperty $NoWithList  NoStaticDefaultVerb)) {
        New-ItemProperty $NoWithList  NoStaticDefaultVerb
    }

    #Appends an underscore '_' to the Registry key for Edge
    $Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
    If (Test-Path $Edge) {
        Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_
    }
}

function AllowEdgePDF {
    Write-Host "Setting Edge back to default"
    $NoPDF = "HKCR:\.pdf"
    $NoProgids = "HKCR:\.pdf\OpenWithProgids"
    $NoWithList = "HKCR:\.pdf\OpenWithList"
    #Sets edge back to default
    If (Get-ItemProperty $NoPDF NoOpenWith) {
        Remove-ItemProperty $NoPDF NoOpenWith
    }
    If (Get-ItemProperty $NoPDF NoStaticDefaultVerb) {
        Remove-ItemProperty $NoPDF NoStaticDefaultVerb
    }
    If (Get-ItemProperty $NoProgids NoOpenWith) {
        Remove-ItemProperty $NoProgids NoOpenWith
    }
    If (Get-ItemProperty $NoProgids NoStaticDefaultVerb) {
        Remove-ItemProperty $NoProgids NoStaticDefaultVerb
    }
    If (Get-ItemProperty $NoWithList NoOpenWith) {
        Remove-ItemProperty $NoWithList NoOpenWith
    }
    If (Get-ItemProperty $NoWithList NoStaticDefaultVerb) {
        Remove-ItemProperty $NoWithList NoStaticDefaultVerb
    }

    #Removes an underscore '_' from the Registry key for Edge
    $Edge2 = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
    If (Test-Path $Edge2) {
        Set-Item $Edge2 AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723
    }
}

function UninstallBloatware {
    $Bloatware = @(
    # Unnecessary Windows 10 AppX Apps
    "Microsoft.3DBuilder"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.AppConnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.MinecraftUWP"
    "Microsoft.GamingServices"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.XboxApp"
    "Microsoft.ConnectivityStore"
    "Microsoft.CommsPhone"
    "Microsoft.ScreenSketch"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.YourPhone"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"

    # Sponsored Windows 10 AppX Apps
    # Add sponsored/featured apps to remove in the "*AppName*" format
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
    "*Viber*"
    "*ACGMediaPlayer*"
    "*Netflix*"
    "*OneCalendar*"
    "*LinkedInforWindows*"
    "*HiddenCityMysteryofShadows*"
    "*Hulu*"
    "*HiddenCity*"
    "*AdobePhotoshopExpress*"
    "*AutodeskSketchBook*"
    "*DisneyMagicKingdoms*"
    "*DragonManiaLegends*"
    "*MarchofEmpires*"
    "*Amazon*"
    "*Dropbox*"
    "*Plex*"
    "*FarmVille2CountryEscape*"
    "*CyberLinkMediaSuiteEssentials*"
    "*DrawboardPDF*"
    "*FitbitCoach*"
    "*RoyalRevolt2*"
    "*Asphalt8Airborne*"
    "*Keeper*"
    "*FarmHeroesSaga*"
    "*CookingFever*"
    "*SpotifyMusic*"
    "*PhototasticCollage*"
    "*WinZipUniversal*"
    "*HotspotShieldFreeVPN*"
    )

    Write-Host "Removing Bloatware..."

    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
    }

    Write-Host "Finished Removing Bloatware. Moving on..."
}

function EnableCollapsibleTray {
    Write-Host "Enabling Collapsible Tray..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 1
    Write-Host "Enabled Collapsible Tray. Moving on..."
}

function DisableCollapsibleTray {
    Write-Host "Disabling Collapsible Tray..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
    Write-Host "Disabled Collapsible Tray. Moving on..."
}

function OptimizeCDrive {
    Write-Host "Optimizing C Drive..."
    Optimize-Volume -DriveLetter "C"
    Write-Host "Optimized C Drive. Moving on..."
}

function OptimizeNetworking {
    $services = @(
    "SSDPSRV"
    "FDPHOST"
    "FDResPub"
    "upnphost"
    )

    Write-Host "Optimizing Networking Settings..."

    foreach ($service in $services) {
        Write-Host "Setting $service StartupType to Automatic"
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
    }

    Write-Host "Optimized Network Settings. Moving on..."
}

function RevertNetworkingOptimization {
    $services = @(
    "SSDPSRV"
    "FDPHOST"
    "FDResPub"
    "upnphost"
    )

    Write-Host "Reverting Networking Optimizations..."

    foreach ($service in $services) {
        Write-Host "Setting $service StartupType to Manual"
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual
    }

    Write-Host "Reverted Network Optimizations. Moving on..."
}

function Set12HrTimeFormat {
    Write-Host "Changing Time Format..."
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortTime" -Type String -Value "hh:mm tt"
    Write-Host "Changed Time Format. Moving on..."
}

function SetTZIndia {
    Write-Host "Setting Time Zone to India..."
    Set-TimeZone -Id "India Standard Time"
    Write-Host "Update Time Zone. Moving on..."
}

function HideDesktopIcons {
    Write-Host "Hiding Desktop Icons..."

    # User Files Icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 1

    # This Pc Icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 1

    # Control Panel Icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 1

    Write-Host "Hid Desktop Icons. Moving on..."
}

function UnhideDesktopIcons {
    Write-Host "Unhiding Desktop Icons..."

    # User Files Icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0

    # This Pc Icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0

    # Control Panel Icon
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0

    Write-Host "Desktop Icons Set. Moving on..."
}

function SetPCName {
    Write-Host "Changing PC Name..."
    Rename-Computer -NewName "MyPc"
    Write-Host "Changed PC Name. Moving on..."
}

# # sycnex
# function HidePeopleIcon {
#     Write-Host "Hiding People icon on Taskbar"
#     $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
#     If (Test-Path $People) {
#         Set-ItemProperty $People -Name PeopleBand -Value 0
#     }
#     Write-Host "Hid People icon on Taskbar. Moving on..."
# }

# # sycnex
# function UnhidePeopleIcon {
#     Write-Host "Unhiding People icon on Taskbar..."
#     $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
#     If (Test-Path $People) {
#         Set-ItemProperty $People -Name PeopleBand -Value 0
#     }
#     Write-Host "Unhid People icon on Taskbar. Moving on..."
# }

# Disassembler0
# Enable Firewall
function EnableFirewall {
    Write-Host "Enabling Firewall..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}

# Disassembler0
# Disable Firewall
function DisableFirewall {
    Write-Host "Disabling Firewall..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}

# Disassembler0
function EnableAutorun {
    Write-Host "Enabling Autorun for all drives..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    Write-Host "Enabled Autorun for all drives. Moving on..."
}

# Disassembler0
function DisableAutorun {
    Write-Host "Disabling Autorun for all drives..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
    Write-Host "Disabled Autorun for all drives. Moving on..."
}

# Disassembler0
function EnableIndexing {
    Write-Host "Starting and Enabling Windows Search Indexing service..."
    Set-Service "WSearch" -StartupType Automatic
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
    Start-Service "WSearch" -WarningAction SilentlyContinue
    Write-Host "Enabled Windows Search Indexing Service. Moving on..."
}

# Disassembler0
function DisableIndexing {
    Write-Host "Stopping and Disabling Windows Search Indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    Write-Host "Disabled Windows Search Indexing. Moving on..."
}

# Disassembler0
function EnableNTFSLongPaths {
    Write-Host "Enabling NTFS paths with length over 260 characters..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1
}

# Disassembler0
function DisableNTFSLongPaths {
    Write-Host "Disabling NTFS paths with length over 260 characters..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 0
}

# Disassembler0
function EnableFastStartup {
    Write-Host "Enabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
    Write-Host "Enabled Fast Startup. Moving on..."
}

# Disassembler0
function DisableFastStartup {
    Write-Host "Disabling Fast Startup..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
    Write-Host "Disabled Fast Startup. Moving on..."
}

# Disassembler0
function EnableSearchAppInStore {
    Write-Host "Enabling searching for apps in Store for unknown extensions..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
    Write-Host "Enabled searching for apps in Store for unknown extensions. Moving on..."
}

# Disassembler0
function DisableSearchAppInStore {
    Write-Host "Disabling searching for apps in Store for unknown extensions..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
    Write-Host "Disabled searching for apps in Store for unknown extensions. Moving on..."
}

# Disassembler0
function HideRecentlyAddedApps {
    Write-Host "Hiding 'Recently added' list from the Start Menu..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
}

# Disassembler0
function UnhideRecentlyAddedApps {
    Write-Host "Showing 'Recently added' list in the Start Menu..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue
    Write-Host "Unhid 'Recently added' list in the Start Menu..."
}

# Disassembler0
# Set Control Panel view to Large icons (Classic)
function SetControlPanelLargeIcons {
    Write-Host "Setting Control Panel view to large icons..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
}

# Disassembler0
function EnableF1HelpKey {
    Write-Host "Enabling F1 Help key..."
    Remove-Item "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Enabled F1 Help Key. Moving on..."
}

# Disassembler0
function DisableF1HelpKey {
    # Disable F1 Help key in Explorer and on the Desktop
    Write-Host "Disabling F1 Help key..."

    If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
        New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value ""

    If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
        New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value ""

    Write-Host "Disabled F1 Help Key. Moving on..."
}

# Disassembler0
function ShowHiddenFiles {
    Write-Host "Showing hidden files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
    Write-Host "Set Hidden Files to visible. Moving on..."
}

# Disassembler0
function HideHiddenFiles {
    Write-Host "Hiding hidden files..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
    Write-Host "Reverted Hidden Files setting. Moving on..."
}

# Disassembler0
function EnableNavPaneExpand {
    Write-Host "Enabling navigation pane expansion to current folder..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 1
    Write-Host "Enabled navigation pane expansion to current folder. Moving on..."
}

# Disassembler0
function DisableNavPaneExpand {
    Write-Host "Disabling navigation pane expansion to current folder..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -ErrorAction SilentlyContinue
    Write-Host "Disabled navigation pane expansion to current folder. Moving on..."
}


function ReadPrefs {

    $prefFile = "setup_prefs.txt"

    If (!Test-Path $prefFile){
        Write-Host "Cannot find pref. file. Exiting..."
        exit
    }

    $prefs = Get-Content $prefFile
    $actionType = ($prefs | Select-Object -Index 2).Trim().ToLower()

    If ($actionType -eq "setup") {
        ($prefs | Select-Object -Index 6).split(",").Trim() | ForEach-Object {
            Switch($_) {
                1 { InstallCustomSoftware }
                2 { UninstallBloatware }
                3 { DisableUnnecessaryTasks }
                4 { DisableDataCollection }
                5 { DisableWifiSense }
                6 { DisableUserActivityHistory }
                7 { HideTasksViewBtn }
                8 { HideMeetNowBtn }
                9 { HideNewsAndInterests }
                10 { HideSearchButtonAndBox }
                11 { DisableCollapsibleTray }
                12 { StopEdgePDF }
                13 { DisableAutorun }
                14 { DisableIndexing }
                15 { EnableNTFSLongPaths }
                16 { DisableSearchAppInStore }
                17 { HideRecentlyAddedApps }
                18 { DisableAppSuggestions }
                19 { DisableWebSearchInMenu }
                20 { DisableNavPaneExpand }
                21 { ShowExpolorerFileExtensions }
                22 { Set12HrTimeFormat }
                23 { SetPCName }
                24 { SetControlPanelLargeIcons }
                25 { OptimizeCDrive }
                26 { CreateRestorePoint }
                27 { UpdateExplorerDefaultLocation }
                28 { Hide3DObjectsInExplorer }
                29 { SetBIOSTimeToUTC }
                30 { DisableFastStartup }
                31 { ShowHiddenFiles }
                32 { OptimizeNetworking }
                33 { DisableF1HelpKey }
                34 { UnhideDesktopIcons }
                35 { DisableFirewall }
            }
        }
    } ElseIf ($actionType -eq "undo") {
        ($prefs | Select-Object -Index 11).split(",").Trim() | ForEach-Object {
            Switch($_) {
                # 1 { InstallCustomSoftware }
                # 2 { UninstallBloatware }
                3 { EnableUnnecessaryTasks }
                4 { EnableDataCollection }
                5 { EnableWifiSense }
                6 { EnableUserActivityHistory }
                7 { UnhideTasksViewBtn }
                8 { UnhideMeetNowBtn }
                9 { UnhideNewsAndInterests }
                10 { UnhideSearchButtonAndBox }
                11 { EnableCollapsibleTray }
                12 { AllowEdgePDF }
                13 { EnableAutorun }
                14 { EnableIndexing }
                15 { DisableNTFSLongPaths }
                16 { EnableSearchAppInStore }
                17 { UnhideRecentlyAddedApps }
                18 { EnableAppSuggestions }
                19 { EnableWebSearchInMenu }
                20 { EnableNavPaneExpand }
                21 { HideExpolorerFileExtensions }
                # 22 { Set12HrTimeFormat }
                # 23 { SetPCName }
                # 24 { SetControlPanelLargeIcons }
                # 25 { OptimizeCDrive }
                # 26 { CreateRestorePoint }
                27 { RevertExplorerDefaultLocation }
                28 { Unhide3DObjectsInExplorer }
                29 { SetBIOSTimeToLocal }
                30 { EnableFastStartup }
                31 { HideHiddenFiles }
                32 { RevertNetworkingOptimization }
                33 { EnableF1HelpKey }
                34 { HideDesktopIcons }
                35 { EnableFirewall }
            }
        }
    } Else {
        Write-Host "Invalid action type specified."
    }
}

ReadPrefs

Write-Host "Exiting..."
Stop-Transcript
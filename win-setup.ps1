# <Remove Apps />
	Get-AppxPackage *3dbuilder* | Remove-AppxPackage
	Get-AppxPackage *windowsalarms* | Remove-AppxPackage
	Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
	Get-AppxPackage *windowscamera* | Remove-AppxPackage
	Get-AppxPackage *officehub* | Remove-AppxPackage
	Get-AppxPackage *skypeapp* | Remove-AppxPackage
	Get-AppxPackage *zunemusic* | Remove-AppxPackage
	Get-AppxPackage *windowsmaps* | Remove-AppxPackage
	Get-AppxPackage *solitairecollection* | Remove-AppxPackage
	Get-AppxPackage *bingfinance* | Remove-AppxPackage
	Get-AppxPackage *zunevideo* | Remove-AppxPackage
	Get-AppxPackage *bingnews* | Remove-AppxPackage
	Get-AppxPackage *onenote* | Remove-AppxPackage
	Get-AppxPackage *windowsphone* | Remove-AppxPackage
	Get-AppxPackage *photos* | Remove-AppxPackage
	Get-AppxPackage *windowsstore* | Remove-AppxPackage
	Get-AppxPackage *bingsports* | Remove-AppxPackage
	Get-AppxPackage *soundrecorder* | Remove-AppxPackage
	Get-AppxPackage *bingweather* | Remove-AppxPackage
	Get-AppxPackage *ScreenSketch* | Remove-AppxPackage
	Get-AppxPackage *Paint3D* | Remove-AppxPackage
	Get-AppxPackage *UbuntuonWindows* | Remove-AppxPackage
	Get-AppxPackage *XboxGameCallableUI* | Remove-AppxPackage
	Get-AppxPackage *XboxGamingOverlay* | Remove-AppxPackage
	Get-AppxPackage *XboxIdentityProvider* | Remove-AppxPackage
	Get-AppxPackage *MicrosoftStickyNotes* | Remove-AppxPackage
	Get-AppxPackage *WindowsCamera* | Remove-AppxPackage
	Get-AppxPackage *WindSynthBerry* | Remove-AppxPackage
	Get-AppxPackage *MIDIBerry* | Remove-AppxPackage
	Get-AppxPackage *Slack* | Remove-AppxPackage
	Get-AppxPackage *GetHelp* | Remove-AppxPackage
	Get-AppxPackage *Messaging* | Remove-AppxPackage
	Get-AppxPackage *Microsoft3DViewer* | Remove-AppxPackage
	Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage
	Get-AppxPackage *MicrosoftSolitaireCollection* | Remove-AppxPackage
	Get-AppxPackage *NetworkSpeedTest* | Remove-AppxPackage
	Get-AppxPackage *News* | Remove-AppxPackage
	Get-AppxPackage *Lens* | Remove-AppxPackage
	Get-AppxPackage *Sway* | Remove-AppxPackage
	Get-AppxPackage *OneConnect* | Remove-AppxPackage
	Get-AppxPackage *People* | Remove-AppxPackage
	Get-AppxPackage *Print3D* | Remove-AppxPackage
	Get-AppxPackage *getstarted* | Remove-AppxPackage
	Get-AppxPackage *RemoteDesktop* | Remove-AppxPackage
	Get-AppxPackage *Office.Todo.List* | Remove-AppxPackage
	Get-AppxPackage *Whiteboard* | Remove-AppxPackage
	Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage
	Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage
	Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage
	Get-AppxPackage *Xbox.TCUI* | Remove-AppxPackage
	Get-AppxPackage *XboxApp* | Remove-AppxPackage
	Get-AppxPackage *XboxGameOverlay* | Remove-AppxPackage
	Get-AppxPackage *XboxSpeechToTextOverlay* | Remove-AppxPackage
	Get-AppxPackage *EclipseManager* | Remove-AppxPackage
	Get-AppxPackage *ActiproSoftwareLLC* | Remove-AppxPackage
	Get-AppxPackage *AdobeSystemsIncorporated* | Remove-AppxPackage
	Get-AppxPackage *Duolingo* | Remove-AppxPackage
	Get-AppxPackage *PandoraMediaInc* | Remove-AppxPackage
	Get-AppxPackage *CandyCrush* | Remove-AppxPackage
	Get-AppxPackage *BubbleWitch3Saga* | Remove-AppxPackage
	Get-AppxPackage *Wunderlist* | Remove-AppxPackage
	Get-AppxPackage *Flipboard* | Remove-AppxPackage
	Get-AppxPackage *Twitter* | Remove-AppxPackage
	Get-AppxPackage *Facebook* | Remove-AppxPackage
	Get-AppxPackage *Spotify* | Remove-AppxPackage
	Get-AppxPackage *Minecraft* | Remove-AppxPackage
	Get-AppxPackage *Royal Revolt* | Remove-AppxPackage
	Get-AppxPackage *Dolby* | Remove-AppxPackage
	Get-AppxPackage *Speed Test* | Remove-AppxPackage
	Get-AppxPackage *549981C3F5F10* | Remove-AppxPackage
# <Remove Apps />

# <Disable OneDrive>
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
# <Disable OneDrive />

# <Enable Dark Mode>
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
# <Enable Dark Mode />

# <Disable Action Center>
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
# <Disable Action Center />

# <Only Security Updates>
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
# <Only Security Updates />

# <Disable Cortana>
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
# <Disable Cortana />

# <Disable Background Apps>
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
# <Disable Background Apps />

# <Disable Telemetry>
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
# <Disable Telemetry />

# <Disable App Sugestions>
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
# <Disable App Sugestions />

# <Disable Activity History>
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
# <Disable Activity History />

# <Disable Tracking Location>
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
# <Disable Tracking Location />

# <Disable Map Updates>
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
# <Disable Map Updates />

# <Disable Feedback>
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
# <Disable Feedback />

# <Disable Tailored Experiences>
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
# <Disable Tailored Experiences />

# <Disable Advertising ID>
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
# <Disable Advertising ID />

# <Disable Error Reporting>
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
# <Disable Error Reporting />

# <Disable Windows Update P2P>
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
# <Disable Windows Update P2P />

# <Disable Diagnostics Tracking Service>
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
# <Disable Diagnostics Tracking Service />

# <Disable WAP Push Service>
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
# <Disable WAP Push Service>

# <Disable Home Group>
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
# <Disable Home Group />

# <Disable Remote Assistance>
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
# <Disable Remote Assistance />

# <Disable Storage Sense>
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
# <Disable Storage Sense />

# <Disable Superfetch Service>
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
# <Disable Superfetch Service />

# <Disable Hibernation>
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
# <Disable Hibernation>

# <Show Task Manager Details>
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
# <Show Task Manager Details />

# <Show File Operations Details>
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
# <Show File Operations Details />

# <Hide Task View Icon>
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
# <Hide Task View Icon />

# <Hide People Icon>
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
# <Hide People Icon />

# <Enable NumLock After Start>
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
# <Enable NumLock After Start />

# <Change Default Explorer To This PC>
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
# <Change Default Explorer To This PC />

# <Hide 3D Objecys Icon>
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
# <Hide 3D Objecys Icon />

# <Network Tweaks>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
# <Network Tweaks />

# <SVCHost Tweak>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
# <SVCHost Tweak />

# <Disable News And Interests>
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
# <Disable News And Interests />

# <Disable Aero-Shake Minimize>
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisallowShaking" 1
# <Disable Aero-Shake Minimize />

# <Stop Egde PDF>
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
    $Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
    If (Test-Path $Edge) {
        Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_ 
    }
# <Stop Egde PDF />

# <Disable Web Search>
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1
# <Disable Web Search />

# <Disable Wi-fi Sense>
    Write-Output "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
    Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
# <Disable Wi-fi Sense />

# <Run O&O Shutup>
	Import-Module BitsTransfer
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/Nilphym/win-setup/main/ooshutup10.cfg" -Destination ooshutup10.cfg
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
	./OOSU10.exe ooshutup10.cfg /quiet
# <Run O&O Shutup />

# <Restore Photo Viewer>
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.bmp") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.bmp" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.cr2") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.cr2" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.dib") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.dib" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.gif") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.gif" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.ico") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.ico" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.jfif") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.jfif" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.jpe") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.jpe" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.jpeg") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.jpeg" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.jpg") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.jpg" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.jxr") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.jxr" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.png") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.png" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.tif") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.tif" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.tiff") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.tiff" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Classes\.wdp") -ne $true) {  New-Item "HKCU:\SOFTWARE\Classes\.wdp" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids") -ne $true) {  New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids" -force -ea SilentlyContinue };
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.bmp' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.cr2' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.dib' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.gif' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.ico' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.jfif' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.jpe' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.jpeg' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.jpg' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.jxr' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.png' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.tif' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.tiff' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Classes\.wdp' -Name '(default)' -Value 'PhotoViewer.FileAssoc.Tiff' -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids' -Name 'PhotoViewer.FileAssoc.Tiff' -Value (New-Object Byte[] 0) -PropertyType None -Force -ea SilentlyContinue;
# <Restore Photo Viewer />

# <Download SDI Tool>
	Start-BitsTransfer -Source "http://sdi-tool.org/releases/SDI_R2102.zip" -Destination SDI_R2102.zip
# <Download SDI Tool />
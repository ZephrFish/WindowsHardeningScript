<#
    ZephrFish's Ultimate Windows Lockdown and Hardening Script 2024
#>

# Before we roll out we must be admin for things to run
If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	WriteToLog -Message "Please run as administrator." -color "red"
	Read-Host
	Exit
}




# Warning about the script's impact
Write-Host "WARNING: This script will make significant changes to your system's configuration to harden security. Please ensure you understand the impact of each change before proceeding." -ForegroundColor Red
$continue = Read-Host "Do you want to continue? (Y/N)"
if ($continue -ne 'Y') {
    Write-Host "Operation aborted by the user."
    exit
}

Write-Host "We are going to first check that all the expected Registry paths exist before executing"
function LetsAllCheckRegExist {
    param (
        [string]$Path
    )
    # Extract the root and subpath for New-Item
    $root = $Path -replace '\\.+', '' 
    $subPath = $Path -replace '^[^\\]+\\', '' 

    # Check if the path exists
    if (-not (Test-Path $Path)) {
        try {
            New-Item -Path "$root" -Name "$subPath" -Force -ErrorAction Stop | Out-Null
            Write-Host "Created registry path: $Path" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create registry path: $Path" -ForegroundColor Red
        }
    }
}

# Provided registry paths
$registryPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch",
    "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter",
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKCU:\Software\Microsoft\Office\14.0\Word\Options",
    "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail",
    "HKCU:\Software\Microsoft\Office\15.0\Word\Options",
    "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail",
    "HKCU:\Software\Microsoft\Office\16.0\Word\Options",
    "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule",
    "HKLM:\SYSTEM\CurrentControlSet\Control",
    "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint",
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
)

# Ensure each path exists before setting properties
foreach ($path in $registryPaths) {
    LetsAllCheckRegExist -Path $path
}

# Change file associations for obscuring malicious filetypes
$extensions = @('hta', 'wsh', 'wsf', 'js', 'jse', 'vbe', 'vbs', 'scr', 'htm')
$optionalExtensions = @('bat', 'ps1')

Write-Host "Do you want to change the file associations for .bat and .ps1 files to Notepad? (Y/N)" -ForegroundColor Yellow
$response = Read-Host "Please enter Y for Yes or N for No"

if ($response -eq 'Y') {
    $extensions += $optionalExtensions
}

foreach ($ext in $extensions) {
    $path = "HKCU:\Software\Classes\.$ext"
    # Ensure the path exists before attempting to set a property.
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "(Default)" -Value "Notepad"
        Write-Host "File association for .$ext changed to Notepad." -ForegroundColor Green
    } else {
        Write-Host "The registry path for .$ext does not exist. Attempting to create."
        # Optionally, create the registry key if it doesn't exist.
        New-Item -Path $path -Force | Out-Null
        Set-ItemProperty -Path $path -Name "(Default)" -Value "Notepad"
        Write-Host "File association for .$ext has been created and set to Notepad." -ForegroundColor Green
    }
}


# Enable and configure Windows Defender
Start-Service WinDefend
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "MP_FORCE_USE_SANDBOX" -Value 1
Start-Process "powershell" -ArgumentList "Set-MpPreference -PUAProtection enable; Set-MpPreference -MAPSReporting Advanced; Set-MpPreference -SubmitSamplesConsent 0" -Wait

# Additional Defender configurations omitted for brevity
Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3

# Enable and Configure Internet Browser Settings
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 1

# Google Chrome and other settings
# Ensure the registry path exists, create if not
$chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
if (-not (Test-Path $chromePolicyPath)) {
    New-Item -Path $chromePolicyPath -Force
}

# Setting Chrome policies
Set-ItemProperty -Path $chromePolicyPath -Name "AdvancedProtectionAllowed" -Value 1 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "AllowCrossOriginAuthPrompt" -Value 0 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "AlwaysOpenPdfExternally" -Value 1 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "AmbientAuthenticationInPrivateModesEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "AudioCaptureAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "AudioSandboxEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "BlockExternalExtensions" -Value 1 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "DnsOverHttpsMode" -Value "on" -Type String
Set-ItemProperty -Path $chromePolicyPath -Name "SSLVersionMin" -Value "tls1" -Type String
Set-ItemProperty -Path $chromePolicyPath -Name "ScreenCaptureAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "SitePerProcess" -Value 1 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "TLS13HardeningForLocalAnchorsEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $chromePolicyPath -Name "VideoCaptureAllowed" -Value 0 -Type DWord

Write-Host "Chrome policy settings have been updated." -ForegroundColor Green


# Enable and Configure Microsoft Office Security Settings
# Harden all version of MS Office itself against common malspam attacks
# Disables Macros, enables ProtectedView

$officeVersions = @('12.0', '14.0', '15.0', '16.0', '19.0')
foreach ($version in $officeVersions) {
    # Define base path for each Office version
    $basePath = "HKCU:\Software\Policies\Microsoft\Office\$version"
    
    # Publisher security settings
    $publisherSecurityPath = "$basePath\Publisher\Security"
    New-Item -Path $publisherSecurityPath -Force | Out-Null
    Set-ItemProperty -Path $publisherSecurityPath -Name "vbawarnings" -Value 4
    
    # Word security settings
    $wordSecurityPath = "$basePath\Word\Security"
    New-Item -Path $wordSecurityPath -Force | Out-Null
    Set-ItemProperty -Path $wordSecurityPath -Name "vbawarnings" -Value 4
    if ($version -eq '15.0' -or $version -eq '16.0' -or $version -eq '19.0') {
        Set-ItemProperty -Path $wordSecurityPath -Name "blockcontentexecutionfrominternet" -Value 1
    }

    # Outlook security settings for versions 15.0, 16.0, and 19.0
    if ($version -eq '15.0' -or $version -eq '16.0' -or $version -eq '19.0') {
        $outlookSecurityPath = "$basePath\Outlook\Security"
        New-Item -Path $outlookSecurityPath -Force | Out-Null
        Set-ItemProperty -Path $outlookSecurityPath -Name "markinternalasunsafe" -Value 0
    }

    # Excel security settings for versions 15.0, 16.0, and 19.0
    if ($version -eq '15.0' -or $version -eq '16.0' -or $version -eq '19.0') {
        $excelSecurityPath = "$basePath\Excel\Security"
        New-Item -Path $excelSecurityPath -Force | Out-Null
        Set-ItemProperty -Path $excelSecurityPath -Name "blockcontentexecutionfrominternet" -Value 1
    }

    # PowerPoint security settings for versions 15.0, 16.0, and 19.0
    if ($version -eq '15.0' -or $version -eq '16.0' -or $version -eq '19.0') {
        $powerPointSecurityPath = "$basePath\PowerPoint\Security"
        New-Item -Path $powerPointSecurityPath -Force | Out-Null
        Set-ItemProperty -Path $powerPointSecurityPath -Name "blockcontentexecutionfrominternet" -Value 1
    }
}

# Setting DontUpdateLinks for Word 2010 (Office 14.0)
$word2010OptionsPath = "HKCU:\Software\Microsoft\Office\14.0\Word\Options"
$word2010WordMailPath = "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail"
New-Item -Path $word2010OptionsPath -Force | Out-Null
New-Item -Path $word2010WordMailPath -Force | Out-Null
Set-ItemProperty -Path $word2010OptionsPath -Name "DontUpdateLinks" -Value 1
Set-ItemProperty -Path $word2010WordMailPath -Name "DontUpdateLinks" -Value 1

# Setting DontUpdateLinks for Word 2013 (Office 15.0)
$word2013OptionsPath = "HKCU:\Software\Microsoft\Office\15.0\Word\Options"
$word2013WordMailPath = "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail"
New-Item -Path $word2013OptionsPath -Force | Out-Null
New-Item -Path $word2013WordMailPath -Force | Out-Null
Set-ItemProperty -Path $word2013OptionsPath -Name "DontUpdateLinks" -Value 1
Set-ItemProperty -Path $word2013WordMailPath -Name "DontUpdateLinks" -Value 1

# Setting DontUpdateLinks for Word 2016 (Office 16.0)
$word2016OptionsPath = "HKCU:\Software\Microsoft\Office\16.0\Word\Options"
$word2016WordMailPath = "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail"
New-Item -Path $word2016OptionsPath -Force | Out-Null
New-Item -Path $word2016WordMailPath -Force | Out-Null
Set-ItemProperty -Path $word2016OptionsPath -Name "DontUpdateLinks" -Value 1
Set-ItemProperty -Path $word2016WordMailPath -Name "DontUpdateLinks" -Value 1

Write-Host "Office settings have been updated." -ForegroundColor Green

# General Windows Security Settings

# Network Hardening
# Stop and disable the Bonjour Service if installed
Get-Service -Name "Bonjour Service" | Stop-Service -PassThru | Set-Service -StartupType Disabled

# Disable NetBIOS over TCP/IP for all network adapters
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }


# Disable LLMNR
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord



# DNS Client and SMB1 configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord

# TCP/IP Configuration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IGMPLevel" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord

# System and Security Policies
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDLLSearchMode" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value 1 -Type DWord

# Wi-Fi and NetBIOS Configuration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord

# Disable Windows PowerShell 2.0
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

# Windows Remote Access Settings
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord

# Removal Media Settings
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord

# Windows Sharing/SMB Settings
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord

# Harden lsass to help protect against credential dumping (mimikatz) and audit lsass access requests
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1 -Type DWord

# Windows RPC and WinRM settings
Stop-Service -Name WinRM -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord

# Disabling RPC usage from a remote asset interacting with scheduled tasks and services
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -Type DWord

# Biometrics and App Privacy
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Value 2 -Type DWord


# Warning before applying firewall rules
Write-Host "WARNING: The next steps involve modifying the firewall settings. This could impact network connectivity and application functionality." -ForegroundColor Red
$continueFirewall = Read-Host "Do you want to continue with firewall modifications? (Y/N)"
if ($continueFirewall -ne 'Y') {
    Write-Host "Firewall modification aborted by the user."
} else {
    # Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Enable Firewall Logging for the current profile
$LogFilePath = "$env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -LoggingFileName $LogFilePath
Set-NetFirewallProfile -LoggingMaxFileSize 4096
Set-NetFirewallProfile -LoggingAllowed $True
Set-NetFirewallProfile -LoggingBlocked $True

# Block all inbound connections on Public profile
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow

# Enable Windows Defender Network Protection
Set-MpPreference -EnableNetworkProtection Enabled

# Block specific Win32 binaries from making outbound connections
$programs = @('notepad.exe', 'regsvr32.exe', 'calc.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'runscripthelper.exe', 'hh.exe', 'msiexec.exe')
foreach ($program in $programs) {
    $ruleName = "Block $($program) network connections"
    $programPath = Join-Path $env:SystemRoot "system32\$program"
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $programPath -Action Block -Protocol TCP -Profile Any
    Write-Host "Firewall rule added: $ruleName" -ForegroundColor Green
}

}
# Windows Privacy Settings, Logging, and more
    Write-Host "WARNING: We're about to remove pre-installed applications that Windows comes with by default. This action cannot be undone." -ForegroundColor Red
    $continue = Read-Host "Do you want to continue with the cleanup? (Y/N)"
    if ($continue -ne 'Y') {
        Write-Host "Operation aborted by the user."
        return
    }

    # Re-register all AppxPackages for all users in case it's needed for repair
    Get-AppxPackage -AllUsers | ForEach-Object {
        Write-Host "Re-registering package: $($_.Name)"
        Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
    }

    # Define an array of AppxPackage names that are considered removable
    $removableApps = @(
        "Microsoft.BingWeather", "Microsoft.DesktopAppInstaller", "Microsoft.GetHelp", 
        "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", 
        "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftSolitaireCollection", 
        "Microsoft.MicrosoftStickyNotes", "Microsoft.MixedReality.Portal", "Microsoft.Office.OneNote", 
        "Microsoft.OneConnect", "Microsoft.Print3D", "Microsoft.SkypeApp", "Microsoft.Wallet", 
        "Microsoft.WebMediaExtensions", "Microsoft.WebpImageExtension", "Microsoft.WindowsAlarms", 
        "Microsoft.WindowsCamera", "microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub", 
        "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI", 
        "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxGamingOverlay", 
        "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.YourPhone", 
        "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft.WindowsFeedback", 
        "Windows.ContactSupport", "PandoraMedia", "AdobeSystemIncorporated.AdobePhotoshop", 
        "Duolingo", "Microsoft.BingNews", "Microsoft.Office.Sway", "Microsoft.Advertising.Xaml", 
        "Microsoft.NET.Native.Framework.1.*", "Microsoft.Services.Store.Engagement", 
        "ActiproSoftware", "EclipseManager", "SpotifyAB.SpotifyMusic", "king.com.*"
    )

    # Loop through the array to remove each specified AppxPackage
    foreach ($appName in $removableApps) {
        Get-AppxPackage -AllUsers -Name $appName | ForEach-Object {
            Write-Host "Removing package: $($_.Name)"
            Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
        }
    }

Write-Host "Crapware removal process completed." -ForegroundColor Green

# Set Windows Analytics to limited enhanced if enhanced is enabled
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 1 -Type DWord

# Set Windows Telemetry to security only
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "MaxTelemetryAllowed" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Value 1 -Type DWord

# Disable location data
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" -Name "Location" -Value "Deny" -Type String

# Prevent the Start Menu Search from providing internet results and using your location
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord

# Disable publishing of Win10 user activity
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 1 -Type DWord

# Disable Windows GameDVR (Broadcasting and Recording)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord

# Disable Microsoft consumer experience which prevents notifications of suggested applications to install
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

# Prevent toast notifications from appearing on lock screen
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord

# Turn off services we don't need
# Define an array of service names to be stopped and disabled
$nonNeededservices = @(
    "WpcMonSvc", "SharedRealitySvc", "Fax", "autotimesvc", "wisvc", "SDRSVC",
    "MixedRealityOpenXRSvc", "WalletService", "SmsRouter", "SharedAccess", "MapsBroker", "PhoneSvc",
    "ScDeviceEnum", "TabletInputService", "icssvc", "edgeupdatem", "edgeupdate",
    "MicrosoftEdgeElevationService", "RetailDemo", "MessagingService", "PimIndexMaintenanceSvc",
    "OneSyncSvc", "UnistoreSvc", "DiagTrack", "dmwappushservice",
    "diagnosticshub.standardcollector.service", "diagsvc", "WerSvc", "wercplsupport",
    "SCardSvr", "SEMgrSvc"
)

# Loop through each service in the array
foreach ($serviceName in $nonNeededservices) {
    Stop-Service $serviceName -ErrorAction SilentlyContinue
    Set-Service $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Service $serviceName has been stopped and disabled." -ForegroundColor Cyan
}

$features = @(
    "TFTP", "TelnetClient", "WCF-TCP-PortSharing45", "SmbDirect", 
    "Printing-XPSServices-Features", "WorkFolders-Client", "MSRDC-Infrastructure"
)

foreach ($feature in $features) {
    dism /Online /Disable-Feature /FeatureName:$feature /NoRestart
}

$capabilities = @(
    "App.StepsRecorder*", "App.Support.QuickAssist*", "Browser.InternetExplore*",
    "Hello.Face*", "MathRecognizer*", "Microsoft.Windows.PowerShell.ISE*", "OpenSSH*", "Language.Handwriting"
)

# Loop through each capability pattern in the array
foreach ($capabilityPattern in $capabilities) {
    Get-WindowsCapability -Online | Where-Object { $_.Name -like $capabilityPattern } | ForEach-Object {
        Remove-WindowsCapability -Online -Name $_.Name -ErrorAction SilentlyContinue
        Write-Host "Capability $($_.Name) has been removed." -ForegroundColor Cyan
    }
}

# Disable specific tasks directly by their full path
$tasksByFullPath = @(
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Application Experience\StartupAppTask",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
)

foreach ($taskPath in $tasksByFullPath) {
    $task = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Disable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
        Write-Host "Task at path $taskPath has been disabled." -ForegroundColor Cyan
    }
}

# Disable all tasks under a specific folder
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask

# Define an array of task names to be disabled
$taskNames = @(
    "ProgramDataUpdater", "Proxy", "Consolidator", "Microsoft-Windows-DiskDiagnosticDataCollector",
    "MapsToastTask", "MapsUpdateTask", "FamilySafetyMonitor", "FODCleanupTask",
    "FamilySafetyRefreshTask", "XblGameSaveTask", "UsbCeip", "DmClient", "DmClientOnScenarioDownload"
)

# Loop through each task name and disable it
foreach ($taskName in $taskNames) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Disable-ScheduledTask -InputObject $task -ErrorAction SilentlyContinue
        Write-Host "Task $taskName has been disabled." -ForegroundColor Cyan
    }
}


# Enable Advanced Windows Logging
# Turn our logging up to 11, to make sure all the essentials are covered
# Set Event Log Size
wevtutil sl Security /ms:1024000 
wevtutil sl Application /ms:1024000 
wevtutil sl System /ms:1024000 
wevtutil sl "Windows PowerShell" /ms:1024000 
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000 

# Enable command line data logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# Enable Advanced Audit Policy Configuration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1

# Enable PowerShell Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScriptBlockLogging" -Value 1

# Enable Windows Event Detailed Logging
$auditCategories = @(
    "Security Group Management",
    "Process Creation",
    "Logoff",
    "Logon",
    "Filtering Platform Connection",
    "Removable Storage",
    "SAM",
    "Filtering Platform Policy Change",
    "IPsec Driver",
    "Security State Change",
    "Security System Extension",
    "System Integrity"
)

foreach ($category in $auditCategories) {
    if ($category -eq "Logoff" -or $category -eq "Filtering Platform Connection" -or $category -eq "SAM" -or $category -eq "Filtering Platform Policy Change") {
        $success = "enable"
        $failure = "disable"
    } else {
        $success = "enable"
        $failure = "enable"
    }
    auditpol /set /subcategory:"$category" /success:$success /failure:$failure
}

Write-Host "Windows Event Log and Auditing Policies are configured." -ForegroundColor Green

# Optional Additional Security Lockdown Options
# Summary of actions to be taken
$actions = @"
This script will apply the following security enhancements and configurations:

1. Enforce NTLMv2 and LM authentication to improve security in network authentication.
2. Prevent unencrypted passwords from being sent to third-party SMB servers to enhance security in file sharing.
3. Prevent guest logons to SMB servers to restrict unauthorized access.
4. Force SMB server signing to ensure the integrity of SMB communications.
5. Enable Windows Defender Application Guard to provide robust isolation for browsing sessions.
6. Enable Windows Defender Credential Guard to protect credential information from attacks.
7. Enable system-wide mitigations like DEP, CFG, ForceRelocateImages, BottomUp, and SEHOP to improve security posture against exploits.
8. Block execution of files unless they meet criteria such as prevalence, age, or being on a trusted list.
9. Enable Windows Defender real-time monitoring to provide continuous protection against malware.
10. Disable Internet Connection Sharing to prevent potential unauthorized network use.
11. Always re-process Group Policy for the latest updates and configurations.
12. Force logoff if a smart card is removed to secure sessions in environments using smart cards.
13. Restrict usage of privileged local admin tokens over the network to enhance security against lateral movement in domain environments.
14. Ensure outgoing secure channel traffic is encrypted to protect data in transit.

Do you want to continue with these changes? (Y/N):
"@

# Prompt the user for confirmation
$continue = Read-Host -Prompt $actions

if ($continue -eq 'Y') {
    # Applying configurations only if user confirms with 'Y'

    # Enforce NTLMv2 and LM authentication
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

    # Prevent unencrypted passwords being sent to third-party SMB servers
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0 -Type DWord

    # Prevent guest logons to SMB servers
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord

    # Force SMB server signing
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord

    # Enable Windows Defender Application Guard
    Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart

    # Enable Windows Defender Credential Guard
    $deviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    New-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $deviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -PropertyType DWord -Force
    New-ItemProperty -Path $deviceGuardPath -Name "LsaCfgFlags" -Value 1 -PropertyType DWord -Force

    # Enable system-wide mitigations
    Set-ProcessMitigation -System -Enable DEP,CFG,ForceRelocateImages,BottomUp,SEHOP

    # Block execution of files based on criteria (Be cautious with this setting)
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled

    # Enable Windows Defender real-time monitoring
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -Force

    # Disable Internet Connection Sharing
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0 -Type DWord -Force

    # Always re-process Group Policy
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value 0 -Type DWord -Force

    # Force logoff if smart card removed
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Value 2 -Type DWord -Force

    # Restrict privileged local admin tokens being used from network
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -Force

    # Ensure outgoing secure channel traffic is encrypted
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force

    Write-Host "Additional security configurations have been applied successfully." -ForegroundColor Green
} else {
    Write-Host "Operation aborted by the user." -ForegroundColor Red
}

# User prompt with a warning about PSExec requirement
Write-Host "WARNING: This script will modify system policies that might affect PSExec functionality. If PSExec is required for your operations, consider selecting 'N'." -ForegroundColor Yellow
$userConfirmation = Read-Host "Do you want to proceed with these changes? (Y/N)"

if ($userConfirmation -eq 'Y') {
    # Convert REG commands to PowerShell commands
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" -Name "Enabled" -Value 0 -Type DWord -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" -Name "RemoteAddresses" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" -Name "Enabled" -Value 0 -Type DWord -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" -Name "RemoteAddresses" -Force -ErrorAction SilentlyContinue
    
    Write-Host "System policies have been updated successfully." -ForegroundColor Green
} else {
    Write-Host "Operation cancelled by the user." -ForegroundColor Red
}


Write-Host "All selected hardening tasks have been completed. Please review system functionality to ensure no critical operations are impacted." -ForegroundColor Green

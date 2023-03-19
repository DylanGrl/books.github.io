
---
layout: default
title: x009-Sybaris
nav_order: 2
has_children: true
parent: writeups
grand_parent: DylanGrl Writings
---
## x009-Sybaris 

### Abstract
Linux machine running 


### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.



| Server IP Adress | Ports Open |
|------------------|------------|
|     192.168.126.93      | TCP :  21,22,80,6379    |
|                  | UDP :      |



**Nmap Scan Results:**

Using  :
```sh
nmap -Pn -n -p- --min-rate 4000 --open -sCV 192.168.126.93
```

Result :
```sh
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-23 21:58 CEST
Nmap scan report for 192.168.126.93
Host is up (0.030s latency).
Not shown: 65519 filtered tcp ports (no-response), 12 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0               6 Apr 01  2020 pub [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.126
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 21:94:de:d3:69:64:a8:4d:a8:f0:b5:0a:ea:bd:02:ad (RSA)
|   256 67:42:45:19:8b:f5:f9:a5:a4:cf:fb:87:48:a2:66:d0 (ECDSA)
|_  256 f3:e2:29:a3:41:1e:76:1e:b1:b7:46:dc:0b:b9:91:77 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-generator: HTMLy v2.7.5
| http-robots.txt: 11 disallowed entries 
| /config/ /system/ /themes/ /vendor/ /cache/ 
| /changelog.txt /composer.json /composer.lock /composer.phar /search/ 
|_/admin/
|_http-title: Sybaris - Just another HTMLy blog
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.22
6379/tcp open  redis   Redis key-value store 5.0.9
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.87 seconds
                                                                  
```

**Vulnerability Exploited:** RedisModules-ExecuteCommand

**Vulnerability Explanation:**

Using write permission inside the FTP server we manage to upload a malicious redis module.

From the redis we are able to load this module and perform command execution and retrieve a reverse shell.

**Vulnerability Fix:** Implement access control to the FTP and the REDIS instance.

**Severity:** CRITICAL

**Proof of Concept / Code Here:**

https://github.com/n0b0dyCN/RedisModules-ExecuteCommand

**Local.txt Proof Screenshot**
![](attachments/Pasted%20image%2020220523225700.png)
**Local.txt Contents**

`d3133a2cfdd41f08aca3eef34bf38251`

### Privilege Escalation

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept / Code Here:**

**Proof Screenshot Here:**

**Proof.txt Contents:**


--------

##cd # NOTES : 
FTP access with anonymous 
Nothing inside but write access inside the "pub" folder (publicly accessible ?????)

Nothing int HTTP

REDIS open

```sh
ftp 192.168.126.93                                                                                         130 ⨯
Connected to 192.168.126.93.
220 (vsFTPd 3.0.2)
Name (192.168.126.93:mad0x): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put test
local: test remote: test
229 Entering Extended Passive Mode (|||10092|).
553 Could not create file.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> passive
Passive mode: on; fallback to active mode: on.
ftp> put test
local: test remote: test
229 Entering Extended Passive Mode (|||10099|).
553 Could not create file.
ftp> ls
229 Entering Extended Passive Mode (|||10092|).
150 Here comes the directory listing.
drwxrwxrwx    2 0        0               6 Apr 01  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> put test
local: test remote: test
229 Entering Extended Passive Mode (|||10093|).
150 Ok to send data.
100% |************************************************************************|     5       92.12 KiB/s    00:00 ETA
226 Transfer complete.
5 bytes sent in 00:00 (0.07 KiB/s)

```


We could use : https://github.com/n0b0dyCN/RedisModules-ExecuteCommand

To create a module and upload it in the FTP then from their we could load the module inside our redis access 
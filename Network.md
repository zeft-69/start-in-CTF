## NMAP TryHackMe rooms

- https://tryhackme.com/r/room/nmap01

- https://tryhackme.com/r/room/nmap02

- https://tryhackme.com/r/room/nmap03

- https://tryhackme.com/r/room/nmap04

## Vulnerability Assessment

- https://tryhackme.com/r/room/rpnessusredux

- https://tryhackme.com/r/room/openvas

- https://www.rapid7.com/products/nexpose/

  

---

  

# Nmap Guide

  
  

## Host Discovery Techniques

  

Host discovery, or "ping scan," helps find active hosts on a network.

### 1. Basic Ping Scan

  

```bash

nmap -sn <target>

```

- Uses ICMP Echo Request and TCP ACK ping to discover hosts.

- Identifies which hosts are online without further scanning.

  
  

### 2. ICMP Echo Request (-PE)

  

```bash

nmap -PE <target>

```

  

- Sends an ICMP Echo Request to each host to check for responses.

- Effective in open networks where ICMP isn’t filtered.

  
  

### 3. TCP SYN Ping (-PS)

  

```bash

nmap -PS80,443 <target>

```

- Sends a SYN packet to specified ports (e.g., 80, 443).

- Useful when ICMP is blocked but TCP ports are open.

  

  

### 4. TCP ACK Ping (-PA)

  

```bash

nmap -PA80 <target>

```

- Sends a TCP ACK packet, helping bypass firewalls that only allow ACK packets.

  

### 5. UDP Ping (-PU)

```bash

nmap -PU53 <target>

```

  

- Sends a UDP packet to discover active hosts, useful for networks where only UDP is open.

  

### 6. ARP Ping Scan (-PR) (Local Network)

  

```bash

nmap -PR <target>

```

- Uses ARP requests, highly accurate on local networks.

- Effective in identifying hosts without relying on IP-level pings.

  

### 7. Disable Host Discovery (-Pn)

  

```bash

nmap -Pn <target>

```

  

- Assumes all hosts are online and skips host discovery.

- Useful when host discovery is blocked, but port scanning is needed.

  
  

---

## Port Scanning Techniques

  

Port scanning reveals which ports are open and potentially accessible on a target.

### 1. SYN Scan (-sS)

  

```bash

nmap -sS <target>

```

  

- Sends SYN packets to each port without completing the TCP handshake.

- Stealthier than a full connection scan.

  

### 2. TCP Connect Scan (-sT)

  

```bash

nmap -sT <target>

```

  

- Completes the TCP handshake, making it more detectable but reliable.

- Used when SYN scan is unavailable, like on non-root systems.

  

### 3. UDP Scan (-sU)

  

```bash

nmap -sU <target>

```

  

- Scans for open UDP ports by sending UDP packets.

- Slower than TCP scans, as UDP responses may not be as immediate.

  

### 4. FIN Scan (-sF)

  

```bash

nmap -sF <target>

```

  

- Sends FIN packets instead of SYN packets.

- Effective in bypassing certain firewalls or IDS that only filter SYN packets.

  

### 5. Xmas Scan (-sX)

  

```bash

nmap -sX <target>

```

  

- Sends packets with FIN, PSH, and URG flags.

- Useful against systems that do not respond to abnormal flag combinations.

  

### 6. Null Scan (-sN)

  

```bash

nmap -sN <target>

```

- Sends packets without any TCP flags.

- Exploits systems that do not handle unusual traffic patterns properly.

  

### 7. Idle Scan (-sI)

  

```bash

nmap -sI <zombie_host> <target>

```

  

- Uses a "zombie" host to scan the target, making it difficult to trace back.

- Requires an idle system with a predictable IP ID sequence.

  

### 8. Scan Specific Ports (-p)

  

```bash

nmap -p 80,443 <target> # only 80,443

nmap -p 80-1024<target> # range

nmap -p- <target> # all ports

```

  

- Allows scanning of specific ports to reduce time or target specific services.

  

---

## Service Discovery

  

Service discovery, also called version detection, goes beyond finding open ports to determine the services and versions running on those ports.

  

### 1. Basic Service Version Detection (-sV)

  

```bash

nmap -sV <target>

```

  

- Sends specific probes to identify software versions.

- Helps in vulnerability assessment by revealing outdated services.

### 2. Aggressive Version Detection (--version-intensity)

  

```bash

nmap -sV --version-intensity 5 <target>

```

  

- Uses more probes (range 0-9) to improve version detection accuracy.

- Higher intensity may slow down the scan but provides more information.

  
  

### 3. Service Detection with OS Scan (-A)

  

```bash

nmap -A <target>

```

  

- Combines OS detection, version detection, script scanning, and traceroute.

- Useful for comprehensive assessments, but it is more time-intensive.

  

---

  

## Nmap Scripting Engine (NSE)

  

The NSE allows running specialized scripts that automate common tasks like vulnerability detection, network discovery, or service enumeration.

  
  

### 1. Basic Script Scan (-sC)

  

```bash

nmap -sC <target>

```

  

- Runs default scripts, including those for banner grabbing and version checks.

- Efficient for quick checks on common vulnerabilities.

  

### 2. Specify a Script Category (--script)

  

```bash

nmap --script <category> <target>

```

  

- Categories include `auth`, `vuln`, `exploit`, `discovery`, and more.

- Example for vulnerability scanning: `nmap --script vuln <target>`

  
  

### 3. Run a Specific Script by Name

  

```bash

nmap --script <script_name> <target>

```

  

- Allows running a specific script by its name, such as `http-title`.

- Example: `nmap --script http-title <target>`

  

### 4. Script Arguments (--script-args)

  

```bash

nmap --script <script_name> --script-args <arg1>=<value1>,<arg2>=<value2> <target>

```

  

- Customize script behavior by providing arguments.

- Example: `nmap --script http-form-brute --script-args userdb=users.txt,passdb=pass.txt <target>`

  

### 5. Vulnerability Scanning

  

```bash

nmap --script vuln <target>

```

  

- NSE includes scripts that check for well-known vulnerabilities.

- Scans for issues like weak SSL configurations and outdated software versions.

  

### 6. Aggressive Scanning with NSE (-A)

  

```bash

nmap -A <target>

```

  

- Combines NSE scripts with OS and version detection, useful for an in-depth analysis.





# PROTOCOLS
## FTP & ssh & smb
1-
```

ftp <RHOST>
```
2-
```
wget -r ftp://anonymous:anonymous@<RHOST>

```





**SSh**  


```


ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1

ssh -R 8080:<LHOST>:80 <RHOST>

ssh -L 8000:127.0.0.1:8000 <USERNAME>@<RHOST>

ssh -N -L 1234:127.0.0.1:1234 <USERNAME>@<RHOST>

ssh -L 80:<LHOST>:80 <RHOST>

ssh -L 127.0.0.1:80:<LHOST>:80 <RHOST>

ssh -L 80:localhost:80 <RHOST>

sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>

ls -lh /usr/share/nmap/scripts/*ssh*



```


**smb**


```
#smb
sudo impacket-smbserver <SHARE> ./

sudo impacket-smbserver <SHARE> . -smb2support

copy * \\<LHOST>\<SHARE>


smbclient -L \\<RHOST>\ -N

smbclient -L //<RHOST>/ -N

smbclient -L ////<RHOST>/ -N

smbclient -U "<USERNAME>" -L \\\\<RHOST>\\

smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>

smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>

smbclient "\\\\<RHOST>\<SHARE>"

smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000

smbclient --no-pass //<RHOST>/<SHARE>

mount.cifs //<RHOST>/<SHARE> /mnt/remote

guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v

```
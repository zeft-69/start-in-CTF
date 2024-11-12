 
# Step 1. Nmap Scan

```bash

nmap -h
//Nmap help message output


sudo nmap -Pn -p- -A -T4 -oN scan.txt <target_ip>
//Slower, but more reliable



sudo nmap -Pn -p- -A --min-rate 5000 -oN scan.txt <target_ip>
Faster, target may drop packets, adjust the '--min-rate' if needed


Q: how detect min-rate for target ???


sudo nmap -Pn -sU --top-ports 500 -A -T4 -oN udp-scan.txt <target_ip>
//UDP scan example using '-T4', as going too fast may miss ports
```

### No Service Banners?

```text
5040/tcp  open  unknown
```
What if `nmap` was able to connect to the port, but was unable to pull a service name and version from the port? There could be various reasons for this, some of the most common being:

- The port was opened on the box in an attempt to trick you
- The port is coupled with another service and doesn't reveal banners
- The service running on the port may be malfunctioning

You can try to manually pull banners from the service, but in all likelihood, you'll just have to move on:
```bash
nc -nv <target-ip> <target-port>

//Try netcat with verbose output, press 'Enter' a couple times to see if there's any output
```

### Cataloging Possible Exploits

We are _****NOT****_ exploiting anything at this phase. Just take inventory of service names and versions to determine what _****might****_ be an avenue to a shell on the target.

When I want to get an idea of any public exploits that might be available for any service(s), I will typically search on Google or Exploit Database.

- Google:
    - `ProFTPD 1.3.3c exploit`
    - `ProFTPD 1.3.3c exploit site:github.com`
- Exploit Database:
    - Command Line: `searchsploit ProFTPD 1.3.3c`
    - Web: [https://www.exploit-db.com/](https://www.exploit-db.com/?ref=benheater.com)

==In the case of a CTF, a `Denial of Service` exploit wouldn't do us much good,== but a `Command Execution` or `File Inclusion` exploit would be very interesting.





# Step 2. Service Enumeration

## Active Directory Specific

We can almost always be certain when we've encountered a ==domain controller== by looking at its port signature

A typical port signature for an Active Directory domain controller, especially apparent due to DNS, SMB, Kerberos, and LDAP being open on the box

### Identify the Local Domain

Next, we should check the `nmap` output for the RootDSE and any potential hostname (e.g. `DC01.domain.tld`). Once, established, we should add the domain and hostname to our `/etc/hosts` file.

```bash
sudo nmap -Pn --script ldap-rootdse.nse $target_ip

//If you've only run a basic `nmap` scan and need to enumerate the RootDSE




```

```bash

//Run these commands to populate your `/etc/hosts` file


target_ip='10.10.10.22'
target_domain='domain.tld'
target_hostname="DC01.${target_domain}"

echo -e "${target_ip}\t\t${target_domain} ${target_hostname}" | sudo tee -a /etc/hosts

```
`

### DNS

If we've established the local domain for the Active Directory environment, we should attempt to enumerate any DNS records for use when assessing other protocols.


```bash

//Attempt a zone transfer from the DNS server on the target. If configured correctly, the zone transfer should be refused.


target_ip='10.10.10.22'
target_domain='domain.tld'
host -T -l $target_domain $target_ip
```


```bash
//If the zone transfer fails, you can try and manually enumerate records in the target domain

target_ip='10.10.10.22'
target_domain='domain.tld'
dns_wordlist='/usr/share/seclists/Discovery/DNS/namelist.txt'
gobuster dns -r $target_ip -d $target_domain -w $dns_wordlist -t 100
```





### LDAP

A quick win would be the ability to enumerate LDAP records anonymously, as this would allow us to gather a great deal of information about interesting users, groups, and other domain records.

```bash
target_domain='domain.tld'
target_hostname="DC01.${target_domain}"
domain_component=$(echo $target_domain | tr '\.', '\n' | xargs -I % echo "DC=%" | paste -sd, -)

ldapsearch -x -H ldap://$target_hostname -b $domain_component

//If configured correctly, you should see an error saying that a successful bind must be completed, meaning you need a credential


```


```bash

//However, if you are able to anonymously query LDAP, this is an example command to pull everything from LDAP

ldapsearch -x -H ldap://$target_hostname -b $domain_component 'objectClass=*'
```


### SMB

If we can connect to SMB anonymously, it's worth checking to see if we can enumerate object RIDs anonymously as well. RID cycling would allow us to enumerate a list of users and groups on the computer for further use during testing.
```bash
#If you can connect to SMB with a null session (and maybe even list shares), we can try and enumerate more and potentially map shares
target_ip='10.10.10.22'
smbclient -N -L //$target_ip
```

```bash
##Connect to a SMB share via null session
smbclient -N //$target_ip/share_name
```

```bash
# nxc replaces crackmapexec
nxc smb $target_ip -u 'anonymous' -p '' --rid-brute 3000
nxc smb $target_ip -u '' -p '' --rid-brute 3000


#If configured correctly, you should see a permissions error, indicating the tests have failed
```



### Kerberos

If you haven't yet managed to compile a list of users from one of the other methods above, we can attempt to use Kerberos pre-authentication and a word list to find usernames.

If we've found some usernames, we can then see if any of them are configured with `UF_DONT_REQUIRE_PREAUTH`, pull some AS-REP hashes, and attempt to crack them offline.

```
Attempt to find valid usernames and save them to a log file, then testing for AS-REP hashes and attempting to crack them. If you manage to crack an AS-REP hash for a user account, you could then spray this password around and see what you can access (or at a minimum, dump LDAP).

```


## General Procedure

This is my generalized approach to every target:

1. File servers
2. Web servers
3. Everything else

I do it this way, because I work my way up by **_level of effort_** and **_amount of time_** involved to enumerate these services.

- File servers are quick and easy to assess, requiring only a widely available client
- Web servers require more work and enumeration due to more complex configurations that are possible on the server
- Everything else comes last when the first two aren't available or they haven't yielded enough info
#### 1. ****File servers**** — FTP/SMB

- May allow anonymous access or may be configured with default credentials
- This is an _****excellent opportunity****_ to gather more information from files
- Additional information may include usernames, passwords, config files, etc
- This information maybe useful when assessing other services
#### 2. Web — HTTP/HTTPS

- Web is just as simple as opening your web browser
- Navigate to the target IP or domain name and just start clicking around
- Make a note of potential input points that could be abused
- Web pages may contain usernames, passwords, interesting source code, etc
#### 3. Everything else

- Start probing other ports, try to understand how they behave
- Lots of Googling, probably something on HackTricks about it
- Try other `nmap` scans to see if additional ports are revealed; UDP or X-Mas scans, for example.

### DNS — UDP/53 & TCP/53

I'm putting this one at the top — above file servers — because this is one of those easy things you can try that can be potentially high-impact.

If you found — for example — in your `nmap` scan that a web server had a TLS certificate with a `commonName=mysite.test` and there is a DNS server running, you should test to see if a zone transfer is possible.

```bash
target_domain='mysite.test'
target_ip='10.10.100.44'
host -T -l $target_domain $target_ip

#Using the `host` command `-l` requests a zone transfer

```

If the zone transfer is successful, you could potentially reveal additional HTTP server names to assess later.

```bash
target_ip='10.10.100.44'
target_domain='mysite.test'
dns_wordlist='/usr/share/seclists/Discovery/DNS/namelist.txt'

gobuster dns -r $target_ip -d $target_domain -w $dns_wordlist -t 100
```
If the zone transfer fails, you can try and manually enumerate records in the target domain

💡

While the `gobuster dns` scan is running, go ahead and start your tests on other ports.


### FTP — TCP/21

```bash
ftp anonymous@10.10.100.44
#Check for anonymous FTP access on the target
```


When prompted for a password, simply press the `Enter` key and see if it will allow you to login. If it does, try the following:

- `ls` to list files on the server
- `get` to retrieve files on the server
- `less` or `more` to read files from the FTP shell
- `cd` to change into any potential directories
- `put` to test write permissions as a way to perhaps chain an exploit with another service

We're trying to uncover:

- Usernames
- Passwords
- Configuration files
- Source code
- Backups
- Anything interesting

If there's a lot of files and folders, you could do a **_recursive_** download and parse the files locally.

### SMB — TCP/139 & TCP/445

#### List Shares

```bash
smbclient -N -L //10.10.100.44
#No username specified, and '-N' for passwordless authentication
```



If you are able to anonymously **_list_** shares, then there's a decent chance you may be able to **_map_** shares.

Shares that aren't interesting **_from a files perspective_** are, for example:

- `IPC$`
- `print$`
#### Mapping Shares

```bash
smbclient -N //10.10.100.44/myshare
#Map the 'myshare' share anonymously
```


If you are able to map the share anonymously, try the following:

- `ls` to list files on the server
- `get` to retrieve files on the server
- `less` or `more` to read files from the SMB shell
- `cd` to change into any potential directories
- `put` to test write permissions as a way to perhaps chain an exploit with another service

Like FTP, we're trying to discover anything interesting. If there's a lot of files and folders, you could do a **_recursive_** download and parse the files locally.

### HTTP — TCP/80 & TCP/443
#### Initial Questions

The first things I want to establish with the web service are:

- Are there any noticeable differences between the `http://` and the `https://` versions of the apps running on the web server? In other words, is `http://` redirecting to `https://`, are they duplicates, or they completely different in behavior and presentation?
- Is the server making use of any `ServerName` (virtual host) directives that would cause different pages to load depending on the the hostname the client requests?

  
  

#### Test the Raw IP Address

- `http://10.10.100.44`
- `https://10.10.100.44`

- If the server loads different content at each unique scheme
    - There are distinct configurations per port
    - Plan on testing the servers independently
- If the server redirects `TCP/80` to `TCP/443`
    - Only need to test `TCP/443` (https)
#### Testing Virtual Hosts
The `Host` header is what the server is looking at to determine which virtual host configuration to serve content from. [_If you're interested in learning more about enumerating virtual hosts, you can see my notes here_](https://notes.benheater.com/books/web/page/virtualhost-enumeration?ref=benheater.com).

We can create a local name resolution entry by editing our `/etc/hosts` file, adding the DNS names we saw in the `nmap` output or any successful zone transfer.

```bash
sudo nano /etc/hosts
```



Edit the /etc/hosts file

```text
# Custom Entry
10.10.100.44 mysite.test dev.mysite.test admin.mysite.test
```



Add these hostnames pointing to '10.10.100.44'

Again, as before, test the server names against both HTTP and HTTPS and see if there are any **_behavioral differences_**.

- `http://mysite.test` and `https://mysite.test`
- `http://dev.mysite.test` and `https://dev.mysite.test`
- `http://admin.mysite.test` and `https://admin.mysite.test`

- If different domain names load the _**same content**_
    - No difference in page content between `http://mysite.test` and `http://subdomain.mysite.test`
    - Safe to assume no virtual hosts are being used
    - You can most likely test the server using the raw IP address
- If different domain names load _**unique content**_
    - `https://mysite.test` and `https://subdomain.mysite.test` load completely different pages
    - More than likely this server is using virtual hosts
    - Test each virtual host as an individual server
#### Walking the Happy Path

At this stage, we just want to use the web page as a normal user would.

- Not doing anything malicious
- Click links and provide expected inputs in standard fields
- Doing things that a normal user would expectedly do
- Navigating to the URLs we've discovered at this point
    - Raw IP addresses
    - Domain names
    - HTTP/HTTPS
- Just click around on links and interact
- Enter input as a normal user would
- Sign up for an account and view the application as an authenticated user
- Trying to understand the application behavior

  
  

#### Checking the Page Source

- Press `CTRL + U`
- Check the page source for any servers that need to be tested
    - Raw IP address
    - Domain names
    - HTTP/HTTPS
- Look for anything interesting visible client side
    - Typically in the HTML comments
    - Usernames
    - Passwords
    - Directory names
    - File names
    - Etc

  
  

#### Check for Robots and Sitemap

- `http://10.10.100.44/robots.txt` or `https://mysite.test/robots.txt`
- `https://10.10.100.44/sitemap.xml` or `https://mysite.test/sitemap.xml`
- `robots.txt` and `sitemap.xml` direct legitimate web crawlers and search engines
- They're only effective to the extent bots respect them
- Can also reveal some interesting and sensitive directories or pages
- `robots.txt` may show an entry for the `/admin` directory or similar
    - A legitimate web crawler respects this and does not crawl the directory
    - - - Malicious users will see this an opportunity to explore

  


#### Directory and File Enumeration

- Interesting files and directories may be "hidden" or not directly exposed
- We can send a series of HTTP requests to determine if a file or directory exists
    - `HTTP 20x` and `HTTP 30x` responses would be interesting
    - `HTTP 403` could be interesting from the perspective of, "What are we _**NOT**_ allowed to access?"
- I typically use `gobuster` or `feroxbuster`
- Choose whichever tool is most comfortable for you
```bash
#HTTP enumeration
gobuster dir -u http://10.10.100.44 -w /usr/share/seclists/Discovery/Web-Content/directory-list-big.txt -x php,html -r -t 100 -o gobuster80.txt
```

```bash
#HTTPS domain-specific enumeration example

gobuster dir -k -u https://dev.mysite.test -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html -r -t 100 -o gobuster443.txt
```

- These enumeration scans could reveal:
    - "Hidden" pages or pages with unintended access
    - Path-based applications such as CMS (eg. WordPress or Drupal)
- Blogs or CMS platforms may be unpatched or use unpatched plugins
    - Should check the version numbers for public exploits
    - `wp-scan` can be helpful when enumerating WordPress
#### Testing the Application

By now, you should have plenty of places to begin looking for potential vulnerabilities with the web applications running on the server.

You want to begin testing the web applications at various points:

- Vulnerable service or plugin versions
- URL parameters
- Login forms
- Search fields
- File uploads
- Etc.

And, you could test for things like:

- Path traversal
- Local and/or remote file inclusion
- Content type filter bypass
- SQL injection
- Default credentials
- Credential stuffing
- Password spraying
- Much, much more

## Unknown Ports and Services

Sometimes you will see uncommon services, uncommon port bindings, and high-number port bindings on certain CTF targets. The key here is being able to tell the difference between:

- An uncommon or high port bound to a service
    - Often included by CTF authors to confuse you
- A dynamic port bound to something like RPC
    - Just part of the operating system or another service like NFS

Fortunately, `nmap` does a good job of identifying services bound to ports, except for when it can't grab service banners from the port. So, you should be able to identify RPC from other port bindings with ease.


```text
49152/tcp open  msrpc        Microsoft Windows RPC  
49153/tcp open  msrpc        Microsoft Windows RPC  
49154/tcp open  msrpc        Microsoft Windows RPC  
49155/tcp open  msrpc        Microsoft Windows RPC  
49156/tcp open  msrpc        Microsoft Windows RPC
```

- Very common to see on Windows targets
- These are dynamic RPC port bindings and can typically be ignored

```text
2869/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
10243/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```
- These port bindings aid in network device discovery
- Can typically be ignored
```text
8080/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
```
- This is a very typical alternate HTTP port binding
- Explore this further if prior testing has been unsuccessful
```text
5040/tcp  open  unknown
```
- Showing an example of nmap failing to detect a service
- I would completely ignore this port unless everything else failed
- If you decide to probe this further, try:
    - Manually grabbing a service banner using `netcat` or `telnet`
    - Open Wireshark and interact with the service and inspect the packets
```text
PORT      STATE SERVICE      VERSION
8014/tcp  open  http         Apache httpd
60000/tcp open  http         Apache httpd 2.4.38
```
- `nmap` has identified these as alternative Apache HTTP server bindings
- Given the odd port numbers, I'd typically spend little time probing these until later
- You could use `curl` or your browser to open them up briefly and see what they look like, but do so much later after testing more common services

```text
PORT      STATE SERVICE      VERSION
1883/tcp  open  mqtt
```

- An example of an atypical service you could see on a box
- When you encounter a new service for the first time, search on Google
- You could search something like: `tcp 1883 mqtt pentest`
- HackTricks often has excellent articles on getting you started with testing services with which you may be unfamiliar
```text
PORT      STATE SERVICE VERSION
2222/tcp  open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
```
- An example of an atypical SSH server binding
- The same SSH principles apply to this server as well
    - Do not try and pentest this service early on, just ignore it initially
    - If you come across a SSH key or a username and password later, that would be a good time to test those credentials on something like this
## Information Re-Use

If you've discovered useful information while probing HTTP or some other service, you should always consider how this information may be able to be used with services you previously looked at.

For example, maybe you found:

- Usernames and/or passwords
- SSH private keys
- Wordlists
- Backups

Can any of this be used to go back and get more information from another service?




# Step 3. Exploit
By now, you should have **_plenty_** of information and a very educated guess about the potential exploit you're planning to use against the target.


All of the information gathering and preparation you've done up until this point should directly inform the exploit you're going to use.

You may end up using a publicly available exploit or you may end up chaining multiple vulnerabilities together. For example, you may have a FTP file upload and local file inclusion chained exploit to get a reverse shell.


# Step 4. Post-Exploit Enumeration and Privilege Escalation

Congratulations! You've got a shell on the target and you're probably full of adrenaline. Now's the time keep a level head and methodically enumerate the target environment to plot the path to full system ownership.

💡

Keep in mind that some of the usernames and/or passwords you enumerated before could be useful to you even at this point in the process.

  
  

## Post-Exploit Enumeration

At this phase, we want to take inventory of the environment. We want to get a lay of the land and figure out as much as we can before we start attacking anything internally.

ℹ️

I try to enumerate as much as I can manually, and in a targeted fashion, before relying on privilege escalation scripts. In fact — for me at least — privilege escalation scripts are always my last resort when all else fails. 

You can find the most up-to-date list of post-exploit enumeration tricks here:

### Operating Environment
#### OS & Kernel

- Windows
    
    - `systeminfo` or `Get-ComputerInfo` to print system overview
    - Check environment variables:
        - CMD: `set`
        - PowerShell: `Get-ChildItem Env:\`
- *nix
    
    - `uname -a` to print kernel information
    - `cat /etc/os-release` to print OS release information
    - Check environment variables:
        - `env` or `set`

#### Current User

- Windows
    
    - `whoami /all` to list:
        - Username
        - Group memberships
        - Privileges
- *nix
    
    - `id` to list username and group memberships
    - `sudo -l` to check `sudo` permissions

### Users and Groups


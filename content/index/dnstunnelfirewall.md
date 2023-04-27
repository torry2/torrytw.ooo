---
title: "Firewall Bypass via DNS tunnels (+HTTPS)"
date: 2022-08-08T17:10:44+08:00
sort: ["all", "networking", "featured"]
draft: false
---

![Network Diagram](/dnstunnelfirewall/networkdiagram.png)
Bypassing Firewalls via DNS Tunnels (+HTTPS) 

<aside id="toc">
    <h4>Table of Contents</h4>
	<h4><a href="#theory">1. </a>Theory</h4>
	<h4><a href="#method">2. </a>Method</h4>
	<h4><a href="#dns-configuration">3. </a>DNS Configuration</h4>
	<h4><a href="#ioddine-server">4. </a>Iodine Server</h4>
	<h4><a href="#iodine-client">5. </a>Iodine Client</h4>
	<h4><a href="#test-connection-0.5">6. </a>Test Connection 0.5</h4>
	<h4><a href="#https-(socks5-proxy)">7. </a>HTTPS (socks5 proxy)</h4>
	<h4><a href="#test-connection-1">8. </a>Test Connection 1</h4>
	<h4><a href="#wireshark">9. </a>Wireshark</h4>
	<h4><a href="#conclusion">10. </a>Conclusion</h4>
</aside>

# Theory
DNS tunneling is an attack in which data is encoded and sent over DNS queries returning decodable responses. Using a domain, internet connected server and a few simple DNS records (+ some tools & programs) an attacker can facilitate an authoritative nameserver (in which they control) to recieve encoded queries, decode them and send appropriate encoded responses back to a client. This allows for network traffic to be "disguised" over DNS and used for other programs and protocols. Note: DNS is <u>not</u> designed for data transfer and sending and retrieving data this way is incredibly slow. Common use cases for this attack include Data Exfiltration, C&C/C2 Command and Control and Wifi Abuse & Policy/Firewall Bypassing. This guide will demonstrate a Policy & Firewall Bypass with DNS tunneling (and achieving HTTPS traffic in a browser) however for the curious links on the other use cases are below:  
- <a href="https://aristanetworks.force.com/AristaCommunity/s/article/DNS-Exfiltration-The-Light-at-the-End-of-the-DNS-Tunnel">DNS Exfiltration</a>  
- <a href="https://blog.gigamon.com/2021/01/20/dns-c2-sandwich-a-novel-approach/">DNS C2 Sandwich</a>

<img src="https://infoblox.b-cdn.net/wp-content/uploads/what-is-dns-tunneling.png" alt="infoblox.com">  

Source: infoblox.com  
# Method
In this guide we will add 2 DNS records to our domain, setup an Iodine(d) server and client and make an SSH connection through our established tunnel and setup a web browser proxy. This will achieve HTTPS traffic over DNS which will allow to bypass network firewalls and policies.
  
To bypass a hypothetical firewall and internal network policy using DNS tunneling we require the following:
- Access to an internet connected server (VPS or cloud server)
- Domain name with ability to add DNS records (A and NS)  
  
- Internal network (in which we want to bypass restrictions) that allows DNS queries and can reach the internet
- Client capable of using command-line utilities  

# DNS Configuration

To configure the DNS records, navigate to your registrar and add the following records to your domain. Note that it will take time for these records to propogate and the process may be slightly different depending on your registrars UI.  

GoDaddy: <a href="https://au.godaddy.com/help/add-an-a-record-19238">Guide</a>  
NameCheap: <a href="https://www.namecheap.com/support/knowledgebase/article.aspx/434/2237/how-do-i-set-up-host-records-for-a-domain/">Guide</a>

A Record:  
tunnel.[domain].[tld] --> [serverip]

NS Record:
ns.[domain].[tld] --> tunnel.[domain].[tld]

To verify the newly added DNS records, we can use the `DIG` utility as follows:  
{{< highlight bash >}}
$ DIG A [domain].[tld]
[snip]
[domain>.[tld].	86400	IN	A	[serverip]
[snip]	
...
$ DIG NS [domain>.[tld]
[snip]
tunnel.[domain].[tld].	86400	IN	NS	ns.[domain].[tld]
[snip]
{{< /highlight >}}

Our `A` record will point the subdomain `tunnel.` to the ip of our server, whilst the `NS` record of the subdomain `ns.` will point to our subdomain in which will point to our server ip. The A record is not required and we can point straight from a domain to our server ip in an `NS` record however it is good practice if we have multiple name servers we want to point to or multiple services being poited to from the domain.    
  
The `NS` record recognises the server as a nameserver in which it is able to recieve and send DNS queries.

# Iodine Server

To install iodine(d) we can clone the repo from <a href="https://github.com/yarrick/iodine">github</a> and build it from source.
IMPORTANT: Package Managers (e.g apt) iodine(d) version is <u>out of date.</u> This will only work with the latest version available on github.
{{< highlight bash >}}
git clone https://github.com/yarrick/iodine.git 
make -C iodine/
# make install
{{< /highlight >}}

To verify the instalation, we can run `iodined -v`  

{{< highlight bash >}}
$ iodined -v
iodine IP over DNS tunneling client
Git version: df49fd6
{{< /highlight >}}

We should be on the latest git version.
Running `iodined` without any arguments should present us with the use output.

{{< highlight bash >}}
$ iodined
Usage: iodined [-46cDfsv] [-u user] [-t chrootdir] [-d device] [-m mtu]
               [-z context] [-l ipv4 listen address] [-L ipv6 listen address]
               [-p port] [-n auto|external_ip] [-b dnsport] [-P password]
               [-F pidfile] [-i max idle time] tunnel_ip[/netmask] topdomain
{{< /highlight >}}

To start the iodine(d) server, we will run the following command:
{{< highlight bash >}}
$ iodined -f -c 10.0.0.1 -P '[connectionpassword]' ns.[domain].[tld]
{{< /highlight >}}

`-f` : Run in foreground  
`-c` : Prevent unexpected enviroment errors  
`10.0.0.1` : Internal Network Tunnel IP Adress, if the 10/ Network is already in use, you can use another (e.g 172/)  
`-P` '' : Set a password clients are required to connect with  
`ns.[domain].[tld]` : Our topdomain (NS record from earlier)  

We can use an online tool to verify we have started the server succesfully:
<a href="https://code.kryo.se/iodine/check-it/">Tool from code.kryo.se</a>

# Iodine Client

To connect a client to the iodine(d) server, we must repeat the install process on the client. The precedent follows:
{{< highlight bash >}}
git clone https://github.com/yarrick/iodine.git 
make -C iodine/
# make install
{{< /highlight >}}

To verify the instalation, we can run `iodine -v` 

{{< highlight bash >}}
$ iodine -v
iodine IP over DNS tunneling client
Git version: df49fd6
{{< /highlight >}}

We should be on the latest git version.
Running `iodine` without any arguments should present us with the use output.
{{< highlight bash >}}
$ iodine 
iodine IP over DNS tunneling client

Usage: iodine [-46fhrv] [-u user] [-t chrootdir] [-d device] [-P password]
              [-m maxfragsize] [-M maxlen] [-T type] [-O enc] [-L 0|1] [-I sec]
{{< /highlight >}}

To connect to our iodine(d) server, we will run the following command:
{{< highlight bash >}}
$ iodine -f -P '[connectionpassword]' -r ns.[domain].[tld]
{{< /highlight >}}
	
`-f` : Run in foreground  
`-P` '' : Connection Password  
`-r` :   
`ns.[domain].[tld]` : If you get a `BADIP` error, try replacing this with the servers raw ip.  

Once the connection is established, you should be hung on the output `Connection setup complete, transmitting data.`
Ive included a sample output of what a succesfully connect looks like below:  
{{< highlight bash >}}
No tun devices found, trying utun
iodine: open_utun: connect: Resource busy
iodine: open_utun: connect: Resource busy
iodine: open_utun: connect: Resource busy
Opened utun3
Opened IPv4 UDP socket
Sending DNS queries for ns.[domain].[tld] to [serverip]
Autodetecting DNS query type (use -T to override).
Using DNS type NULL queries
Version ok, both using protocol v 0x00000502. You are user #0
Setting IP of utun3 to 10.0.0.2
Adding route 10.0.0.0/27 to 10.0.0.2
add net 10.0.0.0: gateway 10.0.0.2
Setting MTU of utun3 to 1130
Server tunnel IP is 10.0.0.1
Skipping raw mode
Using EDNS0 extension
Switching upstream to codec Base128
Server switched upstream to codec Base128
No alternative downstream codec available, using default (Raw)
Switching to lazy mode for low-latency
Server switched to lazy mode
Autoprobing max downstream fragment size... (skip with -m fragsize)
768 ok.. 1152 ok.. ...1344 not ok.. ...1248 not ok.. ...1200 not ok.. ...1176 not ok.. 1164 ok.. will use 1164-2=1162
Setting downstream fragment size to max 1162...
Connection setup complete, transmitting data.
{{< /highlight >}}

# Test Connection 0.5

To verify traffic is being transmitted through the tunnel, attempt to ping the `tunnel IP` from your client, you can also ping the client from the server.
{{< highlight bash >}}
$ ping 10.0.0.1
PING 10.0.0.1 (10.0.0.1): 56 data bytes
64 bytes from 10.0.0.1: icmp_seq=0 ttl=64 time=58.203 ms
{{< /highlight >}}

This proves that we can transmit data through the DNS tunnel.

# HTTPS (socks5 proxy)

DNS traffic is <u>not</u> encrypted, therefore we will need to take further steps to encyrpt our traffic and browse via HTTPS.
To do this we will establish an SSH connection from our client to the server, and forward all our browsers network traffic through the SSH connection with a proxy.

The following command is to be run on the connected client. (do not exit0 the tunnel we established earlier)
{{< highlight bash >}}
$ ssh -ND [port] -i .[key].key [user]@[tunnelip] 
{{< /highlight >}}
NOTE: In this instance the [tunnelip] was `10.0.0.1` and the [port] was `31337` however the port can be configured to any.
	
`-N` : Do not execute a remote command.  
`-D` : Specifies a local “dynamic” application-level port forwarding. This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  
`-i` : Authenticate to the server with your key  
`[user]@[tunnelip]` : The server.  

No output will be shown from this command. To quickly verify no errors have occurs we can run `curl` with the socks5 proxy schema for a site that returns our ip address.
{{< highlight bash >}}
$ curl -x socks5h://127.0.0.1:[port] http://httpbin.org/ip
{
  "origin": "[serverip]"
}
{{< /highlight >}}
The output should return our [serverip]. Not our clients public IP.
	
To use this connection in a browser, we can modify our browsers to use a proxy, this will vary from browser to browser, however the essential parts are as follows:
- SOCKS HOST : 127.0.0.1
- SOCKS v5
- PORT : [port] (as specified in our ssh connection)
	
An alternative (and better) method from reconfiguring your browsers proxy is to install an extension called <a href="https://getfoxyproxy.org/">Foxyproxy</a>, (<a href="https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en">Chrome</a>, <a href="https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/">FireFox</a>)
This extension will allow us to add a proxy and switch between it easily.
Guide on how to add a proxy with FoxyProxy <a href="https://help.observepoint.com/article/154-foxyproxy-extension-configuring-the-liveconnect-proxy">here</a>
The same essentials as the browser configuration follow.
With FoxyProxy installed all you need to do is click the extension icon and the name of the proxy you added, the name should appear over the icon and turn green when selected.  

![FoxyProxy](/dnstunnelfirewall/proxy.png)
# Test Connection 1

To verify our connection in our browser, we can navigate to any site, if no errors are thrown and we make it succesfully to the site, it should indicate that we are connected, to further verify, we can navigate to a site such as <a href="https://ipchicken.com">ipchicken</a> which will present us with our ip address, if it shows us our [serverip] we can confirm that our browser session is connected! The extremely slow loading times may also indicate that it is working. DNS is not designed for this.
	
# Wireshark
![Wireshark](/dnstunnelfirewall/wireshark.png)
We can observe the traffic in wireshark and note the Tunnel IP (10.0.0.2) and port (6969) as our SSH connection.

My Network Speeds  
Download : 0.02  
Upload : 0.00  
Ping : 788.48  
Jitter : 227.33  

# Conclusion
Bypassing Network Policies and Firewalls with DNS tunnels can prove effective in many cases as DNS is considered to be an essential privledge for low level users to browse the internet, (within policy) DNS is often overlooked in IPS systems however taking advantage of this we can only get such a ~~fast~~ slow network connection to the free internet.
  
---------------- 

--> Share via <a href="https://torry.link/index/firewall-bypass-via-dns-tunnels-https/">link</a>  
--> Return to the <a href="https://torrytw.ooo/index/">Index</a>

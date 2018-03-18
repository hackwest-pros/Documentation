# TOC
- [Tools](#tools)
   - [Networking](#networking)
   - [Bluetooth](#bluetooth)
   - [Pentesting Frameworks](#penetration-testing-frameworks)
   - [DNS](#dns)
   - [ARP](#arp)
   - [Web Application Hacking](#web-applicatoin-hacking)
   - [Brute Forcing](#brute-forcing)
   - [FTP](#ftp)
   - [Routers](#routers)
   - [Printers](#printers)
   - [XSS](#xss)
   - [SQL](#sql)
   - [Social Engineering](#social-engineering)
   - [SSL](#ssl)
   - [RE](#re)
   - [Analysis](#analysis)
   - [Git](#git)
   - [Other](#other)
   - [Backdoors](#backdoors)
   - [RFID / NFC](#rfid--nfc)
   - [Fuzzers / Scanners](#fuzzers--scanners)
   - [Prvilege Escalation Scanners](#privilege-escalation-scanners)
   - [Cracking](#cracking)
   - [Collections](#collections)
 
 - [Informational Online Resources](#informational-resources)
   - [General](#general)
   - [APIs](#apis)
   - [Username / Password / Word / Default lists](#username--password--word--default--lists)
   
 - [How-to's](#how-to-write-ups)
   - [Stack exploitation](#stack)
   - [Heap exploitation](#heap)
   - [Kernel exploitation](#kernel)
 
 - [Challenges](#challenges)
   - [RE](#re-1)
 
 - [CTFs](#ctfs)
   - [Hosts](#hosts)
   - [Walkthroughs](#walkthroughs)
   - [Vulnerable VMs](#vulnerable-vms)
  
 - [Books / PDFs](#books--pdfs)
   - [Discrete Mathematics](#discrete-mathematics)
   - [Algorithms](#algorithms)
   - [OS Concept and Design](#os-concept-and-design)
   - [Programming](#programming)
   - [Security](#security)
   - [Other](#other)
 
# Tools
## Networking
- [Wifite](https://github.com/derv82/wifite2)
- [Inject and spy on wifi users](https://github.com/DanMcInerney/LANs.py)
- [Wifijammer](https://github.com/DanMcInerney/wifijammer)
- [Kismet](https://github.com/kismetwireless/kismet)
- [Mitmproxy (man in the middle tool)](https://github.com/mitmproxy/mitmproxy)
- [Net credential sniffer](https://github.com/DanMcInerney/net-creds)
- [Sniffer Packet Trace Parser for TCP, SMTP Emails, and HTTP Cookies](https://github.com/hgascon/pulsar)
- [Sparta (network infrastructure pen testing)](https://github.com/SECFORCE/sparta)
- [CyberScan](https://github.com/medbenali/CyberScan)
- [Aircrack-ng (wifi security auditing tool suite)](https://github.com/aircrack-ng/aircrack-ng)
- [Netcat](http://nc110.sourceforge.net/)
- [Wireshark](https://www.wireshark.org/)
- [MDK3](https://github.com/wi-fi-analyzer/mdk3-master)
- [PixieWPS - wps bruteforcing](https://github.com/wiire-a/pixiewps)
- [Fluxion - WPA MITM](https://github.com/FluxionNetwork/fluxion)
- [wifiphisher - rogue access point framework](https://github.com/wifiphisher/wifiphisher)
- [pig - network packet crafting utility](https://github.com/rafael-santiago/pig)
- [scapy - interactive packet maniupulation library](https://github.com/secdev/scapy)

## Bluetooth
- [Blue Hydra](https://github.com/pwnieexpress/blue_hydra)
- [BlueZ](http://www.bluez.org/)

## Penetration testing frameworks
- [Metasploit](https://github.com/rapid7/metasploit-framework)
- [BeEF - Browser explotation framework](https://github.com/beefproject/beef)

## DNS
- [DNS / subdomain enumaration](https://gist.github.com/stevenswafford/08fd11da7117daddc453)
- [Dnssearch](https://github.com/evilsocket/dnssearch)

## ARP
- [Arpspoof](https://github.com/byt3bl33d3r/arpspoof)
- [Ettercap](https://github.com/Ettercap/ettercap)
- [Bettercap](https://github.com/evilsocket/bettercap)

## Web Application Hacking
- [Admin panel finder](https://github.com/selftaught/AdminFinder)
- [Burp Suite](https://portswigger.net/burp)
- [Filebuster (web fuzzer)](https://github.com/henshin/filebuster)
- [WPForce](https://github.com/n00py/WPForce)

## Brute Forcing
- [Brutespray](https://github.com/x90skysn3k/brutespray)
- [BruteX (automatically brute all services running on target)](https://github.com/1N3/BruteX)

## FTP
- [Ftp-fuzz (ftp fuzzer)](https://git.io/vNZMB)
- [Ftpscout (ftp)](https://github.com/RubenRocha/ftpscout)

## Routers
- [Router exploitation](https://github.com/reverse-shell/routersploit)

## Printers
- [PRET (printer exploitation toolkit)](https://github.com/RUB-NDS/PRET)

## XSS
- [XSS spider (66/66 owasp vulns used)](https://github.com/DanMcInerney/xsscrapy) 

## SQL
- [Sqlmap (sql injection testing)](https://github.com/sqlmapproject/sqlmap)

## Social Engineering
- [Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
- [Maltego - interactive data mining tool that renders directed graphs for link analysis](https://docs.paterva.com/en/)
- [Recon-NG - full featured web reconnassiance framework](https://bitbucket.org/LaNMaSteR53/recon-ng/)

## SSL
- [A2sv (ssl vulnerability scanner)](https://github.com/hahwul/a2sv)
- [SSLStrip](https://github.com/moxie0/sslstrip)
- [SSLSniff - automated MITM on SSL connections](https://github.com/moxie0/sslsniff)
- [SSLSplit](https://github.com/droe/sslsplit)

## RE
- [Androguard - Reverse engineer Android applications](https://github.com/androguard/androguard)
- [Apk2Gold - Yet another Android decompiler](https://github.com/lxdvs/apk2gold)
- [ApkTool - Android Decompiler](http://ibotpeaches.github.io/Apktool/)
- [Barf - Binary Analysis and Reverse engineering Framework](https://github.com/programa-stic/barf-project)
- [BinUtils - Collection of binary tools](http://www.gnu.org/software/binutils/binutils.html)
- [BinWalk - Analyze, reverse engineer, and extract firmware images.](https://github.com/devttys0/binwalk)
- [Boomerang - Decompile x86 binaries to C](https://github.com/nemerle/boomerang)
- [Voltron - Debugger enhancements](https://github.com/snare/voltron)
- [Radare2 - unix-like reverse engineering framework and commandline tools](https://github.com/radare/radare2)
- [GEF - GDB Enhanced Features](https://github.com/hugsy/gef/)
- [SMAP - Shellcode Mapper](https://github.com/rootlabs/smap/)
- [Cutter - Radare2 QT GUI](https://github.com/radareorg/cutter)
- [MSFvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [pwntools](https://github.com/Gallopsled/pwntools)
- [Unicorn - CPU emulator](http://www.unicorn-engine.org/)
- [OllyDBG v1/2 - assembler level debugger](http://www.ollydbg.de/)
- [ROP Gadget](https://github.com/JonathanSalwan/ROPgadget)
- [DLL Injector](https://github.com/OpenSecurityResearch/dllinjector)

## Analysis
- [Angr - platform-agnostic binary analysis framework](https://github.com/angr/angr)
- [Binary Ninja - Binary analysis framework](https://binary.ninja/)
- [Sniffer (Packet Trace Parser for TCP, SMTP Emails, and HTTP Cookies)](https://github.com/hgascon/pulsar)
- [Tcpdump (networking packet analyzer)](https://github.com/the-tcpdump-group/tcpdump)
- [NFdump (networking flow analysis)](https://github.com/phaag/nfdump)
- [binwalk - firmware analysis tool](https://github.com/ReFirmLabs/binwalk)
- [stoq](https://stoq-framework.readthedocs.io/en/latest/)
- [volatility - advanced memory analysis framekwork](https://github.com/volatilityfoundation/volatility)

## Git
- [Githack](https://github.com/lijiejie/githack)
- [Gitrob (finding sensitive information on github)](https://github.com/michenriksen/gitrob)
- [GitHarvester](https://github.com/metac0rtex/GitHarvester)

## Other
- [Datasploit (gather information about a domain)](https://github.com/zanyarjamal/DataSploit)
- [Evercookie (persistent cookies)](https://github.com/samyk/evercookie)
- [Random Insecure VM Generator](https://github.com/cliffe/SecGen)

## RFID / NFC
- [Magspoof (magstrip spoofer)](https://github.com/samyk/magspoof)

## Backdoors
- [Poisontap (persistent backdoor via usb dropper)](https://github.com/samyk/poisontap)

## Fuzzers / Scanners
- [wpscan](https://github.com/wpscanteam/wpscan)
- [Findsploit](https://github.com/1N3/Findsploit)
- [Sn1p3r](https://github.com/1N3/Sn1per)
- [Google dork vulnerability scan](https://github.com/utiso/dorkbot)
- [Fast-recon (google / pastebin dorking)](https://github.com/DanMcInerney/fast-recon)
- [Striker (information and vulnerability recon)](https://github.com/UltimateHackers/Striker)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Sparta (network infrastructure pen testing)](https://github.com/SECFORCE/sparta)
- [Autopwn (automatically run vuln tests against host)](https://github.com/nccgroup/autopwn)
- [CyberScan](https://github.com/medbenali/CyberScan)
- [ShodanHat](https://github.com/HatBashBR/ShodanHat)
- [SearchSploit](https://www.exploit-db.com/searchsploit/#install)
- [nmap vulnerability scanning](https://github.com/scipag/vulscan)
- [nmap vulnerability scanning scripts](https://github.com/cldrn/nmap-nse-scripts)
- [masscan](https://github.com/robertdavidgraham/masscan)
- [httrack - website copier](https://github.com/xroche/httrack)

## Privilege escalation scanners
- [PrivEsc (collection of linux and windows priv esc vulns)](https://github.com/1N3/PrivEsc)

## Cracking
- [Hashcat - World's fastest and most advanced password recovery utility](https://github.com/hashcat/hashcat)
- [John The Ripper - A password cracker available for many distros of linux](https://github.com/magnumripper/JohnTheRipper)
- [THC hydra - login cracker](https://www.thc.org/thc-hydra)
- [Ophcrack - Windows password cracked based on rainbow tables](http://ophcrack.sourceforge.net/)

## Collections
- [Pentest scripts](https://github.com/ChrisTruncer/PenTestScripts)

# Informational resources
## General
- [Generic Security Resources](https://github.com/danielmiessler/SecLists)

## APIs
- [API security checklists](https://github.com/shieldfy/API-Security-Checklist)

## Username / Password / Word / Default lists
- [Wordlist](https://raw.githubusercontent.com/jeanphorn/wordlist)
- [Default-Credentials](https://github.com/netbiosX/Default-Credentials)
- [defaultpassword.com](http://www.defaultpassword.com/)
- [SecLists/Passwords](https://github.com/danielmiessler/SecLists/tree^/master/Passwords)
- [CeWL - (Wordlist generator)](https://github.com/digininja/CeWL)
- [CrackStation wordlists](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm)

## Neural Networks
- [Darknet Neural Network](https://github.com/pjreddie/darknet)

# Challenges
## RE
 - [0x00sec](https://0x00sec.org/c/reverse-engineering/challenges)
 
# How-to write-ups
## Exploitation
### Stack
   - [ret2libc](https://gist.github.com/selftaught/4ff7e46d0142e951f4b6008780ef0487)
   - [remote exploit - shellcode without sockets](https://0x00sec.org/t/remote-exploit-shellcode-without-sockets/1440/5)
   - [x64 ROP](https://0x00sec.org/t/64-bit-rop-you-rule-em-all/1937/3)
   - [Smashing the Stack for Fun and Profit](http://insecure.org/stf/smashstack.html)
   
### Heap
   - [fastbin attack](https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627)
   - [UAF (use after free)](https://0x00sec.org/t/heap-exploitation-abusing-use-after-free/3580)

### Kernel
   - [Dereferencing a NULL pointer](https://0x00sec.org/t/kernel-exploitation-dereferencing-a-null-pointer/3850/4)
   
# CTFs
## Hosts
- [CTF365](https://ctf365.com/)
- [RHme3](https://rhme.riscure.com/3/content?show=about)
- [Hacking-Lab](https://www.hacking-lab.com/index.html)
- [Practical Pentest Labs](https://practicalpentestlabs.com/)

## Walkthroughs
- [0x00sec](https://0x00sec.org/c/ctf)
- [picoCTF - bypassing ASLR via format string bug](https://0x00sec.org/t/picoctf-write-up-bypassing-aslr-via-format-string-bug/1920)
- [Azeria labs ARM exploitation](https://azeria-labs.com/writing-arm-assembly-part-1/)

# Vulnerable VM sources
- [vulnhub](https://www.vulnhub.com/)
- [Metasploitable](https://information.rapid7.com/metasploitable-download.html)

# Books / PDFs

## Discrete Mathematics

- [Concrete Mathematics](https://www.amazon.com/Concrete-Mathematics-Foundation-Computer-Science/dp/0201558025/)

## Algorithms

- [The Algorithm Design Manual](https://www.amazon.com/Algorithm-Design-Manual-Steven-Skiena/dp/1849967202/)

## OS Concepts and Design

- [Design Patterns: Elements of Reusable Object-Oriented Software](https://www.amazon.com/Design-Patterns-Elements-Reusable-Object-Oriented/dp/0201633612/ref=sr_1_1?ie=UTF8&qid=1514762086&sr=8-1&keywords=design+patterns)

## Programming

### C/C++
- [Effective C++](http://a.co/hC555os)
- [More Effective C++](http://a.co/2rpkwM3)
- [The Linux Programming Interface](https://www.nostarch.com/tlpi)

### Assembly
- [The Art of Assembly Language](http://amzn.to/2jlxTNp)
- [Introduction to 64 Bit Intel Assembly Language Programming for Linux: Second Edition](http://a.co/aMRK68Z)

### Perl
- [Learning Perl](http://shop.oreilly.com/product/0636920018452.do)
- [Intermediate Perl](http://shop.oreilly.com/product/0636920012689.do)
- [Mastering Perl](http://shop.oreilly.com/product/9780596527242.do)

## Security 
### Analysis & Forensics
- [Practical Forensic Imaging](https://nostarch.com/forensicimaging)
- [Practical Malware Analysis](https://www.amazon.com/Practical-Malware-Analysis-Hands-Dissecting/dp/1593272901)
- [Malware Analyst's Cookbook](http://amzn.to/2iWPJDd)
- [The Art of Memory Forensics](http://amzn.to/2jMJQs0)
- [Fuzzing for Software Security](http://amzn.to/2jMKCWc)
- [Art of Software Security Assessment](http://amzn.to/2jlvtyt)

### Reverse Engineering
- [Hacking: The Art of Exploitation](https://www.nostarch.com/hacking2.htm)
- [Practical Reverse Engineering](https://www.amazon.com/Practical-Reverse-Engineering-Reversing-Obfuscation/dp/1118787315)
- [Reversing: Secrets of Reverse Engineering](https://www.amazon.com/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817)
- [Reverse Engineering for Beginners](https://beginners.re/)
- [The IDA Pro Book](http://amzn.to/2jTicOg)
- [Gray Hat Hacking](http://amzn.to/2jllIAi)
- [The Antivirus Hacker's Handbook](http://amzn.to/2jn9G99)
- [The Rootkit Arsenal](http://amzn.to/2jlgioK)
- [Windows Internals Part 1](http://amzn.to/2jlo9mA) [Part 2](http://amzn.to/2jMLCth)
- [Inside Windows Debugging](http://amzn.to/2iqFTxf)
- [iOS Reverse Engineering](https://github.com/iosre/iOSAppReverseEngineering)

## Other
 
- [Code: The Hidden Language of Computer Hardware and Software](https://www.amazon.com/Code-Language-Computer-Hardware-Software/dp/0735611319)
- [The GNU Make Book](http://a.co/26MhWkM)
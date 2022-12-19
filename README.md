---
layout: page
title: "Cyber Security Resources"
permalink: /cyberresources
---

# General Infosec

### MITRE Att&ck Framework
Mittre Att&ck is a knowledge base of adversary tactics and techniques. This resource attempts to comprehensively categorize all known methods of accomplishing adversarial tactics.

It is a great resource to know how to use. Not something you need to or perhaps even can memorize. I found value in reading through all the different techniques, Googling what I did not understand.


# Threat Intelligence Resources

### Threat Intelligence Research Groups
You will find many threat research publications and blogs. The groups specified bellow generally offer information relevant to an operational level of understanding. Tactical Intelligence sources are provided bellow in Threat Intel Content Development. <br>

## Security Vendors Threat Blogs
[CrowdStrike](https://www.crowdstrike.com/blog/)<br>
[RiskIQ Articles](https://community.riskiq.com/research)<br>
[PaloAlto's Unit42](https://blog.paloaltonetworks.com/author/unit-42/)<br>
[Cisco Talos](https://blog.talosintelligence.com/)<br>
[Intel471](https://intel471.com/blog/)<br>
[digital_shadows](https://www.digitalshadows.com/blog-and-research/)<br>
[ThreatConnect Blog](https://threatconnect.com/blog/)<br>
[DomainTools Blog](https://www.domaintools.com/)
<br> <br>

### Federal Agency Threat Blogs
[CISA Cybersecurity Blog](https://www.cisa.gov/blog-list/Cybersecurity)<br>
[CERT Alerts](https://us-cert.cisa.gov/ncas/alerts) & [CERT Current Activity](https://us-cert.cisa.gov/ncas/current-activity)
<br><br>

### Meet the Adversaries
###### Resources to learn about the adversaries that are prolific enough to be identified, named, and tracked. <br>
[APT Groups and Operations Matrix](https://apt.threattracking.com) <br>
[Crowdstrike Classifications](https://www.crowdstrike.com/blog/meet-the-adversaries/)
<br><br>


## Basic Web Resources for Operations or Research
### Sandboxes
[HybridAnalysis](https://www.hybrid-analysis.com/)<br>
tags: #windows #macos #linux <br>
[JoesSandbox Cloud](https://www.joesandbox.com/#windows)<br>
tags: #windows #macos #adnroid #linux #ios
<br><br>

### Threat Intell Content Development
[VirusTotal](https://www.virustotal.com/gui/home/url)<br>
tags: #file #url #domain #host <br>
[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)<br>
tags: #ip #url #domain #email #cve #cidr #filehash #filepath #mutex #yara #tag <br>
[Open Threat Exchange](https://otx.alienvault.com/)<br>
tags: #ip #url #domain #email #cve #cidr #filehash #filepath #mutex #yara  <br>
[PassiveTotal](https://community.riskiq.com/search) <br>
tags: #domains #host #ips #sslcert #contactemail <br>
[DomainTools](https://whois.domaintools.com/) <br>
tags: #domain #ip<br>
[Talos](https://talosintelligence.com/)<br>
tags: #domain #ip #contactemail <br>
[ThreatCrowd](https://www.threatcrowd.org/)<br>
tags: #doamin #ip #email #organization<br>
[ThreatMiner](https://www.threatminer.org/)<br>
tags: #domain #ip #filehash #email #ssl #ua #filename #registry #mutex
<br><br>

### Email Analysis Tools
[Google Admin Toolsbox - Messageheader](https://toolbox.googleapps.com/apps/messageheader/)
<br><br>



### External Research Tools
[DNSDumpster](https://dnsdumpster.com/)<br>
[Shodan](https://www.shodan.io/)
<br><br>

### Other Favored Blogs
[Splunk Blogs](https://www.splunk.com/en_us/blog)<br>


## Train Hard, Train Smart
The InfoSec profession does require a good deal of knowledge; but high performing security practitioners are those with an equally impressive skill set through which they can act on that knowledge. Simulations are a great way to strengthen and develop these skills.

Capture the Flag or CTF exercises are a great way to understand some of the tools and thought process of an adversary. Typically, CTF style exercises involve compromising systems to find hidden flags which prove the accomplishment of some gained level of access. While they primary simulate activity of an adversary, you can also attempt to monitor the exercise environment and then review the generated artifacts to practice finding attacks in audit data. This can include system logs from a compromised device, a firewall or IDS such as Suricata and Snort, a network traffic analysis tool such as Zeek, or even simply a packet capture from the exercise.

[VulnHub](https://www.vulnhub.com/) is a created repository of community contributed VMs made vulnerable by design for various training purposes. While you can attempt to detect your self in logs, nothing prohibits you from attempting to secure the VMs from the same attacks you used to gain access.

### My home lab consists of the following networks ###
The following is just some details on what my current home lab looks like. At most, it contains some recommendations. It certainly is not optimal.
1. A class B network for community made CTF targets such as those from VulnHub.
2. A class B "Attack Targets" network
3. Security monitoring controls and domain resources share a VLAN.
4. A class C client network for my laptops or attacking VMs.
5. A class B network for log collection (Logstash and Splunk Universal Forwarder)
6. A Pfsense Firewall that connects to an interface on my home WiFi + Router Combo. This Firewall will be your edge.

The Attack Targets network consists of multiple operating systems both server and client with multiple versions. This network contains various services designed to mimic what might be found in a typical environment. It has grown organically over the years. I advise creating several snapshots of "golden images" that contain configuration for security monitoring software such as Sysmon, Splunk UF, or Logstash. Another alternative is to use something like Ansible or Puppet to automate this configuration.

*Pro Tip: I use KVM; however, if you use ESXi, you can take various partial snapshots before major security updates or periodically. This can allow you to restore or create new VMs from snapshots to test attacks on vulnerabilities you may have patched in your environment. I have found this to save on storage requirement*

### Security Monitoring for Attack Targets ###

**Windows Monitoring**
1. Sysmon
2. Windows Event Logs (System, Security, and Application)
3. Periodic output of various admin tools (netstat, pslist, etc)
Splunk UF is used to Collect Logs + run scripts

**Linux Monitoring**
1. /var/log/messages
2. /var/log/secure
3. /var/log/syslog (syslog-ng)
4. /var/log/auth.log
5. /var/log/faillog
6. Periodic output of various admin tools (netstat, pslist, etc

  A simple $30 TP link switch allows me to select one network interface to use as a mirror for the rest of my networking interfaces. This allows me to use Corelight with a home client to send Zeek and Suricata logs to my Splunk and ELK stack.

  *Note: I had also performed packet captures with this device in the past; however, am unaware if that would interfere with Corelight currently.*

**File Extension Cheat Sheet**
- 7zip : 7-zip archive format
- bzip2 : bzip2 archive format
- cab : cab file format
- dat : data file format
- dmp : memory dump
- docx : microsoft word
- dwg : drawings
- dxf : cad file format for autodesk
- ese : database file format
- idw : image file format for autodesk
- jar : java archive
- macho : binary executable format
- ole : object linking and embedding
- ooxml : office open xml
- pdf : pdf
- pe : pe
- pptx : microsoft powerpoint
- rar : rar archive format
- rtf : rich text format
- script : script file
- sld : slide format for autocad
- tar : tar archive format
- vsdx : microsoft visio
- xar : xar archive format
- xlsx : microsoft excel
- zip : zip archive

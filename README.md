![Pafish Macro screenshot](https://github.com/joesecurity/Joe-Sandbox-Splunk-Addon/blob/master/splunk-integration.p?raw=true)

# Joe Sandbox Splunk Addon Readme
This plugin feeds Joe Sandbox JSON reports automatically into Splunk.

## Installation & Setup

1. Download .tgz package
2. Go to Splunk Home > Manage Apps (Apps Cog Icon) > Install app from File > Upload the downloaded File
3. Go to Apps > Joe Sandbox Addon > Inputs > Create New Input
4. Enter Name, Interval, Index, API URL, API KEY, Minimum Report ID and click Add
5. Go to Search and Report and Enter `sourcetype=jbx` to see downloaded reports.

## Search command Examples:

### List all samples
```
sourcetype=jbx | table fileinfo.filename, generalinfo.target.url, generalinfo.id, fileinfo.md5, signaturedetections.strategy{}.detection
```

### search for sample based on md5, sha1, sha256 or sha512 hash
```
sourcetype=jbx | search "fileinfo.md5"=57e92a7ccfa4f741250afaf221d85cd6 | table fileinfo.filename
sourcetype=jbx | search "fileinfo.sha1"=5f64eabfda76c2140c114464b9842d1c60057060 | table fileinfo.filename
sourcetype=jbx | search "fileinfo.sha256"=6ceac0135811caae965f6f619bb3a5978051be3a200abd265d89589666361b09 | table fileinfo.filename
sourcetype=jbx | search "fileinfo.sha512"=2bbc9ea47be98866fca7ba0c961876977c25e215837c38789ee8f430172c965c462be1e89c230acc77abbe51d899dec375302fdb8b58dbddaec46ba8c4a6d3c6 | table fileinfo.filename
```

### search for dropped PE files
```
sourcetype=jbx | rename "droppedinfo.hash{}.@type" as dropped_type, "droppedinfo.hash{}.@file" as dropped_file, "generalinfo.id" as id | eval temp=mvzip(dropped_type,dropped_file, "|") | mvexpand temp | eval dropped_type=mvindex(split(temp,"|"),0) | eval dropped_file=mvindex(split(temp,"|"),1) | search dropped_type="PE*" | table id, dropped_type, dropped_file
```

### search for dropped malicious files
```
sourcetype=jbx | rename "droppedinfo.hash{}.@malicious" as dropped_malicious, "droppedinfo.hash{}.@file" as dropped_file, "generalinfo.id" as id | eval temp=mvzip(dropped_malicious,dropped_file, "|") | mvexpand temp | eval dropped_malicious=mvindex(split(temp,"|"),0) | eval dropped_file=mvindex(split(temp,"|"),1) | search dropped_malicious="true" | table id, dropped_file
```

### search for dropped files with a high entropy
```
sourcetype=jbx | rename "droppedinfo.hash{}.@entropy" as dropped_entropy, "droppedinfo.hash{}.@file" as dropped_file, "generalinfo.id" as id | eval temp=mvzip(dropped_entropy,dropped_file, "|") | mvexpand temp | eval dropped_entropy=mvindex(split(temp,"|"),0) | eval dropped_file=mvindex(split(temp,"|"),1) | search dropped_entropy>6.9 | table id, dropped_file
```

### list all connected IPs
```
sourcetype=jbx | table "ipinfo.ip{}.@ip" 
```

### search sample based on connected IP
```
sourcetype=jbx | search "ipinfo.ip{}.@ip"="172.217.168.34" | table fileinfo.filename, generalinfo.target.url, generalinfo.id

# Network TCP
sourcetype=jbx "behavior.network.tcp.packet{}.dstip"="172.217.168.34" | table fileinfo.filename, generalinfo.target.url, generalinfo.id

# Network UDP
sourcetype=jbx "behavior.network.udp.packet{}.dstip"="8.8.8.8" | table fileinfo.filename, generalinfo.target.url, generalinfo.id

# Network ICMP
sourcetype=jbx "behavior.network.icmp.packet{}.dstip"="255.255.255.0" | table fileinfo.filename, generalinfo.target.url, generalinfo.id
```

### search for malicious IPs
```
sourcetype=jbx | rename "ipinfo.ip{}.@malicious" as ip_malicious, "ipinfo.ip{}.@ip" as ip_value, "generalinfo.id" as id | eval temp=mvzip(ip_malicious,ip_value, "|") | mvexpand temp | eval ip_malicious=mvindex(split(temp,"|"),0) | eval ip_value=mvindex(split(temp,"|"),1) | search ip_malicious="true" | table id, ip_value
```

### search for malicious IPs and list source process
```
sourcetype=jbx | rename "ipinfo.ip{}.@malicious" as ip_malicious, "ipinfo.ip{}.@currentpath" as ip_process, "generalinfo.id" as id | eval temp=mvzip(ip_malicious,ip_process, "|") | mvexpand temp | eval ip_malicious=mvindex(split(temp,"|"),0) | eval ip_process=mvindex(split(temp,"|"),1) | search ip_malicious="true" | table id, ip_process
```

### search for sample based on URL
```
sourcetype=jbx | search "urlinfo.url{}.@name"="http://www.typography.net"| table fileinfo.filename, generalinfo.target.url, generalinfo.id
```

### search for malicious URLs
```
sourcetype=jbx | rename "urlinfo.url{}.@malicious" as url_malicious, "urlinfo.url{}.@name" as url_value, "generalinfo.id" as id | eval temp=mvzip(url_malicious,url_value, "|") | mvexpand temp | eval url_malicious=mvindex(split(temp,"|"),0) | eval url_value=mvindex(split(temp,"|"),1) | search url_malicious="true" | table id, url_value
```

### search for sample based on connected domain
```
sourcetype=jbx | search "domaininfo.domain{}.@name"="maxxflooring.company"| table fileinfo.filename, generalinfo.target.url, generalinfo.id
```

### search for malicious domains
```
sourcetype=jbx | rename "domaininfo.domain{}.@malicious" as domain_malicious, "domaininfo.domain{}.@name" as domain_value, "generalinfo.id" as id | eval temp=mvzip(domain_malicious,domain_value, "|") | mvexpand temp | eval domain_malicious=mvindex(split(temp,"|"),0) | eval domain_value=mvindex(split(temp,"|"),1) | search domain_malicious="true" | table id, domain_value
```

### search for all samples with a valid PE certificate
```
sourcetype=jbx | search "fileinfo.pe.signature.sigvalid"="true"
```

### search for all samples with a given signature issuer of a PE certificate
```
sourcetype=jbx | search fileinfo.pe.signature.sigissuer="*digi*" | table fileinfo.pe.signature.sigissuer
```

### search for all samples documents which contain VBA code
```
sourcetype=jbx | search fileinfo.ole.olefile{}.overview.indicators.vbamacros="true" | table "fileinfo.filename"
```

### search for all sample documents which contain VBA code and a VBA keyword
```
sourcetype=jbx | search fileinfo.ole.olefile{}.entries.entry{}.stream.valueascii="*Document_Open*" | table "fileinfo.filename"
```

### search for all samples which created a file in C:\Windows
```
source=jbx | rename "behavior.system.processes.process{}.fileactivities.fileCreated.call{}.path" as fileCreated_path, "generalinfo.id" as id | mvexpand fileCreated_path | search fileCreated_path="C:\\Windows\\*" | table id, fileCreated_path
```

### search for all samples which created an autostart registry key
```
source=jbx | rename "behavior.system.processes.process{}.registryactivities.keyValueCreated.call{}.path" as keyValueCreated, "generalinfo.id" as id | mvexpand keyValueCreated | search keyValueCreated="*Run*" | table id, keyValueCreated
```

### search for all samples which hooked the "send" Win32 call
```
sourcetype=jbx | search behavior.hooks.user.process{}.module.hook{}.@hfunc="send" | table "generalinfo.id", "fileinfo.filename"
```

### search for all samples which injected into explorer.exe
```
sourcetype=jbx | search behavior.system.processes.process{}.general.name="explorer.exe" | search behavior.system.processes.process{}.general.reason="extstingprocessinject" | table "generalinfo.id", "fileinfo.filename"
```

### search for all samples which injected into explorer.exe and contacted an IP address in Virgin Islands
```
sourcetype=jbx | search behavior.system.processes.process{}.general.name="explorer.exe" | search behavior.system.processes.process{}.general.reason="extstingprocessinject" | search "ipinfo.ip{}.@country"="*Virgin Islands*" | table "generalinfo.id", "fileinfo.filename", "ipinfo.ip{}.@country"
```

### search for all samples which started powershell
```
sourcetype=jbx | search behavior.system.processes.process{}.general.name="powershell.exe" | table "generalinfo.id", "behavior.system.processes.process{}.general.cmdline"
```

### search powershell event log (transcript)
```
sourcetype=jbx | search "behavior.system.processes.process{}.powershellactivities.eventlog.call{}.name"="ScriptBlockText" | table "generalinfo.id", "behavior.system.processes.process{}.powershellactivities.eventlog.call{}.execution"
```

### list all malicious behavior signatures
```
sourcetype=jbx | rename "signatureinfo.sig{}.@impact" as sig_impact, "signatureinfo.sig{}.@desc" as sig_desc, "generalinfo.id" as id | eval temp=mvzip(sig_impact,sig_desc, "|") | mvexpand temp | eval sig_impact=mvindex(split(temp,"|"),0) | eval sig_desc=mvindex(split(temp,"|"),1) | search sig_impact>=2 | table id, sig_impact, sig_desc
```

### hit statistic for best behavior signature
```
sourcetype=jbx | rename "signatureinfo.sig{}.@impact" as sig_impact, "signatureinfo.sig{}.@desc" as sig_desc, "generalinfo.id" as id | eval temp=mvzip(sig_impact,sig_desc, "|") | mvexpand temp | eval sig_impact=mvindex(split(temp,"|"),0) | eval sig_desc=mvindex(split(temp,"|"),1) | search sig_impact>=2 | chart count by sig_desc
```

### search for all samples with a strong "ransomware" classification
```
sourcetype=jbx | rename "signatureclassifications.classification{}.scores.score{}.@classname" as class_name, "signatureclassifications.classification{}.scores.score{}.@value" as class_score, "generalinfo.id" as id | eval temp=mvzip(class_name,class_score, "|") | mvexpand temp | eval class_name=mvindex(split(temp,"|"),0) | eval class_score=mvindex(split(temp,"|"),1) | search class_name="Ransomware" class_score>=4 | table id, class_score
```

### search for all samples which use a specific MITRE ATT&CK technique
```
sourcetype=jbx | search mitreattack.tactic{}.technique{}.id="t1022" | table "generalinfo.id", "mitreattack.tactic{}.technique{}.id"
```

### search for all samples which match a specific yara rule
```
sourcetype=jbx | search yara.sample.hit{}.rule="Embedded_PE" | table "generalinfo.id", "yara.sample.hit{}.rule", "yara.droppedfiles.hit{}.rule", "yara.memorydumps.hit{}.rule"
```

### search for all samples which have Antivirus detections
```
sourcetype=jbx | search avhit.sample.hit{}.positives!="0" | table avhit.sample.hit{}.source, avhit.sample.hit{}.positives, avhit.sample.hit{}.cloud, avhit.sample.hit{}.label, generalinfo.id
```

## Visualize detections scores and verdicts
To visualize maliciousness score over time enter the following line in the search field and click visualize
```
sourcetype=jbx | timechart span=1s values("signaturedetections.strategy{}.score") as Score
```

To visualize detection verdicts over time enter the following line in the search field and click visualize
```
sourcetype=jbx | timechart span=1s count by "signaturedetections.strategy{}.detection"
```

## Troubleshooting
The addon saves report IDs that have been downloaded in the Splunk KV Store. If in anycase you like to reset the KV Store you can do so by executing the following command (this may require admin/super user rights):
```
splunk clean kvstore -app Joe-Sandbox-Addon -collection Joe_Sandbox_Addon_checkpointer

```
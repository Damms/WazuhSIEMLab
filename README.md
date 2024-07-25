# Wazuh SIEM Lab

## Objective

The Wazuh SIEM Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks based on the [YouTube video by John Hammond](https://youtu.be/i68atPbB8uQ?si=dYoGtUtZLdhDnjwI). The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios, integrate open source intelligence and automate response. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

![image](https://github.com/user-attachments/assets/b7a90e1f-022d-42db-9d04-5fd3219f4b31)


### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Integration of open source intelligence.
- Automated response

### Tools Used

- Wazuh Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Telemetry generation tools to create realistic network traffic and attack scenarios.
- Virus Total integration for open source intelligence.
- MITRE ATT&CK Framework

### Prerequisites 
Hypervisor, I am using [VMWare Workstation Pro](https://www.vmware.com/products/workstation-pro/html.html), but [Virtual Box](https://www.virtualbox.org) is a free alternative.

## Steps
All up to date steps to setup Wazuh can be found using the [quickstart](https://documentation.wazuh.com/current/quickstart.html) and the [proof of concept](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html) guides.

1. [Create VM for Wazuh Server](#part1)
2. [Install Wazuh](#part2)
3. [Add Wazuh Agent](#part3)
4. [Enable vulnerability detection](#part4)
5. [Create some security events!](#part5)
6. [Create automated response | Wazuh Agent](#part6)
7. [Create automated response | Wazuh server](#part7)


<a id="part1"></a>
### Step 1: Create VM for Wazuh Server
Spin up a VM for Ubuntu with resources aligning to the Wazuh documentation
<p align="left">
  <img src="https://github.com/user-attachments/assets/88af8182-fc9f-47d2-9413-8d78397d2f36" />
</p>



Below is my VM configuration
<p align="left">
  <img src="https://github.com/user-attachments/assets/09029662-a33e-4dc4-999d-53f7975dcf3c" />
</p>



<a id="part2"></a>
### Step 2: Install Wazuh
Once Ubuntu is up and running install Wazuh using the following
```
  curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

When Wazuh has finished installing the admin password will be printed in the terminal, take note of this and login to your Wazuh dashboard on any browser by typing in your device ip or local host.
![image](https://github.com/user-attachments/assets/c2a467ca-4577-48b5-89de-e7d04fb647f0)



_Note down the device's ip address, this will be needed when setting up Wazuh agents_

<a id="part3"></a>
### Step 3: Add Wazuh Agent
Now I can install a Wazuh Agent into another VM to start sending information back for our Wazuh server.

Navigate to the Wazuh server ip address using any browser and login using the credentials generated in step 2. Once logged into the Wazuh dashboard click on "Add Agents", then follow the wizard to get the command to install.

![image](https://github.com/user-attachments/assets/a0f00d79-41dc-478d-a564-9c70c8478eb6)

Below example is the command I will use to install the Wazuh agent on another Windows VM via PowerShell
```
  Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.4-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.68.113' WAZUH_REGISTRATION_SERVER='192.168.68.113'
```

After installing the Wazuh agent on the VM of your choice start up the service, e.g. for my Windows VM `NET START WazuhSvc`

Repeat this for as many Wazuh agents as you would like to add.

Now refresh the Wazuh dashboard and see the new agent has been added successfully.
![image](https://github.com/user-attachments/assets/93a517bb-34ad-4977-8d7a-f4b7e9c9923f)


<a id="part4"></a>
### Step 4: Enable vulnerability detection 
To enable vulnerability detection I need to configure the Wazuh server. On the Wazuh Server navigate to the `/var/ossec/etc` directory. Here I want to open the ossec.conf file, this is the config file for the Wazuh server. Scroll down until you find vulnerability-detector and change it from _no_ to _yes_ ![image](https://github.com/user-attachments/assets/6a8c78e4-4f00-4a3e-aee8-89b2a362562f)

Save and close the config file, then restart the Wazuh server 
```
  systemctl restart wazuh-manager
```



<a id="part5"></a>
### Step 5: Create some security events!
Now it's time to be creative and do what you need to create some security events, I will achieve this by using [ninite](https://ninite.com/) to download a bunch of applications.

According to the config file, Wazuh should interval scan for vulnerabilities every 5 mins. After downloading a bunch of applications on my Windows VM there is alot of vulnerabilites found!

![image](https://github.com/user-attachments/assets/6d1a406c-2b1a-4e58-94d7-b8cebd8ceb5a)

On my ubuntu VM I can install [Invoke Atomic](https://github.com/redcanaryco/invoke-atomicredteam/wiki) and simulate some real attacks to create more events.

Once Invoke Atomic has downloaded I can start to simulate attacks! I went into the Wazuh dashboard and used the MITRE ATT&CK framework to find attacks.

![image](https://github.com/user-attachments/assets/07e10ed5-c2a3-4d93-a285-45b03743d208)

Here I will try [T1003.008](https://attack.mitre.org/techniques/T1003/008/) you can click on this in Wazuh to get some more information on the attack.
![image](https://github.com/user-attachments/assets/be1bc578-d334-444b-9d4f-50b7730cadb0)

Follow the below commands to invoke this attack on the ubuntu machince.
```Invoke-AtomicTest``` followed by the technique ID ```T1003.008``` and then _enter_

These events can also be viewed in Wazuh

<a id="part6"></a>
### Step 6: Create automated response | Wazuh Agent

Now I will use [Wazuh Virus Total integration](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html) to add file integrity monitoring and automatically respond.

I added a active response script to the Wazuh agent to remove malicious files.

_The below steps modifying the Wazuh agent config can be done via the Wazuh dashboard too_
In the Wazuh Agent (Ubuntu) navigate to /var/ossec/etc and open the ossec.conf file.

Navigate to the file integrity monitoring section in the config file and add a new directory to monitor real time, in this case I will add the Downloads folder.
```
  <directories realtime="yes">/home/user/Downloads</directories>
```
![image](https://github.com/user-attachments/assets/95ff5626-20ec-4517-b006-6743d9f0f7b5)

Install jq
```
  sudo apt update
  sudo apt -y install jq
```
Create a new bash script called _"remove-threat.sh"_ in the `/var/ossec/active-response/bin` directory with the below content saved in the script, this script will remove the file specified in the JSON input.
```
#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]
then
 # Send control message to execd
 printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

 read RESPONSE
 COMMAND2=$(echo $RESPONSE | jq -r .command)
 if [ ${COMMAND2} != "continue" ]
 then
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
  exit 0;
 fi
fi

# Removing file
rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

exit 0;

```

Change the file ownership and permissions 

```
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
```
Restart the Wazuh agent

```
  sudo systemctl restart wazuh-agent
```

<a id="part7"></a>
### Step 7: Create automated response | Wazuh server

Navitgate to the Wazuh dashboard and go into settings > modules and enable the VirusTotal integration under the Threat Detection and response section.
![image](https://github.com/user-attachments/assets/d4532b9a-299b-45f9-9882-724a92a6260c)


Now that the script to remove malicious files is added to the Wazuh agent I must configure the Wazuh server to alert for any changes made in the endpoint directories, enable VirusTotal integration and trigger the remove threat script if a malicious file is detected.

Open the local_rules.xml (_/var/ossec/etc/rules/local_rules.xml_) file in the Wazuh server and add the below rules that alert for changes in the /home/user/Downloads directory.

```
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Linux systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/home/user/Downloads</field>
        <description>File modified in /home/user/Downloads directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/home/user/Downloads</field>
        <description>File added to /home/user/Downloads directory.</description>
    </rule>
</group>
```

Now open the server config file `/var/ossec/etc/ossec.conf` and paste the below into the bottom of the file, replacing `YOUR_VIRUS_TOTAL_API_KEY` with your [Virus Total API Key](https://docs.virustotal.com/reference/overview).
```
<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key><YOUR_VIRUS_TOTAL_API_KEY></api_key> <!-- Replace with your VirusTotal API key -->
    <rule_id>100200,100201</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```


Also add the below into the config file to trigger the remove-threat script whenever VirusTotal finds a malicious file
```
<ossec_config>
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
</ossec_config>
```

Lastly add the below to the local_rules.xml file to report on the remove threat script outcome then restart the Wazuh server.
```
<group name="virustotal,">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```
```
sudo systemctl restart wazuh-manager
```

Now I can test this out and download a known [malicious TEST file](https://www.eicar.org/download-anti-malware-testfile/) from eicar and view the results!

<p align="left">
  <img src="https://github.com/user-attachments/assets/fcfa8613-0797-4fbc-a6f8-dee2a7cad9a8" />
</p>

<p align="left">
  <img src="https://github.com/user-attachments/assets/f98e4129-06fa-4f37-b44d-aa551e713451" />
</p>

I can see the malicious test file was automatically detected by virus total, which triggered my remove threat script to successfully delete the malicious file. 







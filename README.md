# Wazuh SIEM Lab

## Objective

The Wazuh SIEM Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks based on the [YouTube video by John Hammond](https://youtu.be/i68atPbB8uQ?si=dYoGtUtZLdhDnjwI). The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

![image](https://github.com/user-attachments/assets/b7a90e1f-022d-42db-9d04-5fd3219f4b31)


### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Integration of third party intelligence for automated response.

### Tools Used

- Wazuh Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Telemetry generation tools to create realistic network traffic and attack scenarios.
- Virus Total integration for automated response.

### Prerequisites 
Virtual machines, I am using [VMWare Workstation Pro](https://www.vmware.com/products/workstation-pro/html.html), but [Virtual Box](https://www.virtualbox.org) is a free alternative.

## Steps
All up to date steps to setup Wazuh can be found using the [quickstart guide](https://documentation.wazuh.com/current/quickstart.html).

### Step 1: Create VM for Wazuh Server
Spin up a VM for Ubuntu with resources aligning to the Wazuh documentation
<p align="left">
  <img src="https://github.com/user-attachments/assets/88af8182-fc9f-47d2-9413-8d78397d2f36" />
</p>



Below is my VM configuration
<p align="left">
  <img src="https://github.com/user-attachments/assets/09029662-a33e-4dc4-999d-53f7975dcf3c" />
</p>



### Step 2: Install Wazuh
Once Ubuntu is up and running install Wazuh using the following
```curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh && sudo bash ./wazuh-install.sh -a ```

When Wazuh has finished installing the admin password will be printed in the terminal, take note of this and login to your Wazuh dashboard on any browser by typing in your device ip or local host.
![image](https://github.com/user-attachments/assets/c2a467ca-4577-48b5-89de-e7d04fb647f0)



_Note down the device's ip address, this will be needed when setting up Wazuh agents_

### Step 3: Add Wazuh Agent
Now we can install a Wazuh Agent into another VM to start sending information back for our Wazuh server.

Navigate to the Wazuh server ip address using any browser and login using the credentials generated in step 2. Once logged into the Wazuh dashboard click on "Add Agents", then follow the wizard to get the command to install.

![image](https://github.com/user-attachments/assets/a0f00d79-41dc-478d-a564-9c70c8478eb6)

Below example is the command I will use to install the Wazuh agent on another Windows VM via PowerShell
`Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.4-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.68.113' WAZUH_REGISTRATION_SERVER='192.168.68.113' `

After installing the Wazuh agent on the VM of your choice start up the service, e.g. for my Windows VM `NET START WazuhSvc`

Repeat this for as many Wazuh agents as you would like to add.

Now refresh the Wazuh dashboard and see the new agent has been added successfully.
![image](https://github.com/user-attachments/assets/93a517bb-34ad-4977-8d7a-f4b7e9c9923f)


### Step 4: Enable vulnerability detection 
To enable vulnerability detection we need to configure our Wazuh server. On the Wazuh Server navigate to the `/var/ossec/etc` directory. Here we want to open the ossec.conf file, this is our config file for the Wazuh server. Scroll down until you find vulnerability-detector and change it from _no_ to _yes_ ![image](https://github.com/user-attachments/assets/6a8c78e4-4f00-4a3e-aee8-89b2a362562f)

Save and close the config file, then restart the Wazuh server `systemctl restart wazuh-manager`



### Step 5: Create some security events!
Now it's time to be creative and do what you need to create some security events, for me I will achieve this by using [ninite](https://ninite.com/) to download a bunch of applications.

According to the config file, Wazuh should interval scan for vulnerabilities every 5 mins. After downloading a bunch of applications on my Windows VM there is alot of vulnerabilites found!

![image](https://github.com/user-attachments/assets/6d1a406c-2b1a-4e58-94d7-b8cebd8ceb5a)

On my ubuntu VM I can install [Invoke Atomic](https://github.com/redcanaryco/invoke-atomicredteam/wiki) and simulate some real attacks to create more events.

Once Invoke Atomic has downloaded we can start to simulate attacks! Go into the Wazuh dashboard and you can use the MITRE ATT&CK framework to find attacks.

![image](https://github.com/user-attachments/assets/07e10ed5-c2a3-4d93-a285-45b03743d208)

Here I will try [T1003.008](https://attack.mitre.org/techniques/T1003/008/) you can click on this in Wazuh to get some more information on the attack.
![image](https://github.com/user-attachments/assets/be1bc578-d334-444b-9d4f-50b7730cadb0)

Follow the below commands to invoke this attack on the ubuntu machince.
```Invoke-AtomicTest``` followed by the technique ID ```T1003.008``` and then <enter>

These events can also be viewed in Wazuh

### Step 6: Create automated response

Now we will use [Wazuh Virus Total integration](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html) to add file integrity monitoring and automatically respond.

_The below steps modifying the Wazuh agent config can be done via the Wazuh dashboard too_
In the Wazuh Agent (Ubuntu) navigate to /var/ossec/etc and open the ossec.conf file.

Navigate to the file integrity monitoring section in the config file and add a new directory to monitor real time, in this case I will add the Downloads folder.
```<directories realtime="yes">/home/user/Downloads</directories>```
![image](https://github.com/user-attachments/assets/95ff5626-20ec-4517-b006-6743d9f0f7b5)

Install jq
```
  sudo apt update
  sudo apt -y install jq
```
Create a new bash script called _"remove-threat.sh"_ in the `/var/ossec/active-response/bin` directory with the below content saved in the script
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
Now we can restart the Wazuh agent

`sudo systemctl restart wazuh-agent`















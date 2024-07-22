# Wazuh SIEM Lab

## Objective

The Wazuh SIEM Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks based on the [YouTube video by John Hammond](https://youtu.be/i68atPbB8uQ?si=dYoGtUtZLdhDnjwI). The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

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


### Step 3: Enable vulnerability scanning 
To enable vulnerability scanning we need to configure our Wazuh server. On the Wazuh Server navigate to the `/var/ossec/etc` directory. Here we want to open the ossec.conf file, this is our config file for the Wazuh server. Scroll down until you find vulnerability-detector and change it from _no_ to _yes_ ![image](https://github.com/user-attachments/assets/6a8c78e4-4f00-4a3e-aee8-89b2a362562f)

Save and close the config file, then restart the Wazuh server `systemctl restart wazuh-manager`







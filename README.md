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
Virtual machines, I am using [VMWare Workstation Pro](https://www.vmware.com/products/workstation-pro/html.html), but [virtual box](https://www.virtualbox.org) is a free alternative.

## Steps
All up to date steps to setup Wazuh can be found using the [quickstart guide](https://documentation.wazuh.com/current/quickstart.html).
### Step 1: Create VM for Wazuh
Spin up a VM for Ubuntu with resources aligning to the Wazuh documentation
<p align="center">
  <img src="https://github.com/user-attachments/assets/88af8182-fc9f-47d2-9413-8d78397d2f36" />
</p>



Below is my VM configuration
<p align="center">
  <img src="https://github.com/user-attachments/assets/09029662-a33e-4dc4-999d-53f7975dcf3c" />
</p>



### Step 2: Install Wazuh
Once Ubuntu is up and running install Wazuh using the below in the terminal
```curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh && sudo bash ./wazuh-install.sh -a```



![image](https://github.com/user-attachments/assets/88af8182-fc9f-47d2-9413-8d78397d2f36)
![image](https://github.com/user-attachments/assets/09029662-a33e-4dc4-999d-53f7975dcf3c)

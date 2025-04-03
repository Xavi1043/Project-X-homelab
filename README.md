# Project-X-homelab
Home lab made for Offense &amp; Defense capabilities

## Objective
The Project-X homelab project aims to create a simulated enterprise network environment to facilitate the study and demonstration of network security, system administration, and penetration testing. This project utilizes a variety of operating systems and technologies to mimic real-world business IT infrastructure, providing a controlled environment for security testing, educational purposes, and system configuration practice.

## Network Topology

![image](https://github.com/user-attachments/assets/c9b34a0d-6c6a-44c9-9ee2-17dd78e36df2)

*Figure: Network topology of the Homelab Project.*

## Project Overview

**NAT Network Configuration**
- **Network Name**: project-x-nat (NatNetwork)
- **IP Address Range**: 10.0.0.0/24
- **Usable Range**: 10.0.0.1 – 10.0.0.254
- **DHCP Dynamic Scope**: 10.0.0.100 – 10.0.0.200

**Hosts and Functions**
- **Domain Controller**: Hostname - dc (corp.project-x-dc.com), IP - 10.0.0.5. Functions include DNS, DHCP, SSO.
- **Email Server**: Hostname - email-svr, IP - 10.0.0.8. Functions as SMTP Relay Server.
- **Dedicated Security Server**: Hostname - sec-box, IP - 10.0.0.10.
- **Security Playground**: Hostname - sec-work, IP - 10.0.0.103 (dynamic).
- **Windows Workstation**: Hostname - win-client, IP - 10.0.0.100 (dynamic).
- **Linux Desktop Workstation**: Hostname - linux-client, IP - 10.0.0.101 (dynamic).
- **Attacker Environment**: Hostname - attacker, IP - dynamic.

### Operating Systems Used
- **Windows Server 2025**: For directory services; acts as the central hub for network connection.
- **Windows 11 Enterprise**: Simulates a business user environment.
- **Ubuntu Desktop 22.04**: Used to simulate an enterprise software development environment.
- **Ubuntu Server 22.02**: Hosts applications and serves as an email server.
- **Security Onion**: For security monitoring, log analysis, and intrusion detection.
- **Kali Linux**: For penetration testing and ethical hacking, equipped with various tools for security testing.

### Virtual Machines and Tools
**VirtualBox Configuration**
- VirtualBox is used as the hypervisor for virtualizing the operating systems mentioned above.

**Key Tools and Technologies**
- **Microsoft Active Directory**: Manages network resources, users, and permissions.
- **Wazuh**: Provides intrusion detection, log analysis, vulnerability detection, and compliance reporting.
- **Postfix**: An MTA used for handling emails.
- **Evil-WinRM, Hydra, SecLists, NetExec, XFreeRDP**: Various tools for penetration testing, network exploitation, and security analysis.

### Guides and Documentation
A series of step-by-step guides are provided for setting up each component of the homelab environment. These include provisioning virtual machines, setting up servers and clients, and configuring tools like Postfix and Wazuh.


# Phase 1 - Active Directory Domain Services (AD DS) Deployment

## Objective
Phase 1 focuses on deploying Active Directory Domain Services (AD DS) to establish a foundational enterprise network structure that supports advanced management of user data, security, and distributed resources.

## Key Tasks Completed

### 1. Set Up Virtual Networking
- Created a VirtualBox NAT Network called `project-x-network`.
- Configured subnet: `10.0.0.0/24`.
- Set up DHCP server range: `10.0.0.10 – 10.0.0.254`.
- Confirmed gateway at `10.0.0.1`.


### 2. Provisioned Windows Server VM
- Installed Windows Server 2022/2025 in VirtualBox.
- Assigned a static IP: `10.0.0.5`.
- Configured:
  - Subnet mask: `255.255.255.0`.
  - Gateway: `10.0.0.1`.
  - DNS: Initially `127.0.0.1`, later changed to `10.0.0.5`.


### 3. Installed and Configured Active Directory
- Installed the Active Directory Domain Services role.
- Promoted the server to a Domain Controller.
- Created a new forest: `corp.project-x-dc.com`.
- Server hostname set during installation (can be customized if renamed).

![image](https://github.com/user-attachments/assets/c816a8a9-a690-4a53-b060-f1031e9562dd)

![image](https://github.com/user-attachments/assets/e202b173-0a19-4ed2-8fd6-ab323c3ecd4a)



### 4. Installed and Configured DNS
- Installed DNS Server role.
- Configured the internal DNS server to handle queries for `corp.project-x-dc.com`.
- Added forwarders (e.g., `8.8.8.8`) to allow internet name resolution.
- Verified resolution via `nslookup` and connectivity via `ping`.


![image](https://github.com/user-attachments/assets/f72efbdb-a5ea-490d-add4-e408dddad540)


### 5. Enabled DHCP for Internal Address Distribution
- Installed the DHCP role.
- Configured scope (optional until later phase).
- Reserved the static IP of the DC outside of the DHCP pool.


## Outcome
- The Domain Controller is live and reachable at `10.0.0.5`.
- Internet and internal name resolution function correctly via DNS forwarders.
- The domain `corp.project-x-dc.com` is now ready for client machines to join.
- User account for John Doe added and configured.


![image](https://github.com/user-attachments/assets/4bca5b1d-db85-4c31-8796-15317ce77333)

  
# Phase 2 - Provision & Join Windows 11 Workstation to Domain

## Objective
In Phase 2, the goal is to provision and configure a Windows 11 Enterprise virtual machine, integrate it into the `corp.project-x-dc.com` domain, and demonstrate successful domain-based operations and access controls.

## Key Tasks Completed

### 1. Provisioned Windows 11 Enterprise VM
- Deployed Windows 11 Enterprise using VirtualBox.
- Disabled internet temporarily using a Host-only Adapter to bypass Microsoft Account setup during the initial configuration.
- Completed the local user setup with a generic offline account for initial access.

### 2. Configured Networking
- Switched VM’s network adapter back to NAT Network: `project-x-network`.
- Assigned a static IP configuration:
  - **IP Address**: 10.0.0.x (e.g., 10.0.0.10)
  - **Subnet Mask**: 255.255.255.0
  - **Default Gateway**: 10.0.0.1
  - **Preferred DNS Server**: 10.0.0.5 (AD DNS)
- Conducted connectivity tests:
  - **Ping** to gateway and DC.
  - **DNS resolution** using `nslookup corp.project-x-dc.com`.


![image](https://github.com/user-attachments/assets/1575b546-6d45-4708-bb79-ff43f66ea5c5)


### 3. Joined Workstation to Domain
- Ensured time synchronization with the domain (crucial for Kerberos authentication).
- Successfully joined the Windows 11 workstation to the `corp.project-x-dc.com` domain.
- Restarted the workstation to apply domain membership settings.

### 4. Logged In with Domain User
- Utilized the "Active Directory Users and Computers" on the Domain Controller to create a domain user: `johnd`.
- Logged into the Windows 11 workstation using the domain credentials for `johnd`.
- Verified user profile creation and successful integration into the domain environment.

- **User Profile Login**: Demonstrating logging in with domain credentials.

![image](https://github.com/user-attachments/assets/3ce88c8c-e820-40f4-bc26-7f18ac094434)


## Outcome
The Windows 11 workstation is now fully integrated into the `corp.project-x-dc.com` domain, demonstrating successful network configuration, domain joining, and user authentication via Active Directory.


# Phase 3 - Provision & Integrate Ubuntu Desktop 22.04 with Active Directory

## Objective
This phase focuses on provisioning an Ubuntu Desktop 22.04 VM and configuring it to integrate seamlessly with the Active Directory environment at `corp.project-x-dc.com`. The process involves setting up networking, ensuring correct DNS resolution, and joining the Ubuntu client to the domain using Samba Winbind.

## Key Tasks Completed

### 1. Configured Static IP and DNS
- Set up a new wired connection named "Linux AD1" with static IP configuration.
  - **IP Address**: 10.0.0.9
  - **Subnet Mask**: 255.255.255.0
  - **Default Gateway**: 10.0.0.1
  - **DNS**: 10.0.0.5
- Verified network settings via the GUI.

![image](https://github.com/user-attachments/assets/7a6bc38d-6869-4acc-a066-2c556e2dd3da)

![image](https://github.com/user-attachments/assets/886bac13-714b-42f2-a2e3-a7e55d93ca71)



### 2. Verified DNS Resolution and Domain Configuration
- Adjusted and verified DNS settings using `systemd-resolved` and directly editing `resolv.conf`.
- Used `realm discover` to check the availability and requirements for joining the `corp.project-x-dc.com` domain.

![image](https://github.com/user-attachments/assets/8aca5d5b-fe78-4a23-aa5c-4fe03f719b87)


### 3. Joined the Ubuntu Client to the Domain
- Executed the domain join process using the `net ads join` command.
- Configured necessary services like `smbd`, `nmbd`, and `winbind` and restarted them to apply all changes.
- Verified successful domain join and the functioning of domain services.

![image](https://github.com/user-attachments/assets/645cb4c2-b745-46b8-8df5-008d692e1666)


### 4. Validated User and Group Enumeration
- Checked domain user and group listings using `wbinfo -u` and other `winbind` utilities.
- Successfully listed users, demonstrating integration with Active Directory.

![image](https://github.com/user-attachments/assets/48cc6162-e320-4f44-8e11-5f4fa2d5f7e8)


### 5. Confirmed Active Directory User Login
- Logged in with the domain user `janed` and verified her UID, GID, and group memberships via the `id` command, confirming correct access rights and group mappings.

![image](https://github.com/user-attachments/assets/fb5057d6-3a4a-4358-9b80-7fa574919361)

## Outcome
The Ubuntu Desktop 22.04 VM is fully integrated into the `corp.project-x-dc.com` domain, with correct network settings, DNS configuration,


![image](https://github.com/user-attachments/assets/3b8e5550-7b15-4dfe-ae79-20baaa15b620)


# Phase 4 - Ubuntu Server Setup & Active Directory Integration

## Objective
In Phase 4, we focus on deploying and configuring an Ubuntu Server 22.04 (project-x-email-svr) to integrate seamlessly with the Active Directory environment `corp.project-x-dc.com`. The server is set up to handle email services, although it's also a part of the broader network integration testing with AD.

## Key Tasks Completed

### 1. Provision and Initial Setup
- Deployed Ubuntu Server 22.04 on a VirtualBox VM.
- Configured basic settings including hostname (`project-x-email-svr`), network, and OpenSSH Server installation.

### 2. Network Configuration and Time Synchronization
- Configured static IP `10.0.0.8`, gateway `10.0.0.1`, and DNS settings pointing to the AD Domain Controller `10.0.0.5`.

### 3. AD Integration Preparation
- Installed necessary packages for AD integration including Kerberos, Samba, and Winbind.
- Configured Kerberos and Samba for AD integration.

![image](https://github.com/user-attachments/assets/1f291a34-fe19-4c99-806f-06afa508d67d)


### 4. Domain Joining
- Joined the Ubuntu server to the `corp.project-x-dc.com` domain using Winbind.
- Validated the server's domain membership and ensured the Winbind service is running properly.

![image](https://github.com/user-attachments/assets/cd4701e0-fa28-4a4e-8853-0dfd42d3ce62)


### 5. User and Group Configuration
- Added the `email-svr` user to Active Directory and verified it can log in to the Ubuntu server.
- Checked user and group listings to ensure proper domain integration.

- **AD Users and Computers showing email-svr:** Demonstrates the user creation in Active Directory.

![image](https://github.com/user-attachments/assets/0d42d31f-f898-43b8-be75-1372faa5f22f)


- **Domain Computers showing EMAIL-SVR:** Confirms the Ubuntu server is recognized as a computer within the domain.

![image](https://github.com/user-attachments/assets/ba12b9ce-eee4-4115-aba5-b9f38539d75b)


## Outcome
The Ubuntu Server 22.04 is fully integrated into the `corp.project-x-dc.com` domain, with functional network settings, domain authentication, and user management. This setup ensures that the server can operate within the domain, providing email services and participating in domain security protocols.


# Phase 5 - Postfix Mail Server Setup

## Objective
Phase 5 focuses on setting up and configuring Postfix, a popular Mail Transfer Agent (MTA), to handle email services within the `corp.project-x-dc.com` domain. This setup involves configuring Postfix to operate as an Internet Site, managing email routing, and ensuring integration with the domain's DNS services for optimal mail delivery.

## Key Tasks Completed

### 1. Postfix Installation and Configuration
- Installed Postfix with detailed configuration options.
- Configured Postfix to function as an Internet Site, specifying `email-svr` as the mail name.
- Setup system mail name and recipient configurations.


### 2. Mailbox and Alias Configuration
- Configured the mailbox directory to `/home/email-svr/Maildir`.
- Setup `virtual_alias_maps` to route emails for `email-svr@corp.project-x-dc.com` to the local `email-svr` user account.
- Restarted Postfix to apply new configurations.


### 3. Email Client Setup Using s-nail
- Installed and configured `s-nail` as the email client, setting the mail directory to `/home/email-svr/Maildir`.
- Adjusted s-nail settings to enhance usability and mail management.


### 4. Static IP and DNS Configuration
- Configured a static IP and specified DNS settings to ensure proper domain name resolution and network connectivity.

### 5. Testing and Email Interaction
- Created and navigated the Maildir structure, confirming the correct setup of mail directories (`cur`, `new`, `tmp`).
- Sent test emails using `s-nail`, verified the receipt and functionality of the email system.


![image](https://github.com/user-attachments/assets/0b3422ea-c0d4-4a0f-9e3b-07496416e16f)

![image](https://github.com/user-attachments/assets/01afc872-2e49-4337-9699-32d3f9a4533b)



### 6. DNS Configuration in Active Directory
- Added a DNS host record for `smtp.corp.project-x-dc.com` pointing to `10.0.0.8` in the domain controller's DNS Manager to facilitate mail service discovery within the network.

![image](https://github.com/user-attachments/assets/309f0ae2-cea2-496c-a6b7-48dcecb863a0)


## Outcome
The Postfix mail server is fully operational and integrated into the `corp.project-x-dc.com` domain. It is configured to handle email routing, sending, and receiving for the domain, supporting internal communications within the simulated enterprise network.



# Phase 6 - Security Server Provision & Setup

## Objective
The objective of Phase 6 is to deploy and configure Security Onion on a dedicated security server within the network to enhance monitoring, log management, and intrusion detection capabilities. This phase involves setting up the server, integrating it with Active Directory, and preparing it for future security tasks.

## Key Tasks Completed

### 1. Virtual Machine Cloning and Setup
- Cloned an existing Virtual Machine to create the Security Server, named `project-x-sec-box`.
- Configured the machine with Security Onion to provide network security monitoring and intrusion detection.

### 2. Security Onion Installation
- Installed Security Onion on the newly created VM following the guidelines specified in the Security Onion setup documentation.
- Configured essential services and tested the initial setup to ensure operational readiness.



### 3. Configuring the Security Server
- Configured static IP and network settings to integrate with the corporate network.
- Added the server to the `corp.project-x-dc.com` domain to manage authentication and user access through Active Directory.

### 4. User Account Creation and Configuration
- Created a new user account `sec-user` for daily operations, ensuring it has appropriate permissions for security tasks.
- Integrated the user with Active Directory, assigning necessary roles and privileges for network security management.

![image](https://github.com/user-attachments/assets/3f975903-24b2-4fdf-a010-c28cd2c6e5df)

![image](https://github.com/user-attachments/assets/a15faa9a-55ed-4c85-aecf-cc80db14036d)



### 5. Active Directory Integration
- Successfully joined the Security Server to the Active Directory domain using administrative credentials.
- Configured DNS settings to ensure the server can resolve network names within the domain accurately.

![image](https://github.com/user-attachments/assets/220523b5-7d1a-40a0-a474-55134dc0b336)


### 6. Post-Setup Configuration
- The server is currently set up but not used in active deployments; it's prepared for future security tasks and further configuration as needed.

## Outcome
The Security Server is fully set up with Security Onion, integrated into the Active Directory environment, and ready for deployment. It stands prepared to enhance the organization’s security posture by providing advanced threat detection and response capabilities.


# Phase 7 - Wazuh Agent Installation and Configuration

## Objective
The goal of Phase 7 is to install and configure the Wazuh agent on the Linux client, Window Client , and AD server. This setup aims to enhance security monitoring and automate incident response across the IT infrastructure.

## Wazuh Overview
Wazuh is a powerful open-source security monitoring solution, combining advanced SIEM (Security Information and Event Management) capabilities with XDR (Extended Detection and Response) features. Key components include:
- **Wazuh Agent**: Installed on monitored systems to collect and forward data.
- **Wazuh Manager**: Processes data received from agents and executes analytic rules.
- **Wazuh Dashboard**: Provides a visual interface for real-time data analysis and reporting.

## Key Tasks Completed

### 1. DNS Configuration and Verification
- Resolved DNS issues by temporarily using Google's DNS to facilitate the download of necessary packages.

### 2. Wazuh Agent Download and Installation
- Downloaded the Wazuh agent package from the official repository using `wget` and installed it on the Linux client using `dpkg`.
- Configured the agent to communicate with the Wazuh manager using environment variables.

![image](https://github.com/user-attachments/assets/491726e7-6b1d-47d4-99c8-aa8f49e1d393)

![image](https://github.com/user-attachments/assets/b00936e2-ca35-472b-9757-2f82de68e435)


### 3. Agent Configuration
- Configured the agent to monitor critical system logs including auth, secure, and audit logs, enhancing security event detection and response capabilities.

![image](https://github.com/user-attachments/assets/3964ffe4-0c86-453f-8ec9-f7280eaa49ed)

![image](https://github.com/user-attachments/assets/1af2eda0-61ee-49ba-b695-20b64091caa4)



### 4. Service Management
- Enabled the Wazuh agent service via `systemd`, confirmed its operational status, and ensured it is set to start on system boot.


### 5. Verification and Testing
- Verified the functionality and effective communication of the Wazuh agent with the Wazuh manager, ensuring it performed as configured.


## Outcome
The Wazuh agent on the Linux client, Windows Client , and AD server are successfully installed and configured, fully integrated with the centralized Wazuh manager, and ready for proactive security monitoring and incident response.

![image](https://github.com/user-attachments/assets/944dfc00-ea72-423c-8578-bef9a5039aee)


# Phase 8 – Configure a Vulnerable Environment

## Objective
Intentionally weaken systems within the lab to simulate real-world attack surfaces. This setup enables detection rule creation, alerting, and monitoring using Wazuh on project-x-sec-box. 

---

## Key Tasks Completed

### 1. Open SSH on project-x-email-svr
- Installed and enabled the OpenSSH server.
- Verified SSH service was active and accessible externally.
- Modified `/etc/ssh/sshd_config` to allow password authentication, enabling root login and password-based authentication.
- Restarted SSH service after configuration changes.

![image](https://github.com/user-attachments/assets/0c712144-5c08-457a-94f1-4dad04c2cd47)
![image](https://github.com/user-attachments/assets/6a277269-6ad7-49bd-881e-092b160a4dc7)
![image](https://github.com/user-attachments/assets/32ece3ba-0bd0-42d0-a44e-81d282d6a1b5)
![image](https://github.com/user-attachments/assets/2e0ceed8-7613-40d2-a3e9-0ee46b94f38b)





### 2. Wazuh Detection Integration – Email Server
- Ensured Wazuh agent on project-x-email-svr was actively sending logs to project-x-sec-box.
- Monitored SSH login attempts via `/var/log/auth.log`, creating detection rules for both successful and failed attempts.


### 3. Open SSH on project-x-linux-client
- Enabled and configured the SSH server, opening port 22 through the firewall.
- Verified remote SSH access functionality.

### 4. Wazuh Detection Integration – Linux Client
- Configured log forwarding for SSH events to project-x-sec-box.
- Established a Wazuh rule to detect multiple failed login attempts as a brute-force attack simulation.

### 5. Create Custom SSH Detection Alert
- Implemented a Wazuh rule to generate alerts after three consecutive failed SSH login attempts within a 60-second window.
- Tested rule effectiveness by simulating failed logins.

![image](https://github.com/user-attachments/assets/f9503ff5-f494-41d5-af3a-98a178aff1a8)
![image](https://github.com/user-attachments/assets/7056f403-ea0a-4ef3-813b-a8bf17062db7)
![image](https://github.com/user-attachments/assets/226df24d-cc6f-4c78-aba4-fde549c81cdc)
![image](https://github.com/user-attachments/assets/bf132087-5f57-4e7e-9da3-53fc9655d8e4)
![image](https://github.com/user-attachments/assets/e9e9ccf6-fe94-49c1-bdec-7a2cd7e0c00e)

### 6. Configure Email Communication from project-x-email-svr to project-x-linux-client
- Configured s-nail for sending test messages and verified successful message delivery in Maildir on the Linux client.
- Monitored and confirmed SMTP traffic through internal networking.

![image](https://github.com/user-attachments/assets/3834cffe-b89f-4dc5-b412-a5c40e4253d5)


### 7. Wazuh Detection Integration – Email Traffic
- Captured and monitored mail activity logs for outbound email activities, enhancing the detection of unauthorized email transmissions.

### 8. Enable WinRM on project-x-win-client
- Set up Windows Remote Management and configured necessary firewall settings to facilitate secure remote management.

### 9. Wazuh Detection Integration – WinRM
- Implemented detection for WinRM session initiation and validated alert functionality through simulated remote sessions.

![image](https://github.com/user-attachments/assets/b2badfef-0f77-4d9a-8068-6a14a260c9f9)
![image](https://github.com/user-attachments/assets/825ab776-dbb5-43a4-bec6-8cd536881906)
![image](https://github.com/user-attachments/assets/722610de-7cf4-4d6d-b96b-2d4e4b431ac1)
![image](https://github.com/user-attachments/assets/1c344f7a-dcf5-4e67-bdc2-d28eca3d3915)
![image](https://github.com/user-attachments/assets/cc18e45a-5586-403b-b322-ad7593c6dc9c)





### 10. Enable RDP on project-x-dc (Domain Controller)
- Activated Remote Desktop Protocol and configured firewall to allow RDP connections.
- Verified connectivity using Remote Desktop Connection (mstsc) from a remote host.

![image](https://github.com/user-attachments/assets/7dcda1c6-fe0c-40f5-815d-30f6c2e07ef6)


# Phase 9 – Setup The Attacker Machine

## Objective
Set up Kali Linux on a virtual machine to serve as an attack platform for conducting security tests and simulations within the lab.

---

## Key Tasks Completed

### Configure Kali Linux
- **Installation:** Installed Kali Linux using the VirtualBox platform. The installation process included selecting the "Graphical install" option, setting the hostname to "attacker", and configuring user credentials exclusively for this environment.
- **Network Configuration:** Configured and verified network settings to ensure proper communication within the lab environment.
- **Security Tools Setup:** Installed and configured necessary tools such as Metasploit and Burp Suite for penetration testing and vulnerability assessment.
- **Security Implications Addressed:** Ensured that the use of Kali Linux is isolated within the lab environment to prevent any unauthorized access and potential misuse.
![image](https://github.com/user-attachments/assets/893876c8-7b31-4789-807a-0488e38f7f99)
![image](https://github.com/user-attachments/assets/7a8fb12d-5e6c-4fc4-a460-e56fb4886732)
![image](https://github.com/user-attachments/assets/384be04e-523c-414c-95be-4537d28ac3fc)




# Phase 10: Initial Access to Breached

![image](https://github.com/user-attachments/assets/83215da2-f38c-4ecd-9c20-8f8f4879440d)


## Objective
Simulate a cyber-attack on ProjectX's business network to capture sensitive files and achieve persistence. This phase aims to emulate real-world tactics, using tools and techniques available to the attacker, to penetrate network defenses and establish control.

![image](https://github.com/user-attachments/assets/bdfacd19-3701-4bab-8649-ada6dd2638d7)


## Cyber Attack Overview
- **Threat Actor Motivations:** Financial gain, using the network's vulnerabilities to exfiltrate sensitive information and potentially extort the target.
- **Attack Approach:** Utilizing a mixture of technical vulnerabilities and social engineering to gain initial access and escalate privileges within the network.

## Key Activities

### 1. Reconnaissance
- **Objective:** Identify network vulnerabilities and entry points.
- **Actions:**
  - Conduct an Nmap scan to discover open ports and services on the network.
    - -p1-1000: Scans top 1000 ports
    - -sV: Service scan discovery
    - -Pn: Bypasses ping blocking

![image](https://github.com/user-attachments/assets/ceee85c4-eaac-41b0-a554-e1df2f39db10)


   This scan revealed a host with:
   - Open SSH
   - Open SMTP (Port 25)
   - Target System: `project-x-email-svr` identified as a potential entry point due to its internet accessibility.
 
     ![image](https://github.com/user-attachments/assets/883b19ea-fb5a-4854-a5a0-804b46bfe0b6)

 


  

### 2. Initial Access
- **Objective:** Gain a foothold in the network.
- **Actions:**
  - Utilize SSH vulnerabilities on identified systems.


![image](https://github.com/user-attachments/assets/8986c236-d8e5-427c-9139-eb7eca0ddfba)

- Deploy Hydra to perform brute-force attacks using common passwords and usernames sourced from lists like `rockyou.txt`.
- Successful SSH entry into `project-x-email-svr` using credentials obtained from brute force.
 
![image](https://github.com/user-attachments/assets/7bcd26ac-699c-461e-87f8-bcdf47f4b33c)
![image](https://github.com/user-attachments/assets/2c2b15f2-5cec-4efe-91e4-401f7c292dec)
![image](https://github.com/user-attachments/assets/3077543d-3b75-4591-8bc9-74d1c121372d)




  - Check the OS version and distribution using the command: `cat /etc/os-release`.
  - Determine the hostname with: `hostname`.
  - Discover the IP address of the device using: `ip a`.
  - Inspect active network services to identify potential attack vectors using `netstat -tuln`.
 
  ![image](https://github.com/user-attachments/assets/91d3880d-3206-4a87-9b6b-8a9aed1315a6)

  - Review the email-svr/Maildir directory for outgoing emails that could provide additional context or credentials, specifically checking messages sent to `janed@corp.project-x-dc.com`.

![image](https://github.com/user-attachments/assets/66f13842-09aa-4f1d-a3cb-3ab6d51d644c)

    



### 3. Setup the Lure (Phishing Attack)
- **Objective:** Execute a phishing attack to obtain higher-level credentials.
- **Actions:**
- Craft a spear-phishing email impersonating an internal security alert.

 ![image](https://github.com/user-attachments/assets/e5a36dd8-35b0-439f-b15c-b1409326e39e)

  
  - Host a fake password verification page on a compromised server to capture credentials.
  - 
![image](https://github.com/user-attachments/assets/8ea5f1ad-9237-4cba-83ea-220fbbcee2d0)
![image](https://github.com/user-attachments/assets/b35a50ff-d661-4fdf-821f-fe5a99408734)


    
- Distribute the phishing email to users, specifically targeting a user Jane on `project-x-linux-client`.

![image](https://github.com/user-attachments/assets/04b79e84-1866-4fdc-b3e8-b2c5e70b89b8)

***Important Note***

- If client uses an outlook client Gmail this would be rendered in HTML and the verify my account section would be a hyperlink . It would not be an IP address , but a domain.

![image](https://github.com/user-attachments/assets/3fa381dc-083d-40bc-94f4-2e8d7f771662)
![image](https://github.com/user-attachments/assets/184c7d2d-f2ee-4c4c-b431-64039cfbf0f7)
![image](https://github.com/user-attachments/assets/0ca30d03-1f5a-47d1-85b4-70fdf99e7e0b)
![image](https://github.com/user-attachments/assets/791ecd3a-bc44-4748-a4e6-335773edf4a7)
![image](https://github.com/user-attachments/assets/314faebf-c8f4-4bba-aaa8-4de48e2a2ec2)


Collecting more info on our new victim

![image](https://github.com/user-attachments/assets/eea682c7-bbbe-48d1-b3ee-4e6b009c30f5)

## Server Role Identification

![image](https://github.com/user-attachments/assets/4c1ed0a1-cb2b-4b9e-ad55-a1d8a7bf9b40)


### Context
After conducting an `nmap` scan of the server at `10.0.0.5` following a phishing attack simulation, key services indicative of a Domain Controller within an Active Directory environment were identified.

### Details of Identified Services

- **DNS (Port 53/tcp)**:
  - **Service:** Domain Name System (DNS)
  - **Purpose:** Essential for network name resolution, indicating a central role in network addressing within an Active Directory environment.

- **Kerberos (Port 88/tcp)**:
  - **Service:** Kerberos
  - **Purpose:** Manages secure network authentication, typical of Active Directory environments for authenticating user and service logins.

- **LDAP (Port 389/tcp)**:
  - **Service:** Lightweight Directory Access Protocol (LDAP)
  - **Purpose:** Handles access and maintenance of distributed directory information, essential for managing user data and authentication across the network.

- **Microsoft DS (Port 445/tcp)**:
  - **Service:** Microsoft Directory Services (SMB)
  - **Purpose:** Supports file and printer sharing, along with domain services, reinforcing its function as a critical component of the network infrastructure.
 
  - Winrm service detected running
 
    ![image](https://github.com/user-attachments/assets/518a6491-85d0-4e86-b93e-33a9566981d5)

 


### 4. Lateral Movement and Privilege Escalation
- **Objective:** Expand control within the network and escalate privileges.
- **Actions:**
  - With obtained credentials, access additional systems within the network.
  - Employ tools like Evil-WinRM for Windows systems to exploit WinRM services for higher-level access.

### 5. Data Exfiltration
- **Objective:** Steal sensitive information.
- **Actions:**
  - Identify and locate sensitive files on `project-x-dc`.
  - Utilize SCP to transfer files to the attacker-controlled external server.

### 6. Establishing Persistence
- **Objective:** Maintain long-term access to the network.
- **Actions:**
  - Create backdoor accounts and schedule tasks running reverse shells to ensure ongoing access.

## Tools and Techniques
- **Reconnaissance:** Nmap, network service scanning.
- **Initial Access:** Hydra for brute-force attacks.
- **Phishing Setup:** Custom phishing tools, HTML email crafting.
- **Privilege Escalation:** Evil-WinRM, custom scripts for automation.
- **Data Exfiltration:** SCP for secure file transfer.
- **Persistence:** Scheduled tasks, reverse shell scripts.

## Conclusion
This simulated attack demonstrates the multi-step approach an attacker might take to breach a network, from initial reconnaissance to establishing persistence. The scenario highlights the necessity for robust defense mechanisms and continuous monitoring to detect and mitigate such threats.





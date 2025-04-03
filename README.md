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


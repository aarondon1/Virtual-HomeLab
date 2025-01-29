# Cybersecurity Home Lab Documentation

---

## 📌 Table of Contents
- [Objective](#objective)
- [Current Setup](#current-setup)
- [Planned Enhancements](#planned-enhancements)
- [Experimentation and Learning Process](#experimentation-and-learning-process)
- [Challenges and Resolutions](#challenges-and-resolutions)
- [Future Updates](#future-updates)
- [Screenshots and Logs](#screenshots-and-logs)

---

## 🎯 Objective
The goal of this home lab is to simulate real-world cybersecurity scenarios in a sandbox environment, focusing on configuring and defending against attacks. The lab is designed to build practical skills in threat detection, incident response, and network defense.

---

## 🏗️ Current Setup

### 🛠️ Attack Machine (Kali Linux)
- **Purpose:** Simulates a malicious actor to test and analyze target defenses.
- **Configured Tools:**
  - Metasploit, Nmap, Netcat for reconnaissance and exploitation.
  - Scripts for brute force, phishing, and privilege escalation.
  - Malware testing tools for security evaluation.

### 🛡️ Defending Machine (Windows 10 VM)
- **Purpose:** Target system for security analysis under attacks.
- **Configured Tools:**
  - **Sysmon (System Monitor):** Installed and configured for event logging.
  - **Splunk:** Installed for log aggregation and real-time monitoring.
  - **Planned:** IDS/IPS (Snort/Suricata) for additional threat detection.

### 🌐 Networking
- **Setup:**
  - Private network using VirtualBox.
  - Segmented attack and defending machines.
  - VPN configuration (planned) for secure remote access.

---

## 🚀 Planned Enhancements

### 🔥 Attack Machine Improvements
- **Expand Exploitation Tools:** Cobalt Strike, advanced malware simulation.
- **Simulated Attack Types:** SQL injections, XSS, Man-in-the-Middle, ransomware tests.

### 🛡️ Defense Enhancements
- **Improve Log Management:** Enhanced Sysmon rules, custom Splunk alerts.
- **Deploy IDS:** Install Snort/Suricata for real-time network monitoring.
- **Firewall & DNS Security:** Block suspicious IPs, implement a DNS sinkhole.

### 🌍 Network Enhancements
- **VPN Configuration:** Secure remote access.
- **Network Segmentation:** VLANs to isolate environments.

---

## 🔬 Experimentation and Learning Process

### 📌 **Phase 1: Basic Malware Testing**
- Ran initial malware attacks from Kali Linux to Windows 10.
- Captured logs with Sysmon, analyzed attack patterns.
- Built Splunk dashboards for visualizing login attempts, registry changes.

### 🏗️ **Phase 2: Advanced Attack Simulations (Planned)**
- Simulate brute-force attacks, detect anomalies.
- Conduct network-based attacks, analyze packets in Wireshark.

### 🛡️ **Phase 3: Defense Optimization (Planned)**
- Implement correlation searches in Splunk for deeper threat analysis.
- Centralize IDS alerts in Splunk.
- Deploy endpoint detection (Microsoft Defender ATP).

---

## 🛠️ Challenges and Resolutions

### 🚧 Challenges Faced
- **Sysmon Configuration:** Difficulty setting up rules to capture critical logs.
- **Networking Issues:** Misconfigurations causing communication failures.

### ✅ Resolutions
- **Sysmon Fix:** Adjusted configurations using community best practices.
- **Networking Fix:** Reconfigured VirtualBox network settings for stable VM communication.

---

## 📌 Future Updates
- **Documentation:**
  - Log specific attack scenarios and security responses.
  - Publish sanitized configurations and logs to GitHub.
- **Advanced Techniques:**
  - Experiment with threat hunting techniques.
  - Align security measures with the MITRE ATT&CK framework.

---

## 🖼️ Screenshots and Logs
_Screenshots of Splunk dashboards, attack scenarios, and configurations will be added here once I explore and experiment more with all these tools and situations to better

---

🔄 **This documentation will be regularly updated** as new components are added and security techniques are tested. Check back for progress updates! 🚀


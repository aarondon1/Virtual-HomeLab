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
The goal of this home lab is to create a controlled sandbox environment that enables hands-on learning and experimentation with real-world cybersecurity threats, defenses, and mitigation techniques. By simulating various attack scenarios and implementing defensive security measures, this lab serves as a comprehensive training ground for developing practical skills in threat detection, incident response, digital forensics, and network security.

The lab is designed to mirror real-world cybersecurity challenges, providing an interactive and iterative learning process through controlled attacks, monitoring, and analysis. By configuring and hardening systems against cyber threats, users can enhance their understanding of:

- Attack Vectors & Exploitation: Learning how adversaries attempt to compromise systems through malware, brute-force attacks, phishing, and network-based exploits.
- Security Logging & Monitoring: Implementing SIEM solutions (e.g., Splunk) to aggregate and analyze security logs, detect anomalies, and create alerts for suspicious activity.
- Intrusion Detection & Prevention: Configuring tools like Sysmon, Snort, or Suricata to proactively identify and respond to potential threats.
- Incident Response & Digital Forensics: Investigating attacks, analyzing log data, and applying forensic techniques to reconstruct security incidents.
- Network Security & Defense Strategies: Setting up firewalls, VPNs, DNS sinkholes, and segmentation to protect sensitive systems from intrusion.

By continuously expanding and refining the lab setup, this project will serve as a living documentation of cybersecurity learning and skill development, simulating real-world security operations while reinforcing best practices in cyber defense, risk mitigation, and system hardening.
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


<div align="center"><img align="center" src="https://github.com/user-attachments/assets/c469f501-b62c-4b0d-b46f-590dd4eab013" /></div>
<h2 align="center">CIS HARDENING SCRIPT FOR DEBIAN >= 12 AND UBUNTU >= 18.04</h2>

---
<table width="100%" border="0" cell-spacing="0" cellpadding="10" align="center" style="border: none; width: 100%;">
  <tr>
    <td><img src="https://komarev.com/ghpvc/?username=vjkolaventy&label=+++Views:&color=orange&style=flat" alt="views" /></td>
    <td><img src="https://img.shields.io/badge/%20%20Version-v1.0-green&style=flat" /></td>
    <td><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" /></td>
  </tr>
  <tr>
    <td><img src="https://img.shields.io/badge/bash_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white" /></td>
    <td><img src="https://img.shields.io/badge/Debian-D70A53?style=for-the-badge&logo=debian&logoColor=white" /></td>
    <td><img src="https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" /></td>
  </tr>
</table>

<p style="text-align: justify;">This is a bash script inspired from <a href="https://github.com/ovh/debian-cis">CIS Debian 11/12 Hardening"</a> and <a href="https://github.com/captainzero93/security_harden_linux">Ubuntu / Debian Linux Security Hardening Scripts</a>
This script will help you with the following:
  <ul>
    <li>Remove unnecessary packages installed by default</li>
    <li>Disable unused modules loaded by default</li>
    <li>Disable IPV6</li>
    <li>Disable USB Devices & Storage</li>
    <li>Configure kernel hardening settings</li>
    <li>Configure hardening settings to SSHD</li>
    <li>Setup and configure UFW firewall</li>
    <li>Setup ClamAV antivirus</li>
    <li>Setup and configure Apparmor</li>
    <li>Setup Chrony to synchronise system time</li>
    <li>Setup Advanced Intrusion Detection Environment (AIDE)</li>
    <li>Setup Auditd for monitoring & logging security events</li>
    <li>Setup Rkhunter for rootkit scanning</li>
    <li>Apply recommended file & directory permissions</li>
    <li>Disable root login for enhanced security</li>
    <li>Disable root login for enhanced security</li>
    <li>Limit su (superuser) to wheel members</li>
    <li>Setup pw_quality to enforce strong passwords</li>
    <li>Secure system boot settings</li>
    <li>Setup Google 2FA authentication</li>
    <li>Enable automatic updates</li>
    <li>Setup Lynis for security auditing & vulnerbility detection</li>
  </ul>
</p>

### USING THE SCRIPT
**$\textcolor{red}{WARNING:}$** *This is script is meant to be run on a fresh install. Some options in script can potentially lock you out and make you system unusable. Be sure backup it up before running this script. Use the script at your own risk!*
<p>To use the script just download it and run with sudo priviliges.</p>

```
wget https://github.com/vjkolaventy/cis_hardening/cis_hardening.sh
chmod +x cis_hardening.sh
sudo ./cis_hardening.sh
```

<img width="1734" height="1991" alt="image" src="https://github.com/user-attachments/assets/564f33be-b755-43df-ba59-d702b5036d10" />


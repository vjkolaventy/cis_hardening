<table width="100%" border="0" cell-spacing="0" cellpadding="10" align="center" bgcolor="#FFFFFF" style="border: none;">
  <tr align="center" bgcolor="#FFFFFF"><td colspan="3"><img align="center" src="https://github.com/user-attachments/assets/c469f501-b62c-4b0d-b46f-590dd4eab013" /></td></tr>
  <tr align="center" bgcolor="#FFFFFF">
    <td><img src="https://komarev.com/ghpvc/?username=vjkolaventy&label=+++Views:&color=orange&style=flat" alt="views" /></td>
    <td><img src="https://img.shields.io/badge/%20%20Version-v1.0-green&style=flat" /></td>
    <td><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" /></td>
  </tr>
  <tr align="center">
    <td><img src="https://img.shields.io/badge/bash_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white" /></td>
    <td><img src="https://img.shields.io/badge/Debian-D70A53?style=for-the-badge&logo=debian&logoColor=white" /></td>
    <td><img src="https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" /></td>
  </tr>
  <tr><td colspan="3">
<h3 align="center">CIS HARDENING SCRIPT FOR DEBIAN >= 12 AND UBUNTU >= 18.04</h3>
<p style="text-align: justify;">This is a bash script inspired from <a href="https://github.com/ovh/debian-cis">CIS Debian 11/12 Hardening"</a> and <a href="https://github.com/captainzero93/security_harden_linux">Ubuntu / Debian Linux Security Hardening Scripts</a>. This script will help you to do the following:
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

#### HARDENING TIPS
My personal preference is Debian netinst distribution. Install the server with just Openssh-server. Create partitions with the following options for better hardening. (&check;=apply &cross;=dont apply) 

<table>
  <tr><th>Partition</th><th colspan="3" align="center">Options</th></tr>
  <tr><td></td><td align="center">nodev</td><td align="center">noexec</td><td align="center">nosuid</td></tr>
  <tr><td>/</td><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/boot</td><td align="center">&cross;</td><td align="center">&cross;</td><td align="center">&cross;</td></tr>
  <tr><td>/home</td><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/var</td><td align="center">&check;</td><td align="center">&cross;</td><td align="center">&check;</td></tr>
  <tr><td>/var/log</td align="center"><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/var/log/audit</td><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/dev</td><td align="center">&cross;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/dev/shm</td><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/run</td><td align="center">&check;</td><td align="center">&cross;</td><td align="center">&check;</td></tr>
  <tr><td>/tmp</td><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
  <tr><td>/var/tmp</td><td align="center">&check;</td><td align="center">&check;</td><td align="center">&check;</td></tr>
</table>

In case you are using Grub, you should consider securing it with a password.

#### PRE-REQUISITES
Default install of Debian does not include 'sudo'. You will need to install sudo, add a new non-root user (or an existing non-root user) to sudoers. Ubuntu comes with sudo pre-installed, just make sure that the user login you intend to use for running this script has sudo privileges.

```bash
# run below commands as root. replace username with the name you want
apt install sudo -y
useradd username
usermod -aG sudo username
```

#### USING THE SCRIPT
**$\textcolor{red}{WARNING:}$** *This is script is meant to be run on a fresh install. Some options in script can potentially lock you out and make your system unusable. This script DID NOT WORK for me on cloud-init virtual machine in Proxmox. Be sure to backup up your system before running this script. Use the script at your own risk!*
<p>To use the script simply download it and run it with sudo priviliges. When you are done with the hardening process, you can check your system hardening score with <a href="https://github.com/CISOfy/lynis">Lynis</a> which can installed using this script.</p>

```
wget https://raw.githubusercontent.com/vjkolaventy/cis_hardening/refs/heads/main/cis_hardening.sh
chmod +x cis_hardening.sh
sudo ./cis_hardening.sh
```

<img width="1734" height="1991" alt="image" src="https://github.com/user-attachments/assets/564f33be-b755-43df-ba59-d702b5036d10" />

</td></tr>
</table>

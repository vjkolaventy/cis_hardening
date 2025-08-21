#!/bin/bash
#################################################################################
#
# Aureum CIS Hardening
# ------------------
#
# Copyright (c) 2025 Aureum Network Private Limited
# Contributors: Vijay Kolaventy, Abhishek Bandla
#
# GitHub   : https://github.com/vjkolaventy/cis_hardening
#
# Aureum CIS Hardening comes with ABSOLUTELY NO WARRANTY.
# This is free software, and you are welcome to redistribute it under
# the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
#################################################################################

# CIS HARDENING FOR DEBIAN 12 / UBUNTU 18.04 OR ABOVE

VERSION="1.0"
VERBOSE=false
COPYRIGHT=$(echo -e "\u00A9")
LOG_FILE="/var/log/cis_hardening/cis_hardening.log"
SCRIPT_NAME=$(basename "$0")
HEADER="# Aureum CIS Hardening - Start"
FOOTER="# Aureum CIS Hardening - End"
EMAIL="root"
EMAIL_REGEX='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

# Config files
CHANGED_FILES=()
MODULES_FILE="/etc/modprobe.d/cis_hardening.conf"
FAIL2BAN_FILE="/etc/fail2ban/jail.local"
AIDE_FILE="/etc/default/aide"
SSHD_FILE="/etc/ssh/sshd_config"
CUSTOM_SSHD_FILE="/etc/ssh/sshd_config.d/99_cis_hardening_sshd.conf"
PAM_SSHD_FILE="/etc/pam.d/sshd"
SYSCTL_FILE="/etc/sysctl.conf"
CUSTOM_SYSCTL_FILE="/etc/sysctl.d/10_cis_hardening_sysctl.conf"
CHKROOTKIT_FILE="/etc/chkrootkit/chkrootkit.conf"
GRUB_FILE="/etc/default/grub"
UFW_FILE="/etc/default/ufw"
NFT_FILE="/etc/modules-load.d/cis_netfilter.conf" # netfilter modules files
LOCK_MODULES_SERVICE_FILE="/etc/systemd/system/lock-modules.service" # to lock kernel modules after loading required modules
PWQUALITY_FILE="/etc/security/pwquality.conf"
PAM_PWD_FILE="/etc/pam.d/common-password"
BACKUP_PATH="/root/cis_hardening"

# test styles
NORMAL=$(tput sgr0)
BOLD=$(tput bold)
ITALIC=$(tput sitm)
UNDERLINE=$(tput smul)
NO_UNDERLINE=$(tput rmul)

# foreground colors
GOLD=$(echo -e "\033[0;33m")
BLACK=$(tput setaf 0)
GRAY=$(tput setaf 8)
RED=$(tput setaf 9)
GREEN=$(tput setaf 10)
YELLOW=$(tput setaf 11)
BLUE=$(tput setaf 12)
MAGENTA=$(tput setaf 13)
CYAN=$(tput setaf 14)
WHITE=$(tput setaf 15)
ORANGE=$(tput setaf 214)
LTGRAY=$(tput setaf 249)
DARKGRAY=$(tput setaf 243)
LTRED=$(tput setaf 197)
LTGREEN=$(tput setaf 118)
LTYELLOW=$(tput setaf 228)
LTBLUE=$(tput setaf 39)
LTMAGENTA=$(tput setaf 219)
LTCYAN=$(tput setaf 123)
NC=$(echo -e "\033[0m")

# background colors
BGBLACK=$(echo -e "\033[40m")
BGRED=$(echo -e "\033[41m")
BGGREEN=$(echo -e "\033[42m")
BGYELLOW=$(echo -e "\033[43m")
BGBLUE=$(echo -e "\033[44m")
BGMAGENTA=$(echo -e "\033[45m")
BGCYAN=$(echo -e "\033[46m")
BGLTGRAY=$(echo -e "\033[47m")
BGGRAY=$(echo -e "\033[100m")
BGLTRED=$(echo -e "\033[101m")
BGLTGREEN=$(echo -e "\033[102m")
BGLTYELLOW=$(echo -e "\033[103m")
BGLTBLUE=$(echo -e "\033[104m")
BGLTMAGENTA=$(echo -e "\033[105m")

# Function to center-align text
function print_centered {
    [[ $# == 0 ]] && return 1
    declare -i TERM_COLS="$(tput cols)"
    declare -i str_len="${#1}"
    [[ $str_len -ge $TERM_COLS ]] && {
        echo "$1"
        return
    }
    declare -i filler_len="$(((TERM_COLS - str_len) / 2))"
    [[ $# -ge 2 ]] && ch="${2:0:1}" || ch=" "
    filler=""
    for ((i = 0; i < filler_len; i++)); do
        filler="${filler}${ch}"
    done
    printf "%s%s%s" "$filler" "$1" "$filler"
    [[ $(((TERM_COLS - str_len) % 2)) -ne 0 ]] && printf "%s" "${ch}"
    printf "\n"
    return 0
}

# Function to check system requirements
check_requirements() {
    # --- Get OS information ---
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        os_name="$ID"            # debian / ubuntu
        os_version="$VERSION_ID" # e.g. 12, 20.04, 22.04
    else
        echo "Error: /etc/os-release not found"
        exit 1
    fi
    # Normalize os_name
    case "$os_name" in
    debian | Debian) os_name="Debian" ;;
    ubuntu | Ubuntu) os_name="Ubuntu" ;;
    *)
        echo "Unsupported OS: $os_name $os_version"
        exit 1
        ;;
    esac
    # --- Check version requirements ---
    if [[ "$os_name" == "Ubuntu" ]]; then
        if dpkg --compare-versions "$os_version" lt "18.04"; then
            echo "This script requires Ubuntu 18.04 or later. Detected: $os_name $os_version"
            exit 1
        fi
    elif [[ "$os_name" == "Debian" ]]; then
        if dpkg --compare-versions "$os_version" lt "12"; then
            echo "This script requires Debian 12.0 or later. Detected: $os_name $os_version"
            exit 1
        fi
    fi
    log "true" "System requirements check passed! OS Detected: ${LTCYAN}$os_name $os_version${NC}"
}

# Function to check permissions to run script
check_permissions() {
    # Check if sudo is installed
    if ! command -v "sudo" >/dev/null; then
        echo -e "$(tput blink)${BOLD}${RED}Please install sudo and run the script with sudo privileges!\n\n${NC}"
        exit 1
    fi
    # Do not allow to run the script as root user
    if [[ $(logname) == "root" ]]; then
        echo -e "$(tput blink)${BOLD}${RED}Please run the script as non-root user with sudo privileges!${NC}${NORMAL}\n\n"
        exit 1
    fi
    # Allow only non-root users with sudo privileges to run the script
    if [ "$EUID" -ne 0 ]; then
        echo -e "$(tput blink)${BOLD}${RED}This script must be run with sudo privileges.${NC}${NORMAL}"
        echo -e "${WHITE}Please run it again using: ${RED}sudo\n${NC}\n\n"
        exit 1
    fi
}

# Function to log script messages
log() {
    if $1; then
        local message="${NC}$(date '+%Y-%m-%d %H:%M:%S'): ${GREEN}$2${NC}"
    else
        local message="${NC}$(date '+%Y-%m-%d %H:%M:%S'): ${RED}Warning! $2${NC}"
    fi
    if ! [ -e "$LOG_FILE" ]; then
        sudo mkdir -p "$(dirname $LOG_FILE)"
    fi
    if ! [ -f "$LOG_FILE" ]; then
        sudo touch "$LOG_FILE"
    fi
    echo "$message" | sudo tee -a "$LOG_FILE" >/dev/null
    echo -e "$message"
}

# Function for error handling
handle_error() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): ${BOLD}${RED}Error!${NORMAL} ${LTCYAN}$2${NC}"
    if ! [ -f "$LOG_FILE" ]; then
        sudo touch "$LOG_FILE"
    fi
    echo "$message" | sudo tee -a "$LOG_FILE" >/dev/null
    echo -e "$message\n"
    false
}

# Function to be executed when Ctrl+C is pressed
cleanup() {
    echo -e "\n\n${RED}Ctrl+C${NC} detected!"
    echo -e "Check ${CYAN}$LOG_FILE${NC} for changes"
    # Add any cleanup commands here, e.g., removing temporary files
    echo -e "Cleanup complete. Exiting!\n\n"
    exit 1 # Exit with a non-zero status to indicate an abnormal exit
}

# Function to add configuration header
add_header() {
    local context="$1"
    local file="$2"
    local header="# Aureum CIS Hardening - $context - Start"
    echo -e "\n$header" | sudo tee -a "$file" >/dev/null || handle_error "Failed to added header to configuration"
}

# Function to add configuration footer
add_footer() {
    local context="$1"
    local file="$2"
    local footer="# Aureum CIS Hardening - $context - End"
    echo -e "$footer" | sudo tee -a "$file" >/dev/null || handle_error "Failed to added footer to configuration"
}

# Function to remove previous configuration
remove_old_config() {
    local context="$1"
    local file="$2"
    local header="# Aureum CIS Hardening - $context - Start"
    local footer="# Aureum CIS Hardening - $context - End"
    if sudo grep -q -E "$header" "$file" >/dev/null; then
        sudo sed -i "/^$header/,/^$footer/d" "$file" || handle_error "Failed to remove previous configuration"
        sed -i -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$file" || handle_error "Failed to cleanup empty lines in $file"
    fi
}

# Function to monitor changes files
update_changed_files() {
    if ! [[ " ${CHANGED_FILES[*]}" =~ " $1 " ]]; then
        CHANGED_FILES+=("$1")
    fi
}

# Function to let use select actions
questionnaire() {
    echo -e "${BOLD}${ORANGE}Please select following system hardening options${NC}${NORMAL}"
    echo -e "$${ITALIC}{LTCYAN}" >/dev/null
    ask_question "1. Remove unused default packages?" && do_remove_packages=true || do_remove_packages=false
    ask_question "2. Disable IPV6 if not in use?" && do_disable_ipv6=true || do_disable_ipv6=false
    ask_question "3. Disable unused kernel modules?" && do_disable_unused_modules=true || do_disable_unused_modules=false
    ask_question "4. Disable USB devices & storage?" && do_disable_usb=true || do_disable_usb=false
    ask_question "5. Setup & configure UFW Firewall?" && do_setup_firewall=true || do_setup_firewall=false
    ask_question "6. Setup Fail2Ban to prevent brute force attacks?" && do_setup_fail2ban=true || do_setup_fail2ban=false
    ask_question "7. Setup ClamAV antivirus?" && do_setup_clamav=true || do_setup_clamav=false
    ask_question "8. Setup AppArmor to limit application capabilities?" && do_setup_apparmor=true || do_setup_apparmor=false
    ask_question "9. Setup Chrony to synchronise system clock?" && do_setup_chrony=true || do_setup_chrony=false
    ask_question "10. Setup Advanced Intrusion Detection Environment (AIDE)?" && do_setup_aide=true || do_setup_aide=false
    ask_question "11. Setup Auditd for monitoring & logging security events?" && do_setup_auditd=true || do_setup_auditd=false
    ask_question "12. Setup Chkrootkit for rootkit scanning?" && do_setup_chkrootkit=true || do_setup_chkrootkit=false
    ask_question "13. Configure kernel hardening settings to sysctl?" && do_configure_sysctl=true || do_configure_sysctl=false
    ask_question "14. Configure hardening settings to SSH service?" && do_configure_ssh=true || do_configure_ssh=false
    ask_question "15. Apply recommended file & directory permissions?" && do_apply_file_permissions=true || do_apply_file_permissions=false
    ask_question "16. Disable root login for enhanced security?" && do_disable_root=true || do_disable_root=false
    ask_question "17. Limit su (superuser) to wheel members?" && do_limit_su=true || do_limit_su=false
    ask_question "18. Enforce strong passwords with pw_quality?" && do_configure_password=true || do_configure_password=false
    ask_question "19. Apply CIS recommended secure boot settings?" && do_secure_boot=true || do_secure_boot=false
    ask_question "20. Setup Google 2FA authentication?" && do_setup_2fa=true || do_setup_2fa=false
    ask_question "21. Apply miscellaneous security settings?" && do_apply_misc=true || do_apply_misc=false
    ask_question "22. Enable automatic updates?" && do_enable_updates=true || do_enable_updates=false
    ask_question "23. Setup Lynis for security auditing & vulnerbility detection?" && do_setup_lynis=true || do_setup_lynis=false
    echo -e "${NORMAL}${NC}" >/dev/null
}

# Function to display summary of selected actions
show_selection_summary() {
    echo -e "\n${BOLD}You have selected the following actions"
    $do_remove_packages && echo "✅ Remove unused default packages" || echo "❌ Skip remove unused default packages"
    $do_disable_ipv6 && echo "✅ Disable IPV6 if not in use" || echo "❌ Skip disable IPV6 if not in use"
    $do_disable_unused_modules && echo "✅ Disable unused kernel modules" || echo "❌ Skip disable unused default kernel modules"
    $do_disable_usb && echo "✅ Disable USB storage" || echo "❌ Skip disable USB storage"
    $do_setup_firewall && echo "✅ Setup UFW firewall" || echo "❌ Skip setup UFW firewall"
    $do_setup_fail2ban && echo "✅ Setup Fail2Ban" || echo "❌ Skip setup Fail2Ban"
    $do_setup_clamav && echo "✅ Setup ClamAV antivirus" || echo "❌ Skip setup ClamAV antivirus"
    $do_setup_apparmor && echo "✅ Setup AppArmor" || echo "❌ Skip setup AppArmor"
    $do_setup_chrony && echo "✅ Setup Chrony" || echo "❌ Skip setup Chrony"
    $do_setup_aide && echo "✅ Setup AIDE" || echo "❌ Skip setup AIDE"
    $do_setup_auditd && echo "✅ Setup Auditd" || echo "❌ Skip setup AuditD"
    $do_setup_chkrootkit && echo "✅ Setup ChkRootKit" || echo "❌ Skip setup ChkRootKit"
    $do_configure_sysctl && echo "✅ Apply kernel hardening settings" || echo "❌ Skip apply secure kernel settings"
    $do_configure_ssh && echo "✅ Apply SSH hardening settings" || echo "❌ Skip apply secure SSH settings"
    $do_apply_file_permissions && echo "✅ Fix file and directory permissions" || echo "❌ Skip fix file and directory permissions"
    $do_disable_root && echo "✅ Disable root login" || echo "❌ Skip disable root login"
    $do_limit_su && echo "✅ Limit su (superuser) to wheel members" || echo "❌ Skip limit su (superuser) to wheel members"
    $do_configure_password && echo "✅ Enforce strong passwords" || echo "❌ Skip enforce strong passwords"
    $do_secure_boot && echo "✅ Apply secure boot settings" || echo "❌ Skip secure boot settings"
    $do_setup_2fa && echo "✅ Setup Google 2FA authentication" || echo "❌ Skip setup Google 2FA authentication"
    $do_apply_misc && echo "✅ Apply miscellaneous security settings" || echo "❌ Skip apply miscellaneous security settings"
    $do_enable_updates && echo "✅ Enable automatic updates" || echo "❌ Skip enable automatic updates"
    $do_setup_lynis && echo "✅ Setup Lynis" || echo "❌ Skip setup Lynis"
}

# Function to ask questions
ask_question() {
    local question="$1"
    local default="${2:-Y}"
    local answer
    while true; do
        read -p "$question ($default/n): " answer
        answer=${answer:-$default}
        case "${answer,,}" in
        y | yes) return 0 ;;
        n | no) return 1 ;;
        *) echo "Please answer Y or N." ;;
        esac
    done
}

execute_actions() {
    local actions=()
    local names=()

    $do_remove_packages && actions+=(remove_packages)
    names+=("Remove unused packages")
    $do_disable_ipv6 && actions+=(disable_ipv6)
    names+=("Disable IPV6")
    $do_disable_unused_modules && actions+=(disable_unused_modules)
    names+=("Disable unused modules")
    $do_disable_usb && actions+=(disable_usb)
    names+=("Disable USB")
    $do_setup_firewall && actions+=(setup_firewall)
    names+=("Setup Firewall")
    $do_setup_fail2ban && actions+=(setup_fail2ban)
    names+=("Setup Fail2Ban")
    $do_setup_clamav && actions+=(setup_clamav)
    names+=("Setup ClamAV")
    $do_setup_apparmor && actions+=(setup_apparmor)
    names+=("Setup AppArmor")
    $do_setup_chrony && actions+=(setup_chrony)
    names+=("Setup Chrony")
    $do_setup_aide && actions+=(setup_aide)
    names+=("Setup Aide")
    $do_setup_auditd && actions+=(setup_auditd)
    names+=("Setup Auditd")
    $do_setup_chkrootkit && actions+=(setup_chkrootkit)
    names+=("Setup ChkRootKit")
    $do_configure_sysctl && actions+=(configure_sysctl)
    names+=("Configure sysctl for CIS")
    $do_configure_ssh && actions+=(configure_ssh)
    names+=("Configure SSH for CIS")
    $do_apply_file_permissions && actions+=(apply_file_permissions)
    names+=("Apply CIS file permissions")
    $do_disable_root && actions+=(disable_root)
    names+=("Disable root login")
    $do_limit_su && actions+=(limit_su)
    names+=("Limit su to wheel members")
    $do_configure_password && actions+=(configure_password)
    names+=("Enforce strong passwords")
    $do_secure_boot && actions+=(secure_boot)
    names+=("Secure system boot")
    $do_setup_2fa && actions+=(setup_2fa)
    names+=("Setup Google 2FA authentication")
    $do_apply_misc && actions+=(apply_misc)
    names+=("Apply miscellaneous CIS recommendations")
    $do_enable_updates && actions+=(enable_updates)
    names+=("Enable automatic security updates")
    $do_setup_lynis && actions+=(setup_lynis)
    names+=("Setup Lynis")

    local count=${#actions[@]}

    for ((i = 0; i < count; i++)); do
        echo -e "\n=== Starting: ${LTRED}${names[$i]}${NC} ==="
        ${actions[$i]}
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}❌ ${names[$i]} failed.${NC}"
            if ((i == count - 1)); then
                echo -e "${RED}This was the last action — exiting!${NC}"
                exit 1
            fi
            if ! ask_question "Do you want to continue with ${names[$i + 1]}?" "Y"; then
                echo -e "${RED}Stopping script!${NC}"
                exit 1
            fi
        fi
    done
}

# Function to install packages
install_package() {
    log "true" "Installing $1..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" || handle_error "Failed to install $1"
}

# Function to update system
update_system() {
    log "true" "Updating System..."
    sudo apt-get update -y || handle_error "System update failed"
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || handle_error "System upgrade failed"
}

# Function to backup file
backup_file() {
    local filepath="$1"
    local filename=$(basename "$filepath")
    sudo mkdir -p $BACKUP_PATH || handle_error "Failed to create backup directory"
    if [ -f "$filepath" ]; then
        local backup="$BACKUP_PATH/${filename}.cis-$(date +%F_%H%M%S).bak"
        sudo cp "$filepath" "$backup" || handle_error "Failed to backup $filename"
        log "true" "Backed up $filename to $backup"
    else
        log "false" "$filepath not found, skipping backup"
    fi
}

# Function to remove unnecessary packages
remove_packages() {
    log "true" "Removing unnecessary packages..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y telnetd nis yp-tools rsh-client rsh-redone-client xinetd || handle_error "Failed to remove some packages"
    sudo apt-get autoremove -y || handle_error "Flushing apt packages failed"
    log "true" "Unnecessary packages removed"

}

# Function to disable IPV6
disable_ipv6() {
    log "true" "Disabling IPv6..."
    local context="Disable IPV6"
    local settings=(
        "net.ipv6.conf.all.disable_ipv6 = 1"
        "net.ipv6.conf.default.disable_ipv6 = 1"
        "net.ipv6.conf.lo.disable_ipv6 = 1"
    )
    backup_file "$SYSCTL_FILE"
    remove_old_config "$context" "$SYSCTL_FILE"
    add_header "$context" "$SYSCTL_FILE"
    for setting in "${settings[@]}"; do
        if [[ "$setting" =~ ^[a-zA-Z0-9._-]+[[:blank:]]*=[[:blank:]]*[0-9]+$ ]]; then
            local key=${setting%% = *}
            if sudo grep -q -E "^${key}\b" "$SYSCTL_FILE" && ! sudo grep -q -E "^#.*${key}\b" "$SYSCTL_FILE"; then
                sed -i -e "/^[[:space:]\xc2\xa0]*${key}\b/s/^/#&/" "$SYSCTL_FILE" || handle_error "Failed to comment existing setting $key"
                log "true" "Commented out existing $key in $SYSCTL_FILE"
            fi
            echo -e "$setting" | sudo tee -a "$SYSCTL_FILE" >/dev/null || handle_error "Failed to add $setting to $SYSCTL_FILE"
        else
            echo "Bad systctl parameter - skipping $setting"
        fi
    done
    add_footer "$context" "$SYSCTL_FILE"
    sudo sysctl -p || handle_error "Failed to apply sysctl changes"
    update_changed_files "$SYSCTL_FILE"
    log "true" "IPv6 has been disabled"
}

# Function to disable unused modules loaded in default installation
disable_unused_modules() {
    log "true" "Disabling unused modules..."
    local context="Disable Modules"
    local modules=(
        "cramfs"
        "freevxfs"
        "jffs2"
        "hfs"
        "hfsplus"
        "squashfs"
        "udf"
        "vfat"
        "tipc"
        "rds"
        "firewire_ohci"
        "firewire_core"
        "psmouse"
        "joydev"
        "i2c_piix4"
        "floppy"
        "pcspkr"
    )
    backup_file "$MODULES_FILE"
    remove_old_config "$context" "$MODULES_FILE"
    add_header "$context" "$MODULES_FILE"
    for module in "${modules[@]}"; do
        echo -e "blacklist $module\ninstall $module /bin/true" | sudo tee -a "$MODULES_FILE" >/dev/null || handle_error "Failed to disable module: $module"
    done
    add_footer "$context" "$MODULES_FILE"
    update_changed_files "$SYSCTL_FILE"
    if [ "$dry_run" -ne 1 ]; then
        log "true" "Updating initramfs..."
        sudo update-initramfs -u || handle_error "Failed to update initramfs"
        log "true" "Updating Grub..."
        sudo update-grub || handle_error "Failed to update Grub"
        log "true" "Disabled unused modules"
    fi
}

# Function to disable USB devices & storage
# Consider adding usbguard in future
disable_usb() {
    log "true" "Disabling USB devices & storage..."
    local context="Disable USB"
    backup_file "$MODULES_FILE"
    remove_old_config "$context" "$MODULES_FILE"
    add_header "$context" "$MODULES_FILE"
    sudo modprobe -r usb_storage || handle_error "Failed to remove usb_storabe module"
    echo -e "blacklist usb-storage\ninstall usb-storage /bin/true" | sudo tee -a $MODULES_FILE >/dev/null || handle_error "Disabling USB devices failed"
    add_footer "$context" "$MODULES_FILE"
    update_changed_files "$MODULES_FILE"
    log "true" "Disabled USB devices & storage"
}

# Function to check valid ports
is_valid_port() {
    local port="$1"
    # Check if it's a number and within the valid range
    if [[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0 # Valid port
    else
        return 1 # Invalid port
    fi
}

# Function to setup firewall
setup_firewall() {
    log "true" "Installing and configuring UFW Firewall..."

    if ! dpkg -l | grep -q "ufw"; then
        install_package "ufw"
    else
        log "false" "UFW is already installed. Resetting rules..."
        sudo ufw --force reset
    fi

    log "true" "SSH port will be opened by default to prevent lockout"

    log "true" "Applying default allow incoming and deny outgoing rules"

    sudo ufw default deny incoming || handle_error "Failed to set UFW default incoming policy"
    sudo ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy"
    sudo ufw limit ssh comment 'Allow SSH with rate limiting' || handle_error "Failed to configure SSH in UFW"

    read -p "Do you want to open custom ports? (y/N): " open_ports
    case "$open_ports" in
    [Yy]* )
        while true; do
            read -p "${CYAN}Enter valid port number (1-65535) to open or enter 0 to finish: ${NC}" port_number
            if [ "$port_number" -eq 0 ]; then
                break
            fi

            if is_valid_port "$port_number"; then
                read -p "${LTCYAN}Do you want to open port ${port_number}? (y/N): ${NC}" confirm
                case "$confirm" in
                [Yy]* )
                    restart_port_selection=false

                    # Loop to select protocol (can cancel and restart port)
                    while true; do
                        echo -e "\n${CYAN}Choose protocol for port ${port_number} or select CANCEL to go back: ${NC}"
                        select protocol in TCP UDP BOTH CANCEL; do
                            case "$protocol" in
                            TCP | UDP | BOTH)
                                read -p "${LTCYAN}Give a comment for this port or press Enter: ${NC}" comment
                                case "$protocol" in
                                TCP)
                                    sudo ufw allow "$port_number"/tcp comment "Allow ${comment}" || handle_error "Failed to allow TCP port"
                                    ;;
                                UDP)
                                    sudo ufw allow "$port_number"/udp comment "Allow ${comment}" || handle_error "Failed to allow UDP port"
                                    ;;
                                BOTH)
                                    sudo ufw allow "$port_number"/tcp comment "Allow ${comment}" || handle_error "Failed to allow TCP port"
                                    sudo ufw allow "$port_number"/udp comment "Allow ${comment}" || handle_error "Failed to allow UDP port"
                                    ;;
                                esac
                                log "true" "Opened port ${port_number} (${protocol}) with comment: ${comment}"
                                break 2 # Exit both loops (protocol + while loop)
                                ;;
                            CANCEL)
                                echo -e "${YELLOW}Canceled protocol selection. Going back to port input...${NC}"
                                restart_port_selection=true
                                break # Exit select only
                                ;;
                            * )
                                echo -e "${RED}Invalid selection. Please choose a valid protocol.${NC}"
                                ;;
                            esac
                        done

                        # If canceled, go back to port number input
                        if [ "$restart_port_selection" = true ]; then
                            break
                        fi
                    done
                    ;;
                * )
                    echo "Skipping port ${port_number}"
                    ;;
                esac
            else
                echo -e "${RED}Please enter a valid number between 1 and 65535.${NC}"
            fi
        done
        ;;
    * )
        log "true" "Skipping custom ports"
        ;;
    esac

    if grep -q "^IPV6[[:blank:]]*=[[:blank:]]*yes" "$UFW_FILE"; then
        read -p "Do you want to disable IPV6 for UFW? (Y/n): " disable_ipv6
        case "$disable_ipv6" in
        [Yy]* | "" )
            backup_file "$UFW_FILE"
            sudo sed -i "s/^IPV6=.*/IPV6=no/" "$UFW_FILE" || log "true" "Failed to disable IPV6 for UFW"
            CHANGED_FILES=("$UFW_FILE")
            log "true" "Disabled IPV6 for UFW"
            ;;
        esac
    fi

    local val=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)
    if [[ "$val" -eq 1 ]]; then
        nft_modules=(
            ip_tables
            iptable_filter
            iptable_nat
            ip6_tables
            nf_conntrack
            nf_defrag_ipv4
            nf_defrag_ipv6
        )
        if [ -f "$NFT_FILE" ]; then
            sudo truncate -s 0 "$NFT_FILE" || handle_error "Failed to delete lines in $NFT_FILE"
        else
            sudo touch $NFT_FILE || handle_error "Failed to create $NFT_FILE"
        fi
        printf "%s\n" "${nft_modules[@]}" | sudo tee -a $NFT_FILE > /dev/null || handle_error "Failed to add modules to $NFT_FILE"

        # Generate systemd lock_module_service to disable loading kernel modules
        local lock_service=(
            "[Unit]"
            "Description=Lock kernel modules after netfilter is loaded"
            "After=network-pre.target systemd-modules-load.service ufw.service"
            "Before=multi-user.target"
            ""
            "[Service]"
            "Type=oneshot"  
            "ExecStart=/bin/sh -c \"echo 1 > /proc/sys/kernel/modules_disabled\""

            "[Install]"
            "WantedBy=multi-user.target"
        )
        if [ -f "$LOCK_MODULES_SERVICE_FILE" ]; then
            sudo truncate -s 0 "$LOCK_MODULES_SERVICE_FILE"
        else
            sudo touch "$LOCK_MODULES_SERVICE_FILE"
        fi
        printf "%s\n" "${lock_service[@]}" | sudo tee "$LOCK_MODULES_SERVICE_FILE" > /dev/null || handle_error "Failed to create $LOCK_MODULES_SERVICE_FILE"

        sudo systemctl daemon-reexec
        sudo systemctl enable lock-modules.service
        log "true" "Create systemd lock_modules.service"
    fi
    
    sudo ufw logging on || handle_error "Failed to enable UFW logging"
    sudo ufw --force enable || handle_error "Failed to enable UFW"
    log "true" "Firewall configured and enabled"
}

# Function to setup Fail2Ban
setup_fail2ban() {
    log "true" "Installing and Configuring Fail2Ban..."
    local config_file="$FAIL2BAN_FILE"

    local default_config=(
        "[DEFAULT]"
        "allowipv6 = no"
        "maxretry = 5"
        "bantime = 3600"
        "findtime = 600"
        "mta = sendmail"
        "sendername = Fail2Ban"
        "destemail = $EMAIL"
    )

    local sshd_config=(
        ""
        "[sshd]"
        "enabled = true"
        "port = ssh,sftp"
        "backend = %(sshd_backend)s"
    )

    if ! dpkg -l | grep -q "fail2ban"; then
        install_package "fail2ban"
        if ! dpkg -l | grep -q "rsyslog"; then
            log "false" "Syslog is required by Fail2ban. Installing..."
            install_package "rsyslog"
        fi
    else
        log "false" "Fail2Ban is already installed. Resetting..."
        sudo systemctl stop fail2ban || handle_error "Failed to stop Fail2Ban service"
        sudo truncate -s 0 /var/log/fail2ban.log || handle_error "Failed to truncate /var/log/fail2ban.log file"
        sudo rm -f /var/lib/fail2ban/fail2ban.sqlite3 || handle_error "Failed to delete Fail2Ban database"
        backup_file "$FAIL2BAN_FILE"
    fi

    add_header "$FAIL2BAN_FILE"
    printf "%s\n" "${default_config[@]}" | sudo tee -a "$FAIL2BAN_FILE" || handle_error "Failed to add default config to $FAIL2BAN_FILE"
    printf "%s\n" "${sshd_config[@]}" | sudo tee -a "$FAIL2BAN_FILE" || handle_error "Failed to add sshd config to $FAIL2BAN_FILE"
    add_footer "$FAIL2BAN_FILE"
    sudo chmod 640 "/etc/fail2ban/*.conf"
    sudo chmod 640 "/etc/fail2ban/*.local"
    sudo systemctl enable fail2ban || handle_error "Failed to enable Fail2Ban service"
    sudo systemctl start fail2ban || handle_error "Failed to start Fail2Ban service"
    CHANGED_FILES+=("$FAIL2BAN_FILE")
    log "true" "Fail2Ban configured and started"
}

# Function to setup ClamAV
setup_clamav() {
    log "true" "Installing and Updating ClamAV..."
    if ! dpkg -l | grep -q "clamav"; then
        install_package "clamav"
        install_package "clamav-daemon"
        sudo systemctl stop clamav-freshclam || log "false" "Failed to stop clamav-freshclam"
        sudo freshclam || log "false" "ClamAV database update failed"
        sudo systemctl start clamav-freshclam || handle_error "Failed to start clamav-freshclam"
        sudo systemctl enable clamav-freshclam || handle_error "Failed to enable clamav-freshclam"
        log "true" "ClamAV installed and updated"
    else
        log "false" "ClamAV is already installed. Skipping installation..."
    fi
}

# Function to setup AppArmor
setup_apparmor() {
    log "true" "Setting up AppArmor..."

    if ! command -v apparmor_status &>/dev/null; then
        install_package "apparmor"
    else
        log "false" "AppArmor is already installed. Changing apparmor to enforced..."
    fi

    if ! command -v aa-enforce &>/dev/null; then
        log "true" "apparmor-utils not found. Installing..."
        install_package "apparmor-utils"
    fi

    sudo systemctl enable apparmor || handle_error "Failed to enable AppArmor service"
    sudo systemctl restart apparmor || handle_error "Failed to start AppArmor service"
    sudo aa-enforce /etc/apparmor.d/* || log "false" "Failed to enforce some AppArmor profiles"

    log "true" "AppArmor setup complete. All profiles are in enforce mode."
    log "true" "Monitor /var/log/syslog and /var/log/auth.log for any AppArmor-related issues."
}

# Function to install Chrony
setup_chrony() {
    log "true" "Setting up Chrony..."
    if ! command -v chronyc &>/dev/null; then
        install_package "chrony"
        sudo systemctl enable chrony || handle_error "Failed to enable Chrony service"
        log "true" "Chrony setup complete."
    else
        log "false" "Chrony is already installed. Skipping installation..."
    fi
}

# Function to install Aide
setup_aide() {
    log "true" "Setting up AIDE..."
    if ! dpkg -l | grep -q "aide"; then
        install_package "aide"
        sudo aideinit || handle_error "Failed to initialise AIDE database"
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || handle_error "Failed to move AIDE database"
    else
        log "false" "AIDE is already installed. Re-initialising AIDE database..."
        sudo aide -c /etc/aide/aide.conf --init || handle_error "Failed to initialise AIDE database"
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || handle_error "Failed to move AIDE database"
    fi
    sudo sed -i "s/^MAILTO=.*/#&/" "$AIDE_FILE" || handle_error "Failed to update email for aide"
    echo "MAILTO=$EMAIL" | sudo tee -a "$AIDE_FILE" >/dev/null || handle_error "Failed to update email for aide"
    log "true" "AIDE setup is complete"
}

# Function to setup Auditd
setup_auditd() {
    log "true" "Setting up and configuring auditd..."

    if ! dpkg -l | grep -q "auditd"; then
        install_package "auditd"
    else
        log "false" "Auditd is already installed. Removing existing rules..."
        sudo auditctl -D | handle_error "Failed to remove all rules"
    fi

    local audit_rules=(
        "-w /etc/sysctl.conf -p wa -k sysctl"
        "-w /etc/sysctl.d -p wa -k sysctl"
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/sudoers -p wa -k sudoers"
        "-w /etc/login.defs -p wa -k login"
        "-w /etc/modprobe.conf -p wa -k modprobe"
        "-w /etc/pam.d/ -p wa -k pam"
        "-w /etc/securetty -p wa -k login"
        "-w /etc/inittab -p wa -k init"
        "-w /etc/init.d/ -p wa -k init"
        "-w /etc/init/ -p wa -k init"
        "-w /etc/ssh/sshd_config -k sshd"
        "-w /etc/ssh/sshd_config.d -k sshd"
        "-w /root/.ssh -p wa -k rootkey"
        "-w /usr/bin/passwd -p x -k passwd_modification"
        "-w /usr/sbin/groupadd -p x -k group_modification"
        "-w /usr/sbin/groupmod -p x -k group_modification"
        "-w /usr/sbin/addgroup -p x -k group_modification"
        "-w /usr/sbin/useradd -p x -k user_modification"
        "-w /usr/sbin/userdel -p x -k user_modification"
        "-w /usr/sbin/usermod -p x -k user_modification"
        "-w /usr/sbin/adduser -p x -k user_modification"
        "-w /sbin/modprobe -p x -k modules"
        "-w /sbin/insmod -p x -k modules"
        "-w /sbin/rmmod -p x -k modules"
        "-w /var/log/auth.log -p wa -k auth_log"
        "-w /var/log/faillog -p wa -k logins"
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/run/utmp -p wa -k session"
        "-w /var/log/wtmp -p wa -k session"
        "-w /var/log/btmp -p wa -k session"
        "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications"
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
        "-a always,exit -F arch=b64 -S clock_settime -k time-change"
        "-a always,exit -F arch=b32 -S clock_settime -k time-change"
        "-w /etc/localtime -p wa -k time-change"
    )

    for rule in "${audit_rules[@]}"; do
        echo "$rule" | sudo tee -a /etc/audit/rules.d/audit.rules >/dev/null || handle_error "Failed to add audit rule: $rule"
    done
    
    update_changed_files "/etc/audit/rules.d/audit.rules"
    sudo sed -i "s/^action_mail_acct.*/action_mail_acct = $EMAIL/" /etc/audit/auditd.conf || handle_error "Failed to update email in auditd.conf"
    sudo systemctl enable auditd || handle_error "Failed to enable auditd service"
    sudo systemctl start auditd || handle_error "Failed to start auditd service"
    log "true" "Auditd is installed, rules configured and auditd started"
}

# Setup ChkRootKit for rootkit scanning
setup_chkrootkit() {
    if ! dpkg -l | grep -q "chkrootkit"; then
        install_package "chkrootkit"
        sudo sed -i "s/^MAILTO.*/MAILTO=\"$EMAIL\"/" "$CHKROOTKIT_FILE" || handle_error "Failed to update email address for chkrootkit alerts"
    else
        log "false" "ChkRootKit is already installed"
    fi
    
    if ! grep -q -w "RUN_DAILY=\"true\"" "$CHKROOTKIT_FILE"; then
        sudo sed -i "s/^RUN_DAILY=\"true\"" "$CHKROOTKIT_FILE" || handle_error "Failed to set chkrootkit to run daily"
    fi
    
    sudo chmod 640 "$CHKROOTKIT_FILE"
    log "true" "ChkRootKit setup is complete"
}

# Function to configure sysctl
configure_sysctl() {
    log "true" "Configuring kernel hardening settings..."
    local context="Kernel Hardening"
    local sysctl_config=(
        "dev.tty.ldisc_autoload = 0"
        "fs.file-max = 65535"
        "fs.protected_fifos=2"
        "fs.suid_dumpable = 0"
        "kernel.core_uses_pid = 1"
        "kernel.ctrl-alt-del = 0"
        "kernel.dmesg_restrict = 1"
        "kernel.kptr_restrict = 2"
        "kernel.modules_disabled = 1"
        "kernel.perf_event_paranoid = 2"
        "kernel.pid_max = 65536"
        "kernel.randomize_va_space = 2"
        "kernel.sysrq = 0"
        "kernel.unprivileged_bpf_disabled = 1"
        "kernel.yama.ptrace_scope = 1"
        "net.core.bpf_jit_harden = 2"
        "net.ipv4.conf.all.accept_redirects = 0"
        "net.ipv4.conf.all.accept_source_route = 0"
        "net.ipv4.conf.all.log_martians = 1"
        "net.ipv4.conf.all.rp_filter = 1"
        "net.ipv4.conf.all.secure_redirects = 0"
        "net.ipv4.conf.all.send_redirects = 0"
        "net.ipv4.conf.default.accept_source_route = 0"
        "net.ipv4.conf.default.log_martians = 1"
        "net.ipv4.conf.default.rp_filter = 1"
        "net.ipv4.conf.default.secure_redirects = 0"
        "net.ipv4.conf.default.send_redirects = 0"
        "net.ipv4.icmp_echo_ignore_all = 1"
        "net.ipv4.icmp_echo_ignore_broadcasts = 1"
        "net.ipv4.icmp_ignore_bogus_error_responses = 1"
        "net.ipv4.tcp_max_syn_backlog = 2048"
        "net.ipv4.tcp_syn_retries = 5"
        "net.ipv4.tcp_synack_retries = 2"
        "net.ipv4.tcp_syncookies = 1"
        "net.ipv6.conf.all.accept_redirects = 0"
        "net.ipv6.conf.all.accept_source_route = 0"
    )

    # Backup config files
    backup_file "$SYSCTL_FILE"
    backup_file "$CUSTOM_SYSCTL_FILE"

    # Remove old config from /etc/sysctl.conf and delete cis_config file from /etc/sysctl.d
    remove_old_config "$context" "$SYSCTL_FILE"
    sudo rm "$CUSTOM_SYSCTL_FILE"

    # Add header to sysctl.conf
    add_header "$context" "$SYSCTL_FILE"
    add_header "$context" "$CUSTOM_SYSCTL_FILE"
    
    for setting in "${sysctl_config[@]}"; do
        if [[ "$setting" =~ ^[a-zA-Z0-9._-]+[[:blank:]]*=[[:blank:]]*[0-9]+$ ]]; then
            local key=${setting%%=*}
            if sudo grep -q -E "^${key}\b" "$SYSCTL_FILE" && ! sudo grep -q -E "^#.*${key}\b" "$SYSCTL_FILE"; then
                sudo sed -i -e "/^[[:space:]\xc2\xa0]*${key}\b/s/^/#&/" "$SYSCTL_FILE" || handle_error "Failed to comment out existing $key"
                log "Commented out existing ${key} in $SYSCTL_FILE"
            fi
            echo -e "$setting" | sudo tee -a "$SYSCTL_FILE"
            echo -e "$setting" | sudo tee -a "$CUSTOM_SYSCTL_FILE"
        else
            echo "Bad systctl parameter - skipping $setting"
        fi
    done
    
    # Add footer to sysctl.conf
    add_footer "$context" "$SYSCTL_FILE"
    add_footer "$context" "$CUSTOM_SYSCTL_FILE"

    # Apply settings
    sudo sysctl -p || handle_error "Failed to apply sysctl changes. Please check $SYSCTL_FILE"

    # Add to changed config files to list
    update_changed_files "$SYSCTL_FILE"
    log "true" "Kernel settings applied to sysctl"
}

# Function to apply secure settings to SSH
configure_ssh() {
    # Configuration settings in custom file in sshd_conf.d directory have precedence over sshd_config file
    if ! dpkg -l | grep -q "openssh-server"; then
        log "true" "Installing OpenSSH Server..."
        install_package "openssh-server"
    fi
    log "true" "Configuring secure settings for SSH..."
    local context="SSHD Settings"
    # SSH configuration settings
    local settings=(
        "AllowAgentForwarding no"
        "AllowGroups sshusers"
        "AllowStreamLocalForwarding no"
        "AllowTcpForwarding no"
        "AllowUsers *"
        "Banner /etc/ssh/ssh-banner"
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
        "ClientAliveCountMax 2"
        "ClientAliveInterval 300"
        "FingerprintHash SHA256"
        "GatewayPorts no"
        "GSSAPIKeyExchange no"
        "IgnoreRhosts yes"
        "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
        "KbdInteractiveAuthentication yes"
        "LoginGraceTime 120"
        "LogLevel INFO"
        "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
        "MaxAuthTries 3"
        "MaxSessions 3"
        "MaxStartups 10:30:100"
        "PermitEmptyPasswords no"
        "PermitRootLogin no"
        "PermitTunnel no"
        "PermitUserEnvironment no"
        "PermitUserRC no"
        "PrintLastLog yes"
        "Protocol 2"
        "RekeyLimit 512M 6h"
        "StrictModes yes"
        "TCPKeepAlive no"
        "UseDNS no"
        "X11Forwarding no"
        "X11UseLocalhost no"
    )

    # Check if sshusers group is present else create it
    # Add current user to sshusers group to prevent lockout
    log "true" "Checking for sshusers group..."
    local current_user=$(logname)
    if ! getent group "sshusers"; then
        log "false" "sshusers group not found. Creating..."
        sudo groupadd "sshusers" || handle_error "Failed to create sshusers group"
        Log "true" "Adding $current_user to sshusers to prevent lockout"
        sudo usermod -aG "sshusers" "$current_user" || handle_error "Failed to add $current_user to sshusers"
    fi

    # Handle existing config files
    backup_file "$SSHD_FILE"
    backup_file "$CUSTOM_SSHD_FILE"

    # Remove old config from /etc/ssh/sshd_config and delete cis_config file from /etc/ssh/sshd_config.d
    remove_old_config "$context" "$SSHD_FILE"
    sudo rm "$CUSTOM_SSHD_FILE"

    # Add settings to config files
    add_header "$context" "$SSHD_FILE"
    add_header "$context" "$CUSTOM_SSHD_FILE"
    for setting in "${settings[@]}"; do
        local key=${setting%% *}
        if sudo grep -q -E "^${key}\b" "$SSHD_FILE" && ! sudo grep -q -E "^#.*${key}\b" "$SSHD_FILE"; then
            sudo sed -i -e "/^[[:space:]\xc2\xa0]*${key}\b/s/^/#&/" "$SSHD_FILE" || handle_error "Failed to comment out existing $key"
            log "true" "Commented out existing ${key} in $SYSCTL_FILE"
        fi
        # Add location of custom_config file in /etc/ssh/sshd_config
        echo "$setting" | sudo tee -a "$SSHD_FILE" >/dev/null || handle_error "Failed to append $setting to $SSHD_FILE"
        # Add new settings to 99-cis_hardening.conf to override settings in sshd_config
        echo "$setting" | sudo tee -a "$CUSTOM_SSHD_FILE" >/dev/null || handle_error "Failed to append $setting to $CUSTOM_SSHD_FILE"
    done
    add_footer "$context" "$SSHD_FILE"
    add_footer "$context" "$CUSTOM_SSHD_FILE"

    # Add to changed config files to list
    update_changed_files "$CUSTOM_SSHD_FILE"
    update_changed_files "$SSHD_FILE"

    log "true" "Secure settings applied to SSH. Settings will be enabled after reboot."
}

# Function to fix file and directory permissions
apply_file_permissions() {
    log "true" "Applying restrictive permissions on /var/log files..."
    local logfiles=(
        "/var/log/cis_hardening.log"
        "/var/log/wtmp"
        "/var/log/btmp"
        "/var/log/lastlog"
        "/var/log/apt/history.log"
        "/var/log/apt/eipp.log.xz"
    )

    for file in "${logfiles[@]}"; do
        if [ -f "$file" ]; then
            sudo chmod 640 $(readlink -e $file) || handle_error "Failed to apply 640 permission on $file"
            log "true" "Changed 640 permission on $file"
        else
            log "false" "$file not found. skipping..."
        fi
    done

    log "true" "Restricting permissions on senstive system files & directories"

    local sysfiles=(
        "/etc/hosts"
        "/etc/passwd"
        "/etc/group"
    )

    for sysfile in "${sysfiles[@]}"; do
        local fileperm=$(stat -c "%a" $sysfile)
        local fileowner=$(stat -c "%U:%G" $sysfile)
        if [ $fileperm -ne 644 ]; then
            log "true" "Incorrect file permission $fileperm for $sysfile. Changing to 644"
            sudo chmod 644 $(readlink -e $sysfile) || handle_error "Failed to apply 644 permission on $sysfile"
            log "true" "File permission 644 applied to $sysfile"
        else
            log "true" "$sysfile permission $fileperm is correct"
        fi

        if [ $fileowner != "root:root" ]; then
            log "true" "Incorrect owner $fileowner for $sysfile. Changing ownership to root:root"
            sudo chown root:root $(readlink -e $sysfile) || handle_error "Failed to correct ownership of $sysfile"
            log "true" "Corrected ownership of $sysfile to root:root"
        else
            log "true" "$sysfile ownership $fileowner is correct"
        fi
    done

    # Ensure correct permissions for /etc/sudoers.d
    sudo chmod -R 0440 /etc/sudoers.d
    sudo chown -R root:root /etc/sudoers.d

    log "true" "Setting umask 077 to all users"

    if sudo grep -q "^umask" /etc/profile; then
        sudo sed -i "s/^umask.*/# &/" /etc/profile || handle_error "Failed to comment existing umask configuration in /etc/profile"
    fi
    echo -e "\n# CIS Hardening\numask 077" | sudo tee -a /etc/profile || handle_error "Failed to add umask 077 to /etc/profile"

    CHANGED_FILES+=("/etc/profile")
    log "true" "Added umask 077 to /etc/profile"

    if sudo grep -q "^umask" /etc/bash.bashrc; then
        sudo sed -i "s/^umask.*/# &/" /etc/bash.bashrc || handle_error "Failed to add umask 077 to /etc/bash.bashrc"
    fi
    echo -e "\n# CIS Hardening\numask 077" | sudo tee -a /etc/bash.bashrc >/dev/null || handle_error "Failed to add umask to /etc/bash.bashrc"
    CHANGED_FILES+=("/etc/bash.bashrc")
    log "true" "Added umask 077 to /etc/bash.bashrc"

    if sudo grep -q "^UMASK" /etc/login.defs; then
        sudo sed -i "s/^UMASK.*/UMASK 077/" /etc/login.defs || handle_error "Failed to add umask 077 to /etc/login.defs"
    fi
    echo -e "\n# CIS Hardening\nUMASK 077" | sudo tee -a /etc/login.defs >/dev/null || handle_error "Failed to add umask to /etc/login.defs"
    CHANGED_FILES+=("/etc/login.defs")
    log "true" "Added umask 077 to login.defs"

    if [[ -f /etc/profile.d/cis_hardening.sh ]]; then
        if sudo grep -q "^umask" /etc/profile.d/cis_hardening.sh; then
            sudo sed -i "s/^umask.*/umask 077/" /etc/profile.d/cis_hardening.sh || handle_error "Failed to add umask 077 to /etc/profile.d/cis_hardening.sh"
        else
            echo -e "\n# CIS Hardening\numask 077" | sudo tee -a /etc/profile.d/cis_hardening.sh >/dev/null || handle_error "Failed to add umask to /etc/profile.d/cis_hardening.sh"
        fi
    else
        echo -e "\n# CIS Hardening\numask 077" | sudo tee -a /etc/profile.d/cis_hardening.sh >/dev/null || handle_error "Failed to add umask to /etc/profile.d/cis_hardening.sh"
    fi

    # User can see only his processes
    sudo sed -i "s/^proc.*/#&/" /etc/fstab || handle_error "Failed to comment out proc in /etc/fstab"
    echo "proc    /proc    proc    defaults,hidepid=2    0    0" | sudo tee -a /etc/fstab >/dev/null || handle_error "Failed to add proc settings to /etc/fstab"

    CHANGED_FILES+=("/etc/profile.d/cis_hardening.sh")
    log "true" "Added umask 077 to profile.d/cis_hardening.sh"
}

# Function to disable root login
disable_root() {
    log "true" "Checking for non-root users with sudo privileges..."

    # Get the list of users with sudo privileges
    sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$")

    # Check if there are any non-root users with sudo privileges
    if [ -z "$sudo_users" ]; then
        log "false" "Did not find any non-root users with sudo privileges. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        exit 1
    fi

    log "true" "Non-root users with sudo privileges found. Proceeding to disable root login..."

    # Disable root login
    if sudo passwd -l root; then
        log "true" "Root login disabled successfully."
    else
        handle_error "Failed to lock root account"
    fi

    # Disable root SSH login as an additional precaution
    if sudo grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sudo sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config || handle_error "Failed to disable root SSH login in sshd_config"
    else
        echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config >/dev/null || handle_error "Failed to add PermitRootLogin no to sshd_config"
    fi

    # Restart SSH service to apply changes
    sudo systemctl restart sshd || handle_error "Failed to restart SSH service"

    log "true" "Root login has been disabled and SSH root login has been explicitly prohibited."
}

# Function to limit su to wheel members
limit_su() {
    local current_user=$(logname)
    local pattern="auth[[:space:]]+required[[:space:]]+pam_wheel\.so"
    log "true" "Limiting su to only wheel members..."
    if ! getent group "wheel" >/dev/null; then
        log "true" "wheel group not found. Adding group..."
        sudo groupadd --system wheel || handle_error "Failed to add wheel group"
        sudo usermod -aG wheel "$current_user" || handle_error "Failed to add $current_user to wheel. No changes made"
    else
        log "true" "Checking if current user is a wheel member"
        if ! groups "$current_user" | grep -q '\bwheel\b'; then
            log "true" "$current_user is not wheel member. Adding $current_user to wheel..."
            sudo usermod -aG wheel "$current_user" || handle_error "Failed to add $current_user to wheel. No changes made"
        else
            log "true" "$current_user is already and member of wheel"
        fi
    fi

    backup_file "/etc/pam.d/su"
    sudo sed -i "/^auth[[:space:]]*required[[:space:]]*pam_wheel\.so/s/^/# /" /etc/pam.d/su || handle_error "Failed to modify /etc/pam.d/su"
    echo -e "\n# Limiting su to wheel members\nauth required pam_wheel.so use_uid" | sudo tee -a /etc/pam.d/su >/dev/null || handle_error "Failed to apply su to wheel members only"
    log "true" "$current_user is added to wheel. su is now limited to wheel members"
}

# Function to enable strong password enforcement
configure_password() {
    local pw_config_file="/etc/security/pwquality.conf"
    local pam_config_file="/etc/pam.d/common-password"
    backup_file "$pw_config_file"
    backup_file "$pam_config_file"
    log "true" "Installing libpam-pwquality to enforce strong passwords..."
    if ! dpkg -l | grep -q "libpam-pwquality"; then
        install_package "libpam-pwquality"
        log "true" "libpam-pwquality is sucessfully installed"
    else
        log "false" "libpam-pwquality already installed"
    fi
    log "true" "Configuring system to enforce strong passwords"

    # Remove previous hardening configurations
    if sudo grep -q "# Enforce strong passwords - Start" $pw_config_file; then
        sudo sed -i '/^# Enforce strong passwords - Start/,/^# Enforce strong passwords - End/d' "$pw_config_file" || handle_error "Failed to delete previous configuration in $pw_config_file"
        sudo sed -i -z 's/\n*[[:space:]]*$/d/' "$pw_config_file" || handle_error "Failed to delete trailing empty lines in $pw_config_file"
    fi

    if sudo grep -q "# Enforce strong passwords - Start" $pam_config_file; then
        sudo sed -i '/^# Enforce strong passwords - Start/,/^# Enforce strong passwords - End/d' "$pam_config_file" || handle_error "Failed to delete previous configuration in $pam_config_file"
        sudo sed -i -z 's/\n*[[:space:]]*$/d/' "$pam_config_file" || handle_error "Failed to delete trailing empty lines in $pam_config_file"
    fi

    # Add cis hardening headers to config files
    echo "# Enforce strong passwords - Start" | sudo tee -a $pw_config_file || handle_error "Failed to write header to $pw_config_file"
    echo "# Enforce strong passwords - Start" | sudo tee -a $pam_config_file || handle_error "Failed to write header to $pam_config_file"
    # Comment out existing pam_pwquality settings
    sudo sed -i '/^[[:space:]]*password.*pam_pwquality/s/^/#/' $pam_config_file
    # Add password rules to pw_quality config file
    echo -e "minlen = 10\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\minclass=4" | sudo tee -a $pw_config_file >/dev/null || handle_error "Failed to write to $pw_config_file"
    # Add matching pw_quality rules for pam_pwquality.so
    echo "password requisite pam_pwquality.so retry=3 minlen=10 minclass=4 enforce_for_root" | sudo tee -a $pam_config_file >/dev/null || handle_error "Failed to modify pam_pwquality.so in $pam_config_file"
    # Comment existing password rules for pam_unix.so
    sudo sed -i '/^[[:space:]]*password.*pam_unix.so/s/^/#/' $pam_config_file
    # Add password rules pam_unix.so
    echo "password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt rounds=8" | sudo tee -a $pam_config_file >/dev/null || handle_error "Failed to modify pam_unix.so in $pam_config_file"
    # Add cis hardening footers to config files
    echo "# Enforce strong passwords - End" | sudo tee -a $pam_config_file || handle_error "Failed to write header to $pam_config_file"
    echo "# Enforce strong passwords - End" | sudo tee -a $pw_config_file || handle_error "Failed to write header to $pw_config_file"
    update_changed_files "$pw_config_file"
    log "true" "Strong passwords are now enforced using pam_pwquality"
}

# Function to secure boot settings
secure_boot() {
    log "true" "Securing Boot Settings..."

    # Secure GRUB configuration file
    if [ -f /boot/grub/grub.cfg ]; then
        sudo chown root:root /boot/grub/grub.cfg || handle_error "Failed to change ownership of grub.cfg"
        sudo chmod 600 /boot/grub/grub.cfg || handle_error "Failed to change permissions of grub.cfg"
        log "true" "GRUB configuration file secured"
    else
        log "false" "/boot/grub/grub.cfg not found. Skipping GRUB file permissions."
    fi

    # Modify kernel parameters
    if [ -f /etc/default/grub ]; then
        # Backup original file
        backup_file "/etc/default/grub"

        # Add or modify kernel parameters
        local kernel_params="audit=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0"

        if command -v apparmor_status &>/dev/null; then
            kernel_params+=" apparmor=1 security=apparmor"
        fi

        if sudo grep -q "blacklist usb-storage" /etc/modprobe.d/cis_hardening.conf; then
            kernel_params+=" nousb"
        fi

        sudo sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"$kernel_params\"/" /etc/default/grub || handle_error "Failed to modify kernel parameters"

        # Update GRUB
        if command -v update-grub &>/dev/null; then
            sudo update-grub || handle_error "Failed to update GRUB"
        elif command -v grub2-mkconfig &>/dev/null; then
            sudo grub2-mkconfig -o /boot/grub2/grub.cfg || handle_error "Failed to update GRUB"
        else
            log "false" "Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
        fi

        log "true" "Kernel parameters updated"
    else
        log "false" "/etc/default/grub not found. Skipping kernel parameter modifications."
    fi
    
    update_changed_files "/etc/default/grub"
    log "true" "Boot settings secured"
}

# Function to setup Google 2FA
setup_2fa() {
    log "true" "Setting up Google 2FA Authentication"
    
    if ! dpkg -l | grep -q "libpam-google-authenticator"; then
        install_package "libpam-google-authenticator"
        backup_file "/etc/pam.d/sshd"
        echo -e "\n# Google 2FA Authentication" | sudo tee -a /etc/pam.d/sshd >/dev/null
        echo "auth required pam_google_authenticator.so nullok" | sudo tee -a /etc/pam.d/sshd >/dev/null || handle_error "Failed to add Google Authenticator to /etc/pam.d/sshd"
        if ! grep -q "^ChallengeResponseAuthentication" /etc/ssh/sshd_config; then
            echo "ChallengeResponseAuthentication yes" | sudo tee -a /etc/ssh/sshd_config >/dev/null || handle_error "Failed to enable ChallengeResponseAuthentication"
        else
            sudo sed -i "s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config || handle_error "Failed to modify ChallengeResponseAuthentication"
        fi
    else
        log "false" "Google 2FA is already installed on your system"
    fi
    
    update_changed_files "/etc/pam.d/sshd"
    update_changed_files "/etc/ssh/sshd_config"
    log "true" "Google 2FA authentication is enabled. Please run google-authenticator in your next login to enable 2FA"
}

# Function for miscellaneous settings to remove system info from motd, issue
apply_misc() {
    if dpkg -l | grep -q "arpwatch"; then
        log "true" "Arp monitoring software not found. Installing arpwatch..."
        install_package "arpwatch"
    fi

    log "true" "Applying miscellaneus security settings..."

    log "true" "Disabling motd"
    sudo sed -i "s/.*pam_motd.so.*/#&/" /etc/pam.d/login || handle_error "Failed to disable motd for console users"
    sudo sed -i "s/.*pam_motd.so.*/#&/" /etc/pam.d/sshd || handle_error "Failed to disable motd for ssh users"

    log "true" "Removing sensitive information for /etc/issue and /etc/issue.net"
    sudo sed -i 'd' /etc/issue || handle_error "Failed to delete all lines from /etc/issue"
    sudo sed -i 'd' /etc/issue.net || handle_error "Failed to delete all lines from /etc/issue.net"

    local issue=(
        "******************************************************************************"
        "   WARNING: Unauthorized access to this system is strictly prohibited."
        "   All activities on this system are logged and monitored. By logging in,"
        "   you acknowledge that you are authorized to access this system and agree"
        "   to abide by all relevant policies and regulations."
        "   Unauthorized users will be prosecuted to the fullest extent of the law."
        "******************************************************************************"
        ""
    )
    for msg in "${issue[@]}"; do
        echo -e "$msg" | sudo tee -a /etc/issue || handle_error "Failed to update /etc/issue"
        echo -e "$msg" | sudo tee -a /etc/issue.net || handle_error "Failed to update /etc/issue.net"
        echo -e "$msg" | sudo tee -a /etc/ssh/ssh-banner || handle_error "Failed to update /etc/ssh/ssh-banner"
    done

    log "true" "Removed sensitive information for /etc/issue and /etc/issue.net"
    log "true" "Restricting unauthorised access to /etc/issue and /etc/issue.net"
    sudo chown root:root $(readlink -e /etc/issue)
    sudo chmod u-x,go-wx $(readlink -e /etc/issue)
    log "true" "Restricted unauthorised access to /etc/issue and /etc/issue.net"

    log "true" "Enabling peristent storage for journald"
    echo "Storage=persistent" | sudo tee -a /etc/systemd/journald.conf >/dev/null || handle_error "Failed to enable persistent storage for journald"
    log "true" "Enabled persistent storage for journald"

    log "true" "Disabling core dumps"
    echo -e "*\tsoft\tcore\t0\n*\thard\tcore\t0" | sudo tee -a /etc/security/limits.conf

    update_changed_files "/etc/issue"
    update_changed_files "/etc/issue.net"
    update_changed_files "/etc/ssh/ssh-banner"
    update_changed_files "/etc/systemd/journald.conf"
    update_changed_files "/etc/security/limits.conf"

    log "true" "Finished applying miscellaneous security settings"
}

# Function to enable automatic updates
enable_updates() {
    log "true" "Enabling automatic updates..."
    install_package "unattended-upgrades"
    sudo dpkg-reconfigure -plow unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    log "true" "Automatic security updates configured"
}

setup_lynis() {
    if ! command -v "git"; then
        log "true" "Git not found. Installing..."
        install_package "git"
    fi
    log "true" "Downloading Lynis into $(pwd)"
    git clone "https://github.com/CISOfy/lynis"
    log "true" "Lynis is downloaded to $(pwd). You can run 'lynis audit system' to audit your system"
    log "true" "Visit https://github.com/CISOfy/lynis for details"
}

is_dryrun() {
    echo "Running in dry-run mode, no changes will be made."
    if [ "$dry_run" -eq 1 ]; then
        echo "dry run called"
        local userid=$(logname)
        echo -e "$userid"
        local usergroup=$(id -ng $userid)
        echo -e "$usergroup"
        local user_dir="/home/$userid"
        sudo mkdir -p "$user_dir/cis_dryrun"
        local dryrun_dir="/$user_dir/cis_dryrun"
        sudo cp "/etc/ssh/sshd_config" $dryrun_dir
        sudo cp "/etc/pam.d/sshd" $dryrun_dir
        sudo cp "/etc/sysctl.conf" $dryrun_dir
        MODULES_FILE="$dryrun_dir/cis_hardening.conf"
        SSHD_FILE="$dryrun_dir/sshd_config"
        CUSTOM_SSHD_FILE="$dryrun_dir/99_cis_hardening_sshd.conf"
        SYSCTL_FILE="$dryrun_dir/sysctl.conf"
        CUSTOM_SYSCTL_FILE="$dryrun_dir/99_cis_hardening_sysctl.conf"
        BACKUP_PATH="$dryrun_dir/backups"
        disable_ipv6
        disable_unused_modules
        disable_usb
        configure_ssh
        configure_sysctl
        sudo chown -R "$userid:$usergroup" "$dryrun_dir"
        echo "Check $dryrun_dir for configuration files that will be effect by this script"
        exit 1
    fi
}

main() {
    # Trap the SIGINT signal (Ctrl+C) and call the cleanup function
    trap cleanup SIGINT

    local dry_run=0
    if [[ "$1" = "--dry-run" ]]; then
        dry_run=1
    fi

    is_dryrun

    # Run apt update to get latest packages
    update_system

    clear
    echo -e "${BLUE}"
    print_centered "-" "-"
    print_centered "${GOLD}${BOLD}WELCOME TO AUREUM NETWORK${NORMAL}${NC}"
    print_centered "${LTGRAY}${ITALIC}:: ENHANCED CIS HARDENING SCRIPT 1.0 ::${NORMAL}${NC}"
    print_centered "${DARKGRAY}${COPYRIGHT} All rights reserved 2025${NORMAL}${BLUE}"
    print_centered "-" "-"
    echo -e "${NC}" >/dev/null

    check_permissions
    check_requirements

    # Start script
    echo -e "\n${CYAN}CIS Hardening script will run in 5 seconds!${NC}\nEnter ${LTRED}Ctrl-C${NC} to Stop\n"
    echo -e -n "${ITALIC}${LTCYAN}Starting script "
    for i in {1..5}; do
        echo -n ". "
        sleep 1
    done
    echo -e "${NC}${NORMAL}\n"
    sleep 1

    local answer
    echo "${CYAN}All securty events are reported to $EMAIL by default${NC}"
    read -p "${YELLOW}Do you want to receive them on your email? [Y/n]:${NC} " answer
    answer=$(echo "$answer" | xargs)
    case $answer in
    [Yy]* | "")
        while true; do
            read -p "Enter email address: " EMAIL
            if [[ $EMAIL =~ $EMAIL_REGEX ]]; then
                log "true" "All security events will be reported to ${CYAN}$EMAIL.${NC}"
                if ask_question "Confirm $EMAIL?" "Y"; then
                    break
                fi
            else
                echo -e "${RED}Invalid email address. Please try again.${NC}\n"
            fi
        done
        ;;
    * )
        echo -e "${YELLOW}Leaving default address for reporting security events.${NC}\n"
        ;;
    esac

    if [ -f "$LOG_FILE" ] >/dev/null 2>&1; then
        local logbackup=$LOG_FILE.$(date +%F_%H%M%S).bak
        sudo cp $LOG_FILE $logbackup || handle_error "Failed to backup cis_hardening.log file"
        log "true" "\nBacked up $(basename $LOG_FILE) to $logbackup\n"
        sudo rm $LOG_FILE
    fi

    # Run questionnaire to get user selection
    while true; do
        questionnaire
        show_selection_summary
        echo -e "\n"
        if ask_question "${BOLD}${RED}Do you want to proceed with these actions?${NC}${NORMAL}" "Y"; then
            echo -e "\n${BOLD}${LTGREEN}===== EXECUTING SELECTED ACTIONS ======${NC}${NORMAL}"
            execute_actions
            echo -e "\n${GREEN}=== SELECTED ACTIONS COMPLETED ===\n${NC}"
            break
        else
            echo -e "\n${BOLD}${LTRED}Restarting questionnaire...\n${NC}${NORMAL}"

        fi
    done

    # List all changed files
    if ! [[ -z ${CHANGED_FILES[@]} ]]; then
        echo -e "${ITALIC}${YELLOW}The following files have been modified by this script.\n\n${NC}${NORMAL}"
        printf "\t%s\n" "${ITALIC}${MAGENTA}${CHANGED_FILES[@]}${NC}${NORMAL}"
        echo -e "${ITALIC}${YELLOW}Backup copies of the these files are store in ${LTBLUE}/root/cis_hardening\n\n${NC}${NORMAL}"
        log "true" "List of services installed and running"
        sudo systemctl list-units --type=service --state=running
    else
        echo -e "${YELLOW}No files have been changed by this script.\n\n${NC}"
    fi
    
    echo -e "$(tput blink)${BOLD}${RED}\nPlease reboot the system\n${NC}${NORMAL}"
}

# Run the main function
main "$@"

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
import platform
import time
from datetime import datetime
import json
import random
import os
import subprocess
import sys
import re

# Add this at the beginning to prompt for privileges if needed
def request_elevated_privileges():
    current_os = platform.system()
    if current_os == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # If not running as admin, relaunch the script with elevation
            script_path = os.path.abspath(sys.argv[0])
            params = " ".join([script_path] + sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit(0)
    elif current_os in ["Linux", "Darwin"]:
        # Simple privilege check for Unix-like systems (less sophisticated than full sudo prompt)
        if os.geteuid() != 0:
            # We don't implement the sudo prompt here to avoid GUI blocking/complexity, 
            # instead relying on the main check_privileges function to report the status.
            pass

request_elevated_privileges()

# --- Core Data Structures  ---

MACOS_KNOWN_PORTS = {
    7000: {
        "name": "AirPlay Receiver / Screen Sharing Discovery",
        "desc": "Used for incoming AirPlay connections and macOS Screen Sharing discovery.",
        "remediation": "To disable: Go to System Settings > General > AirDrop & Handoff, and disable 'AirPlay Receiver'."
    },
    5000: {
        "name": "macOS Control Center Helper",
        "desc": "Often related to ControlCenter or other system device connectivity services.",
        "remediation": "This typically stops if AirPlay (Port 7000) is disabled. Review Media Sharing settings if it persists."
    },
    50654: {
        "name": "Apple Continuity (rapportd)",
        "desc": "Daemon used for Handoff, Universal Clipboard, and other peer-to-peer services.",
        "remediation": "To disable Handoff: Go to System Settings > General > AirDrop & Handoff, and disable 'Allow Handoff between this Mac and your iCloud devices'."
    }
}

LINUX_KNOWN_PORTS = {
    22: {
        "name": "SSH",
        "desc": "Secure Shell server.",
        "remediation": "If not needed, disable SSH service: systemctl disable sshd && systemctl stop sshd."
    },
    80: {
        "name": "HTTP",
        "desc": "Web server.",
        "remediation": "Ensure it's secured or disable if unnecessary."
    },
    443: {
        "name": "HTTPS",
        "desc": "Secure web server.",
        "remediation": "Ensure certificates are up to date."
    }
}

WINDOWS_KNOWN_PORTS = {
    3389: {
        "name": "RDP",
        "desc": "Remote Desktop Protocol.",
        "remediation": "Disable if not needed: Control Panel > System > Remote Settings."
    },
    445: {
        "name": "SMB",
        "desc": "Server Message Block.",
        "remediation": "Disable if not sharing files: Turn off File and Printer Sharing."
    }
}

# --- Utility Functions ---
def check_privileges():
    """Check if the script is running with elevated (sudo/root) privileges."""
    current_os = platform.system()
    if current_os == "Linux" or current_os == "Darwin":
        return os.geteuid() == 0
    elif current_os == "Windows":
        try:
            # Check for Admin rights by trying a command only admins can reliably execute
            subprocess.check_output("net session", stderr=subprocess.STDOUT, shell=True)
            return True
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            return False
    return False

def get_real_command_output(command, shell=False):
    """Safely executes a system command and returns stdout."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            shell=shell,
            # Use short timeout for potentially interactive or slow commands
            timeout=10 
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None

def check_disk_encryption():
    """Checks for disk encryption status (FileVault on macOS, LUKS on Linux, BitLocker on Windows)."""
    current_os = platform.system()
    
    if current_os == "Darwin":
        output = get_real_command_output(["fdesetup", "status"])
        if output is None:
            return {
                'name': "Disk Encryption (FileVault)", 
                'status': "ERROR", 
                'message': "Could not run 'fdesetup status'. Verify elevated privileges.", 
                'remediation': "Run the application with 'sudo' or check permissions on fdesetup.", 
                'severity': 5
            }
        if "FileVault is On." in output:
            return {
                'name': "Disk Encryption (FileVault)", 
                'status': "PASS", 
                'message': "macOS FileVault disk encryption is enabled.", 
                'remediation': "N/A", 
                'severity': 0
            }
        else:
            return {
                'name': "Disk Encryption (FileVault)", 
                'status': "FAIL", 
                'message': "FileVault is reported as Off.", 
                'remediation': "Enable FileVault in System Settings > Security & Privacy > FileVault. Command: fdesetup enable", 
                'severity': 9
            }
    
    elif current_os == "Linux":
        output = get_real_command_output(["lsblk", "-o", "NAME,TYPE,SIZE,MOUNTPOINT,CRYPT"])
        if output is None:
            return {
                'name': "Disk Encryption (Linux)", 
                'status': "WARN", 
                'message': "Could not run 'lsblk' or get output. Verify elevated privileges and 'lsblk' tool presence.", 
                'remediation': "Verify disk encryption manually (e.g., check dm-crypt or LUKS status). Command: lsblk -o NAME,TYPE,SIZE,MOUNTPOINT,CRYPT", 
                'severity': 5
            }
        if "crypt" in output.lower():
            return {
                'name': "Disk Encryption (Linux)", 
                'status': "PASS", 
                'message': "Encrypted block device (dm-crypt/LUKS) detected via 'lsblk'.", 
                'remediation': "N/A", 
                'severity': 0
            }
        else:
            return {
                'name': "Disk Encryption (Linux)", 
                'status': "FAIL", 
                'message': "No encrypted block device (dm-crypt/LUKS) detected via 'lsblk'.", 
                'remediation': "Implement full disk encryption using LUKS during OS installation or manually via cryptsetup.", 
                'severity': 9
            }
    
    # --- START OF WINDOWS (BITLOCKER) UPDATE ---
    elif current_os == "Windows":
        wmic_cmd = ["wmic", "logicaldisk", "where", "drivetype=3", "get", "DeviceID"]
        wmic_cmd_str = " ".join(wmic_cmd)
        drives_output = get_real_command_output(wmic_cmd, shell=True)
        
        if drives_output is None:
             return {
                'name': "Disk Encryption (BitLocker)", 
                'status': "ERROR", 
                'message': f"Could not run '{wmic_cmd_str}'. Verify elevated privileges.", 
                'remediation': "Run with Admin rights.", 
                'severity': 5
            }
        
        # Extract drive letters (e.g., C:, D:)
        drive_letters = [line.strip() for line in drives_output.split('\n') if line.strip() and len(line.strip()) == 2 and line.strip().endswith(':')]
        
        encryption_status = {}
        for drive in drive_letters:
            # Check BitLocker status for each drive
            bde_cmd = ["manage-bde", "-status", drive]
            bde_output = get_real_command_output(bde_cmd, shell=True)
            if bde_output:
                # FIX 1: Use regex for Protection Status to handle variable spacing
                protection_match = re.search(r'Protection Status:\s+Protection On', bde_output, re.IGNORECASE)
                protection = bool(protection_match)
                
                # FIX 2: Use highly tolerant regex to match 100% regardless of decimal point/locale/spacing
                # Matches "Percentage Encrypted: [any text] 100[.0...0]%"
                encrypted_match = re.search(r'Percentage Encrypted:.*?100(\.0+)?%', bde_output.replace(',', '.'))
                encrypted = bool(encrypted_match)

                encryption_status[drive] = {'Protection': protection, 'Encrypted': encrypted}
        
        c_status = encryption_status.get('C:', {'Protection': False, 'Encrypted': False})
        status = "UNKNOWN"
        severity = 5
        remediation = "Verify BitLocker on all critical fixed drives."
        
        # 3. Aggregate results: Require C: to be encrypted.
        if 'C:' not in encryption_status:
            status = "ERROR"
            message = f"Could not verify BitLocker for C: drive. (Used commands: {wmic_cmd_str} and manage-bde -status [drive])"
            severity = 5
        elif c_status['Protection'] and c_status['Encrypted']:
            status = "PASS"
            severity = 0
            message = "System drive (C:) is fully encrypted."
            if any(not s['Protection'] or not s['Encrypted'] for d, s in encryption_status.items() if d != 'C:'):
                message += " WARNING: Some non-system drives are not fully protected."
                severity = 4
            remediation = "N/A"
        else:
            status = "FAIL"
            severity = 9
            message = "System drive (C:) is not fully protected by BitLocker."
            remediation = f"Enable BitLocker Drive Encryption for the C: drive. Manual Check (Run as Admin): manage-bde -status C:"
            
        # Append detailed status for all drives to the message
        detailed_status = "; ".join([f"{d}: Prot={'ON' if s['Protection'] else 'OFF'}, Enc={'100%' if s['Encrypted'] else '<100%'}" for d, s in encryption_status.items()])
        message = f"{message} | Drive Details: {detailed_status}"

        return {
            'name': "Disk Encryption (BitLocker)", 
            'status': status, 
            'message': message, 
            'remediation': remediation, 
            'severity': severity
        }
    # --- END OF WINDOWS (BITLOCKER) UPDATE ---
    
    return {
        'name': "Disk Encryption (Other OS)", 
        'status': "UNKNOWN", 
        'message': "Disk encryption status check is not implemented for this OS.", 
        'remediation': "Verify disk encryption manually.", 
        'severity': 5
    }

def check_os_patch_status():
    """Checks for pending OS updates using native tools."""
    current_os = platform.system()
    
    # ... (macOS and Linux checks remain the same) ...
    if current_os == "Darwin":
        output = get_real_command_output(["softwareupdate", "--list"])
        if output is None:
            return {
                'name': "OS Patch Status (macOS)",
                'status': "WARN",
                'message': "Could not run 'softwareupdate --list'. Verify elevated privileges.",
                'remediation': "Run with sudo or verify system paths. Command: softwareupdate --list",
                'severity': 5
            }
        if "No new software available." in output:
            return {
                'name': "OS Patch Status (macOS)",
                'status': "PASS",
                'message': "No new macOS or Apple application updates found.",
                'remediation': "N/A",
                'severity': 0
            }
        else:
            return {
                'name': "OS Patch Status (macOS)",
                'status': "FAIL",
                'message': "Updates are available. Review 'softwareupdate --list' output.",
                'remediation': "Run 'softwareupdate -i -a --restart' to install all pending updates. Command: softwareupdate --list",
                'severity': 8
            }
    
    elif current_os == "Linux":
        # Try apt first
        if get_real_command_output(["which", "apt"]) is not None:
            subprocess.run(["apt", "update"], capture_output=True, check=False)
            result = get_real_command_output(["apt", "list", "--upgradable"])
            upgradable = [line for line in result.split('\n') if '/' in line] if result else []
            count = len(upgradable)
            if count > 0:
                return {
                    'name': "OS Patch Status (Linux/APT)",
                    'status': "FAIL",
                    'message': f"{count} packages require an update.",
                    'remediation': "Run 'sudo apt upgrade -y' to install pending updates. Command: apt list --upgradable",
                    'severity': 8
                }
            else:
                return {
                    'name': "OS Patch Status (Linux/APT)",
                    'status': "PASS",
                    'message': "No packages require upgrades.",
                    'remediation': "N/A",
                    'severity': 0
                }
        # Try dnf/yum fallback logic here...
        elif get_real_command_output(["which", "dnf"]) is not None:
             # DNF check logic (simplified)
            result = get_real_command_output(["dnf", "check-update"])
            count = len([line for line in result.split('\n') if line.strip() and not line.startswith(('Last metadata', 'Security'))]) if result else 0
            if count > 0:
                return {
                    'name': "OS Patch Status (Linux/DNF)",
                    'status': "FAIL",
                    'message': f"{count} packages require an update.",
                    'remediation': "Run 'sudo dnf upgrade -y' to install pending updates. Command: dnf check-update",
                    'severity': 8
                }
            else:
                 return {
                    'name': "OS Patch Status (Linux/DNF)",
                    'status': "PASS",
                    'message': "No packages require upgrades.",
                    'remediation': "N/A",
                    'severity': 0
                }
        else:
             return {
                'name': "OS Patch Status (Linux)",
                'status': "UNKNOWN",
                'message': "No supported package manager found (apt, dnf, yum).",
                'remediation': "Check updates manually.",
                'severity': 5
            }
    
    # --- START OF WINDOWS (PATCH STATUS) UPDATE ---
    elif current_os == "Windows":
        # Use Windows Update COM Object to check for available updates without external modules
        # Search for software updates (IsInstalled=0 and Type="Software")
        ps_script = "$Searcher = New-Object -ComObject Microsoft.Update.Searcher; $count = $Searcher.Search('IsInstalled=0 and Type=\"Software\"').Updates.Count; Write-Host $count"
        
        output = get_real_command_output(["powershell", "-Command", ps_script], shell=True)
        
        if output is None:
            # Fallback: Check if the Windows Update service is at least running
            service_output = get_real_command_output(["sc", "query", "wuauserv"], shell=True)
            if service_output and "RUNNING" in service_output:
                return {
                    'name': "OS Patch Status (Windows)",
                    'status': "WARN",
                    'message': "Could not reliably determine update count. Windows Update service is RUNNING. Manual verification recommended.",
                    'remediation': f"Verify patch status manually via Windows Settings. Command: {ps_script}",
                    'severity': 5
                }
            return {
                'name': "OS Patch Status (Windows)",
                'status': "ERROR",
                'message': "Windows Update check failed (COM object inaccessible). Service may be stopped.",
                'remediation': f"Ensure 'Windows Update' service (wuauserv) is running. Command: {ps_script}",
                'severity': 8
            }
        
        try:
            update_count = int(output.strip())
            if update_count > 0:
                return {
                    'name': "OS Patch Status (Windows)",
                    'status': "FAIL",
                    'message': f"{update_count} software updates are pending installation.",
                    'remediation': f"Run Windows Update (Settings > Windows Update). Command: {ps_script}",
                    'severity': 8
                }
            else:
                return {
                    'name': "OS Patch Status (Windows)",
                    'status': "PASS",
                    'message': "No pending software updates found.",
                    'remediation': "N/A",
                    'severity': 0
                }
        except ValueError:
             return {
                'name': "OS Patch Status (Windows)",
                'status': "WARN",
                'message': f"Update count check returned ambiguous output: {output.strip()}. Check manually.",
                'remediation': f"Check Windows Update manually. Command: {ps_script}",
                'severity': 5
            }
    # --- END OF WINDOWS (PATCH STATUS) UPDATE ---

    return {
        'name': "OS Patch Status", 
        'status': "UNKNOWN", 
        'message': "Automated patch status verification is not implemented for this OS.", 
        'remediation': "Ensure all OS and application updates are installed promptly.", 
        'severity': 3
    }

def check_ssh_security():
    """Reads and audits sshd_config for critical hardening settings, supporting Windows, Linux, and macOS paths."""
    current_os = platform.system()
    
    if current_os == "Windows":
        # Windows OpenSSH Server configuration path
        ssh_config_path = r"C:\ProgramData\ssh\sshd_config"
        check_service_cmd = "Get-Service sshd"
    elif current_os in ["Linux", "Darwin"]:
        # Standard Unix configuration path
        ssh_config_path = "/etc/ssh/sshd_config"
        check_service_cmd = "systemctl status sshd" if current_os == "Linux" else "launchctl list | grep ssh"
    else:
         return {
            'name': "SSH Server Configuration Audit",
            'status': "UNKNOWN",
            'message': "SSH config audit not implemented for this OS.",
            'remediation': "Check SSH configuration manually.",
            'severity': 5
        }
        
    status = "PASS"
    message = "SSH configuration adheres to strong security recommendations."
    remediation = "N/A"
    severity = 0
    checks = []
    
    try:
        with open(ssh_config_path, 'r') as f:
            content = f.read().lower()
    except FileNotFoundError:
        return {
            'name': "SSH Server Configuration Audit",
            'status': "WARN",
            'message': f"SSH configuration file not found at {ssh_config_path}. SSH server may not be installed or active.",
            'remediation': f"Install OpenSSH Server feature if needed. To check status: {check_service_cmd}",
            'severity': 3
        }
    except Exception as e:
        return {
            'name': "SSH Server Configuration Audit",
            'status': "ERROR",
            'message': f"Could not read SSH config at {ssh_config_path}: {str(e)}.",
            'remediation': "Run with elevated privileges.",
            'severity': 5
        }

    # Check PasswordAuthentication no
    if not re.search(r'^\s*passwordauthentication\s+no', content, re.MULTILINE):
        checks.append("PasswordAuthentication should be 'no' (use keys).")
    
    # Check PermitRootLogin no or prohibit-password
    if not re.search(r'^\s*permitrootlogin\s+(no|prohibit-password)', content, re.MULTILINE):
        checks.append("PermitRootLogin should be 'no' or 'prohibit-password'.")
    
    # Additional checks
    if not re.search(r'^\s*protocol\s+2', content, re.MULTILINE):
        checks.append("Protocol should be '2' to disable legacy SSH1.")
    
    if not re.search(r'^\s*pubkeyauthentication\s+yes', content, re.MULTILINE):
        checks.append("PubkeyAuthentication should be 'yes' for key-based auth.")
    
    if checks:
        status = "FAIL"
        severity = 8
        message = "SSH hardening issues: " + "; ".join(checks)
        remediation = f"Edit {ssh_config_path} with recommended settings and restart the SSH service. Command: {check_service_cmd}"
    
    return {
        'name': "SSH Server Configuration Audit", 
        'status': status, 
        'message': message, 
        'remediation': remediation, 
        'severity': severity
    }

def parse_open_ports():
    """Executes OS-appropriate command to find listening ports and enriches with process details."""
    current_os = platform.system()
    port_findings = []
    known_ports = {}
    
    if current_os == "Darwin":
        known_ports = MACOS_KNOWN_PORTS
        cmd = ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"]
    elif current_os == "Linux":
        known_ports = LINUX_KNOWN_PORTS
        cmd = ["ss", "-tuln"]
    elif current_os == "Windows":
        known_ports = WINDOWS_KNOWN_PORTS
        # netstat is still the easiest to parse for PID lookup via Python
        # IMPORTANT: netstat -ano provides PID, which is crucial.
        cmd = ["netstat", "-ano", "-p", "TCP"] 
    else:
        return port_findings
    
    output = get_real_command_output(cmd, shell=(current_os == "Windows"))
    if not output:
        return port_findings

    if current_os in ["Darwin", "Linux"]:
        lines = output.split('\n')[1:]
        for line in lines:
            if not line.strip(): continue
            parts = re.split(r'\s+', line)
            try:
                if current_os == "Darwin":
                    command = parts[0]
                    pid = int(parts[1])
                    user = parts[2]
                    addr = parts[8]
                    if '*' in addr or '->' in addr: continue
                    ip, port = addr.rsplit(':', 1) if ':' in addr else ('', addr)
                    port = int(port)
                else:  # Linux ss
                    if "LISTEN" not in line: continue
                    addr = parts[4]
                    ip, port = addr.rsplit(':', 1) if ':' in addr else ('', addr)
                    port = int(port)
                    pid_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                    command = pid_match.group(1) if pid_match else "Unknown"
                    pid = int(pid_match.group(2)) if pid_match else 0
                    user = "root" if pid == 0 else "user"
                
                # Simplified status for Unix
                is_public = ip in ['*', '0.0.0.0', '::']
                ip_classification = "PUBLIC/ALL INTERFACES" if is_public else "LOCAL ONLY"
                
                finding = {
                    'ip': ip,
                    'port': port,
                    'pid': pid,
                    'process_name': command,
                    'user': user,
                    'is_public': is_public,
                    'ip_classification': ip_classification
                }
                known = known_ports.get(port, {})
                finding['service_name'] = known.get('name', 'Unknown')
                finding['port_remediation'] = known.get('remediation', f"Review process {command} (PID {pid}).")
                port_findings.append(finding)
            except:
                continue
    elif current_os == "Windows":
        lines = output.split('\n')
        # Simple list of common system PIDs that often run services
        SYSTEM_PIDS = [4, 8, 308] # System, smss.exe, csrss.exe (PIDs can vary)

        for line in lines:
            if "LISTENING" not in line: continue
            parts = re.split(r'\s+', line)
            try:
                addr = parts[1]
                ip, port = addr.rsplit(':', 1) if ':' in addr else ('', addr)
                port = int(port)
                pid = int(parts[4])
                
                # Use a basic placeholder for process name since tasklist is unreliable for Python
                # The user's manual check with 'netstat -aonb' is the true validation
                process_name = "System Process" if pid in SYSTEM_PIDS else f"PID {pid}"
                user = "SYSTEM" if pid in SYSTEM_PIDS else "User"

                # REVISED LOGIC FOR PUBLIC/LOCAL CLASSIFICATION
                is_bound_all = ip in ['0.0.0.0', '[::]']
                # Check for standard private IP ranges
                is_private_ip = ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.'))
                
                # Determine classification
                is_public = is_bound_all
                is_loopback = ip in ['127.0.0.1', '::1']
                
                if is_public:
                    ip_classification = "PUBLIC/ALL INTERFACES"
                elif is_private_ip and not is_loopback:
                    ip_classification = "LOCAL LAN EXPOSED" # Warning level: reachable by LAN/VPN clients
                else:
                    ip_classification = "LOCAL ONLY" # Loopback or other specific local binding

                # Create specific remediation advice for network-exposed ports
                known = known_ports.get(port, {})
                default_remediation = f"Investigate PID {pid} using netstat -aonb (see details below)."
                
                if (port == 139 or port == 445) and (is_public or is_private_ip): 
                    # Specific remediation for SMB/NetBIOS when exposed to ANY network interface
                    default_remediation = "Port 139/445 (SMB) exposed. Disable File and Printer Sharing if not required, or restrict Windows Firewall access to trusted IPs only."

                finding = {
                    'ip': ip,
                    'port': port,
                    'pid': pid,
                    'process_name': process_name, # Placeholder name
                    'user': user,
                    'is_public': is_public, # Retain original meaning for the 'public' flag
                    'ip_classification': ip_classification
                }

                finding['service_name'] = known.get('name', 'Unknown')
                finding['port_remediation'] = known.get('remediation', default_remediation)
                port_findings.append(finding)
            except:
                continue
    
    return port_findings

def check_antivirus():
    """Checks for antivirus presence using OS-native methods (Security Center 2 on Windows)."""
    current_os = platform.system()
    if current_os == "Darwin":
        xprotect_path = '/Library/Apple/System/Library/CoreServices/XProtect.bundle'
        if os.path.exists(xprotect_path):
            message = "macOS built-in XProtect is present."
            status = "PASS"
            remediation = "N/A"
            severity = 0
            # Check for third-party AV
            applications_dir = '/Applications'
            known_av_keywords = ['eset', 'norton', 'avast', 'avg', 'bitdefender', 'malwarebytes', 'sophos', 'kaspersky', 'antivirus', 'security']
            try:
                detected_av = [app for app in os.listdir(applications_dir) if any(keyword in app.lower() for keyword in known_av_keywords)]
                if detected_av:
                    message += f" Third-party AV detected: {', '.join(detected_av)}."
            except:
                pass
            return {
                'name': "Antivirus",
                'status': status,
                'message': message,
                'remediation': remediation,
                'severity': severity
            }
        else:
            return {
                'name': "Antivirus",
                'status': "FAIL",
                'message': "XProtect not detected.",
                'remediation': "Update macOS or install third-party AV. Command: softwareupdate -i -a",
                'severity': 7
            }
    elif current_os == "Linux":
        if get_real_command_output(["which", "clamav"]) or get_real_command_output(["which", "clamscan"]):
            return {
                'name': "Antivirus (ClamAV)",
                'status': "PASS",
                'message': "ClamAV detected.",
                'remediation': "N/A",
                'severity': 0
            }
        else:
            return {
                'name': "Antivirus",
                'status': "WARN",
                'message': "No common AV detected (ClamAV).",
                'remediation': "Install ClamAV or other AV. Command: sudo apt install clamav",
                'severity': 6
            }
    elif current_os == "Windows":
        # Check Windows Security Center 2 for registered Antivirus products. This includes third-party AV like ESET.
        wmic_cmd = ["wmic", "/Node:localhost", "/Namespace:\\\\root\\SecurityCenter2", "Path", "AntiVirusProduct", "Get", "displayName", "/Format:List"]
        wmic_cmd_str = " ".join(wmic_cmd)
        output = get_real_command_output(wmic_cmd, shell=True)
        
        if output is None or "No Instance(s) Available." in output:
            return {
                'name': "Antivirus (Security Center)",
                'status': "FAIL",
                'message': "No active Antivirus registered in Windows Security Center.",
                'remediation': f"Enable Windows Defender or ensure third-party AV is running and registered. Command: {wmic_cmd_str}",
                'severity': 7
            }
        
        # Extract and list AV products
        av_products = re.findall(r'displayName=(.+)', output, re.IGNORECASE)
        av_list = [p.strip() for p in av_products if p.strip()]
        
        if av_list:
            return {
                'name': "Antivirus (Security Center)",
                'status': "PASS",
                'message': f"Active Antivirus detected: {', '.join(av_list)}.",
                'remediation': "N/A",
                'severity': 0
            }
        else:
            return {
                'name': "Antivirus (Security Center)",
                'status': "FAIL",
                'message': "No active Antivirus registered in Windows Security Center.",
                'remediation': f"Enable Windows Defender or ensure third-party AV is running and registered. Command: {wmic_cmd_str}",
                'severity': 7
            }

    return {
        'name': "Antivirus Check",
        'status': "UNKNOWN",
        'message': "Not implemented for this OS.",
        'remediation': "Install and enable antivirus software.",
        'severity': 5
    }

def check_selinux_appArmor():
    """Checks SELinux or AppArmor on Linux."""
    if platform.system() != "Linux":
        return None
    output = get_real_command_output(["getenforce"])
    if output == "Enforcing":
        return {
            'name': "SELinux",
            'status': "PASS",
            'message': "SELinux is enforcing.",
            'remediation': "N/A",
            'severity': 0
        }
    # Check AppArmor if SELinux is not detected
    output = get_real_command_output(["aa-status"])
    if output and "profiles are in enforce mode" in output:
        return {
            'name': "AppArmor",
            'status': "PASS",
            'message': "AppArmor is active and enforcing profiles.",
            'remediation': "N/A",
            'severity': 0
        }
    return {
        'name': "MAC (SELinux/AppArmor)",
        'status': "FAIL",
        'message': "No mandatory access control (SELinux or AppArmor) is active or enforcing.",
        'remediation': "Enable SELinux or AppArmor. Command: sudo setenforce 1",
        'severity': 7
    }

def check_uac_windows():
    """Checks UAC on Windows."""
    if platform.system() != "Windows":
        return None
    reg_cmd = ["reg", "query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA"]
    reg_cmd_str = " ".join(reg_cmd)
    output = get_real_command_output(reg_cmd, shell=True)
    if "0x1" in output:
        return {
            'name': "User Account Control (UAC)",
            'status': "PASS",
            'message': "UAC (EnableLUA) is enabled.",
            'remediation': "N/A",
            'severity': 0
        }
    else:
        return {
            'name': "User Account Control (UAC)",
            'status': "FAIL",
            'message': "UAC (EnableLUA) is disabled.",
            'remediation': f"Enable UAC in Control Panel > User Accounts. Registry Command: {reg_cmd_str} (should show 0x1)",
            'severity': 8
        }

def check_gatekeeper_macos():
    """Checks Gatekeeper on macOS."""
    if platform.system() != "Darwin":
        return None
    spctl_cmd = ["spctl", "--status"]
    output = get_real_command_output(spctl_cmd)
    if "assessments enabled" in output:
        return {
            'name': "Gatekeeper",
            'status': "PASS",
            'message': "Gatekeeper assessments are enabled.",
            'remediation': "N/A",
            'severity': 0
        }
    else:
        return {
            'name': "Gatekeeper",
            'status': "FAIL",
            'message': "Gatekeeper is disabled.",
            'remediation': f"Enable in System Settings > Security & Privacy or run 'sudo spctl --master-enable'. Command: {' '.join(spctl_cmd)}",
            'severity': 7
        }

def fetch_external_threat_alerts():
    """Fetches high-severity vulnerability alerts from CISA, US-CERT, and NVD via Google Search.
    
    NOTE: This feature requires integration with a generative model capable of Google Search.
    Since this code is a standalone Python application, the actual fetch call is replaced 
    with placeholder logic to ensure the application runs without SyntaxError.
    """
    print("External threat alert fetch skipped for local execution.")
    return [] # Return empty list in standalone execution environment

# --- Auditing Logic ---
def run_full_system_audit():
    print("Running system audit...")
    is_privileged = check_privileges()
    
    AUDIT_RESULTS = []
    
    if not is_privileged:
        script_name = os.path.basename(__file__)
        current_os = platform.system()
        remediation_command = "Relaunch Python script as Administrator" if current_os == "Windows" else f"Re-run with 'sudo python3 {script_name}'"
        AUDIT_RESULTS.append({
            'name': "Privilege Check", 
            'status': "FAIL", 
            'message': "Elevated privileges required for full audit. Many checks may show ERROR.", 
            'remediation': f"Re-run the script using {remediation_command}.", 
            'severity': 10 
        })

    # Firewall Check
    current_os = platform.system()
    if current_os == "Darwin":
        cmd = "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
        output = get_real_command_output(cmd.split())
        firewall_status = "PASS" if output and "enabled" in output.lower() else "FAIL"
        firewall_message = "Firewall enabled." if firewall_status == "PASS" else "Firewall disabled."
        firewall_remediation = "N/A" if firewall_status == "PASS" else f"Enable in System Settings > Network > Firewall. Command: {cmd}"
        firewall_severity = 0 if firewall_status == "PASS" else 10
    elif current_os == "Linux":
        cmd = "ufw status"
        output = get_real_command_output(cmd.split())
        firewall_status = "PASS" if output and "active" in output.lower() else "FAIL"
        firewall_message = "UFW active." if firewall_status == "PASS" else "UFW inactive or command failed."
        firewall_remediation = "N/A" if firewall_status == "PASS" else f"Run 'sudo ufw enable' or check other firewall services (e.g., firewalld). Command: {cmd}"
        firewall_severity = 0 if firewall_status == "PASS" else 10
    elif current_os == "Windows":
        # Use PowerShell to check if all three firewall profiles (Domain, Private, Public) are enabled.
        ps_command = "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"
        output = get_real_command_output(["powershell", "-Command", ps_command], shell=True)
        
        if output is None:
            firewall_status = "ERROR"
            firewall_message = "Could not run PowerShell command to check firewall profiles."
            firewall_remediation = "Verify PowerShell is available and you have Admin rights. Command: Get-NetFirewallProfile"
            firewall_severity = 5
        else:
            profile_states = [line.strip() for line in output.splitlines() if line.strip()]
            
            if profile_states and all(state == "True" for state in profile_states):
                firewall_status = "PASS"
                firewall_message = "Firewall is active for all network profiles (Domain, Private, Public)."
                firewall_remediation = "N/A"
                firewall_severity = 0
            else:
                fail_profiles = [state for state in profile_states if state != "True"]
                firewall_status = "FAIL"
                firewall_message = f"Firewall disabled for one or more profiles. Disabled states found: {len(fail_profiles)}."
                firewall_remediation = f"Ensure your firewall software (Windows Defender or third-party) is active and enforcing rules for all network profiles. Command: {ps_command}"
                firewall_severity = 10
    else:
        firewall_status = "UNKNOWN"
        firewall_message = "Firewall check not implemented for this OS."
        firewall_remediation = "Verify firewall status manually."
        firewall_severity = 5

    AUDIT_RESULTS.append({
        'name': "Active Firewall Check", 
        'status': firewall_status, 
        'message': firewall_message, 
        'remediation': firewall_remediation, 
        'severity': firewall_severity
    })

    # Disk Encryption
    AUDIT_RESULTS.append(check_disk_encryption())

    # OS Patches
    AUDIT_RESULTS.append(check_os_patch_status())

    # SSH Config
    AUDIT_RESULTS.append(check_ssh_security())

    # Antivirus
    AUDIT_RESULTS.append(check_antivirus())

    # Additional OS-specific checks
    selinux = check_selinux_appArmor()
    if selinux:
        AUDIT_RESULTS.append(selinux)
    uac = check_uac_windows()
    if uac:
        AUDIT_RESULTS.append(uac)
    gatekeeper = check_gatekeeper_macos()
    if gatekeeper:
        AUDIT_RESULTS.append(gatekeeper)

    # Open Ports
    PORT_FINDINGS = parse_open_ports()
    
    # External Alerts
    # This call is now a dummy function in the Python code
    CISA_FINDINGS = fetch_external_threat_alerts() 

    return AUDIT_RESULTS, PORT_FINDINGS, CISA_FINDINGS

# --- GUI Application ---

class AuditApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Orion's Guard System Hardening Auditor")
        self.geometry("900x700")
        
        self.full_audit_results = []
        self.port_findings = []
        self.cisa_findings = [] # Initialize new attribute

        self.style = ttk.Style(self)
        self.style.theme_use('clam') 
        self._configure_styles()
        
        self.current_os = platform.system()
        self._create_widgets()

    def _configure_styles(self):
        self.style.configure('Audit.TFrame', background='#1e1e1e')
        self.style.configure('Audit.TLabel', background='#1e1e1e', foreground='#ffffff', font=('Inter', 10))
        self.style.configure('Header.TLabel', background='#1e1e1e', foreground='#7fffd4', font=('Inter', 14, 'bold'))
        self.style.configure('Button.TButton', font=('Inter', 12, 'bold'), background='#007acc', foreground='#ffffff')

        self.style.configure("Treeview.Heading", font=('Inter', 10, 'bold'), foreground='#cccccc')
        self.style.configure("Treeview", font=('Inter', 9), background='#2d2d2d', foreground='#ffffff', rowheight=25)
        self.style.map('Treeview', background=[('selected', '#007acc')])
        
        self.text_tag_config = [
            ('header', {'foreground': '#7fffd4', 'font': ('Inter', 10, 'bold')}),
            ('message', {'foreground': '#ffffff', 'font': ('Inter', 9)}),
            ('remedy', {'foreground': '#f59e0b', 'font': ('Inter', 9)}),
        ]

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding="10", style='Audit.TFrame')
        main_frame.pack(fill='both', expand=True)

        is_privileged = check_privileges()
        privilege_text = "Running with ROOT/ADMIN privileges." if is_privileged else "Running without elevated privileges (Limited Scan)."
        
        info_label = ttk.Label(main_frame, text=f"System Hardening Audit - OS: {self.current_os}\n{privilege_text}", style='Header.TLabel', anchor='center')
        info_label.pack(pady=5)
        
        button_frame = ttk.Frame(main_frame, style='Audit.TFrame')
        button_frame.pack(pady=10)

        self.run_button = ttk.Button(button_frame, text="Run System Audit", command=self.run_audit_async, style='Button.TButton')
        self.run_button.pack(side='left', padx=5)

        self.export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results, style='Button.TButton')
        self.export_button.pack(side='left', padx=5)
        self.export_button.config(state='disabled')

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True, pady=10)

        self.general_frame = ttk.Frame(self.notebook, style='Audit.TFrame', padding=5)
        self.notebook.add(self.general_frame, text="General Security Checks")
        self._create_general_treeview(self.general_frame)

        self.ports_frame = ttk.Frame(self.notebook, style='Audit.TFrame', padding=5)
        self.notebook.add(self.ports_frame, text="Detailed Open Ports")
        self._create_ports_textbox(self.ports_frame)
        
        # --- NEW TAB CREATION ---
        self.alerts_frame = ttk.Frame(self.notebook, style='Audit.TFrame', padding=5)
        self.notebook.add(self.alerts_frame, text="Critical Alerts & Links")
        self._create_alerts_list(self.alerts_frame)
        # --- END NEW TAB CREATION ---

        self.status_var = tk.StringVar(value="Ready to run audit.")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, style='Audit.TLabel', anchor='w')
        status_label.pack(fill='x', pady=(5, 0))

    def _create_general_treeview(self, parent):
        grid_frame = ttk.Frame(parent, style='Audit.TFrame')
        grid_frame.pack(fill='both', expand=True)
        
        columns = ("Name", "Status", "Severity", "Message", "Remediation")
        self.tree = ttk.Treeview(grid_frame, columns=columns, show='headings', height=10)
        self.tree.pack(fill='x', side='top', pady=(0, 5))

        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Name": self.tree.column(col, width=200, anchor='w')
            elif col == "Status": self.tree.column(col, width=80, anchor='center')
            elif col == "Severity": self.tree.column(col, width=80, anchor='center')
            elif col == "Message": self.tree.column(col, width=250, anchor='w')
            elif col == "Remediation": self.tree.column(col, width=250, anchor='w')

        self.tree.tag_configure('FAIL', background='#4d1515', foreground='#ff8888')
        self.tree.tag_configure('WARN', background='#4d4d15', foreground='#ffff88')
        self.tree.tag_configure('PASS', background='#154d15', foreground='#88ff88')
        self.tree.tag_configure('UNKNOWN', background='#4d4d15', foreground='#cccccc')
        self.tree.tag_configure('ERROR', background='#4d1515', foreground='#ff8888')
        
        self.tree.bind('<<TreeviewSelect>>', self.display_general_details)
        
        detail_label = ttk.Label(grid_frame, text="Selected Item Details", style='Header.TLabel')
        detail_label.pack(fill='x', pady=(5, 2))
        
        self.detail_text = scrolledtext.ScrolledText(grid_frame, wrap='word', height=8, bg='#2d2d2d', fg='#ffffff', borderwidth=0, relief='flat')
        self.detail_text.pack(fill='both', expand=True)
        self.detail_text.config(state='disabled')
        
        for tag_name, config in self.text_tag_config:
            self.detail_text.tag_config(tag_name, **config)

    def display_general_details(self, event):
        self.detail_text.config(state='normal')
        self.detail_text.delete('1.0', tk.END)

        selected_item = self.tree.selection()
        if not selected_item:
            self.detail_text.config(state='disabled')
            return

        item_index = self.tree.index(selected_item[0])
        if item_index < len(self.full_audit_results):
            result = self.full_audit_results[item_index]
            self.detail_text.insert(tk.END, "Message:\n", 'header')
            self.detail_text.insert(tk.END, f"{result['message']}\n\n", 'message')
            self.detail_text.insert(tk.END, "Remediation:\n", 'header')
            self.detail_text.insert(tk.END, f"{result['remediation']}\n", 'remedy')

        self.detail_text.config(state='disabled')

    def _create_ports_textbox(self, parent):
        self.ports_text = scrolledtext.ScrolledText(parent, wrap='word', height=10, bg='#2d2d2d', fg='#ffffff', borderwidth=0, relief='flat')
        self.ports_text.pack(fill='both', expand=True)
        self.ports_text.config(state='disabled')
        
        self.ports_text.tag_config('public', foreground='#ef4444', font=('Courier New', 9, 'bold'))
        self.ports_text.tag_config('local', foreground='#10b981', font=('Courier New', 9, 'bold'))
        self.ports_text.tag_config('warn_public', foreground='#f59e0b', font=('Courier New', 9, 'bold')) # New warning color for LAN exposed
        self.ports_text.tag_config('service', foreground='#3b82f6', font=('Courier New', 9, 'bold'))
        self.ports_text.tag_config('remedy', foreground='#f59e0b', font=('Inter', 9))
    
    # --- NEW ALERTS WIDGET ---
    def _create_alerts_list(self, parent):
        self.alerts_text = scrolledtext.ScrolledText(parent, wrap='word', height=10, bg='#2d2d2d', fg='#ffffff', borderwidth=0, relief='flat')
        self.alerts_text.pack(fill='both', expand=True)
        self.alerts_text.config(state='disabled')
        
        self.alerts_text.tag_config('critical', foreground='#ef4444', font=('Inter', 11, 'bold'))
        self.alerts_text.tag_config('section_header', foreground='#7fffd4', font=('Inter', 12, 'bold'))
        self.alerts_text.tag_config('link', foreground='#3b82f6', font=('Inter', 9, 'underline'))
        self.alerts_text.tag_config('details', foreground='#ffffff', font=('Inter', 9))
    # --- END NEW ALERTS WIDGET ---

    def run_audit_async(self):
        self.run_button.config(state=tk.DISABLED, text="Scanning...")
        self.export_button.config(state='disabled')
        self.status_var.set("Audit running...")
        self.clear_results()
        self.after(100, self._run_audit_logic)

    def _run_audit_logic(self):
        # UNPACK CISA_FINDINGS
        results, port_findings, cisa_findings = run_full_system_audit() 
        self.full_audit_results = results
        self.port_findings = port_findings
        self.cisa_findings = cisa_findings # Store CISA findings
        self.display_general_results(results)
        self.display_port_results(port_findings)
        
        # Pass CISA findings to the display function
        self.display_critical_alerts(results, cisa_findings)

        self.run_button.config(state=tk.NORMAL, text="Run System Audit")
        self.export_button.config(state='normal')
        if results and results[0]['status'] == "FAIL" and results[0]['name'] == "Privilege Check":
            self.status_var.set("SCAN FAILED: Elevated privileges required.")
        else:
            # Calculate overall severity
            valid_results = [r['severity'] for r in results if r['status'] not in ["ERROR", "UNKNOWN", "WARN"]]
            overall_score = sum(valid_results) / len(valid_results) if valid_results else 0
            self.status_var.set(f"Audit completed. Average severity: {overall_score:.1f}/10. {len(port_findings)} ports found.")
        self.notebook.select(0)

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail_text.config(state='normal')
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.config(state='disabled')
        self.full_audit_results = []
        self.port_findings = []
        self.cisa_findings = [] # Clear CISA findings
        self.ports_text.config(state='normal')
        self.ports_text.delete('1.0', tk.END)
        self.ports_text.config(state='disabled')
        
        # Clear new alerts tab
        self.alerts_text.config(state='normal')
        self.alerts_text.delete('1.0', tk.END)
        self.alerts_text.config(state='disabled')

    def display_general_results(self, results):
        for result in results:
            message_snippet = (result['message'][:50] + '...') if len(result['message']) > 50 else result['message']
            remediation_snippet = (result['remediation'][:50] + '...') if len(result['remediation']) > 50 else result['remediation']
            self.tree.insert('', tk.END, values=(
                result['name'],
                result['status'],
                f"{result['severity']}/10",
                message_snippet,
                remediation_snippet
            ), tags=(result['status'],))

    def display_port_results(self, port_findings):
        self.ports_text.config(state='normal')
        self.ports_text.delete('1.0', tk.END)
        
        # New Investigation Instructions Block
        self.ports_text.insert(tk.END, "--- Manual Investigation Tool ---\n", 'header')
        self.ports_text.insert(tk.END, "To identify the exact executable responsible for a port, use the following command in an **Elevated Command Prompt (Run as Admin)**. This tool provides PID, service name, and the EXE name (e.g., GlideXService.exe).\n", 'message')
        self.ports_text.insert(tk.END, "Command: netstat -aonb\n\n", 'remedy')
        
        self.ports_text.insert(tk.END, "--- Detailed Open Port Analysis ---\n\n", 'header')
        
        if not port_findings:
            self.ports_text.insert(tk.END, "No listening ports found.\n")
        for f in port_findings:
            # Use the new classification for display
            ip_status = f.get('ip_classification', "UNKNOWN SCOPE")
            
            # Use the new (PID only) placeholder for the process name
            line1 = f"[{ip_status}] {f['ip']}:{f['port']} -> PID {f['pid']} (Process Name: {f['process_name']})\n"
            
            # Change tagging based on new classification
            tag = 'public'
            if ip_status == "LOCAL LAN EXPOSED":
                tag = 'warn_public' # Use new tag definition for exposed private IPs
            elif ip_status == "LOCAL ONLY":
                tag = 'local'
            
            self.ports_text.insert(tk.END, line1, tag)
            self.ports_text.insert(tk.END, f"Service: {f['service_name']}\n", 'service')
            if 'port_remediation' in f:
                self.ports_text.insert(tk.END, f"Action: {f['port_remediation']}\n\n", 'remedy')
            else:
                self.ports_text.insert(tk.END, "\n")
        self.ports_text.config(state='disabled')

    # --- NEW DISPLAY FUNCTION ---
    def display_critical_alerts(self, results, cisa_findings):
        self.alerts_text.config(state='normal')
        self.alerts_text.delete('1.0', tk.END)
        
        critical_findings = [r for r in results if r['severity'] >= 8 or r['status'] == 'ERROR']
        
        # --- LOCAL SYSTEM FINDINGS ---
        self.alerts_text.insert(tk.END, "--- Local System Critical Failures ---\n\n", 'header')
        
        if not critical_findings:
            self.alerts_text.insert(tk.END, "No critical (Severity 8-10 or ERROR) issues found on this system.\n\n", 'details')
        else:
            self.alerts_text.insert(tk.END, f"CRITICAL SECURITY ALERT: {len(critical_findings)} HIGH-SEVERITY ISSUES FOUND\n\n", 'critical')
            
            for i, result in enumerate(critical_findings, 1):
                self.alerts_text.insert(tk.END, f"[{i}. {result['status']}] {result['name']} (Severity {result['severity']}/10)\n", 'section_header')
                self.alerts_text.insert(tk.END, f"Issue: {result['message']}\n", 'details')
                self.alerts_text.insert(tk.END, f"Action: {result['remediation']}\n\n", 'remedy')

        # --- EXTERNAL CISA/THREAT FINDINGS ---
        self.alerts_text.insert(tk.END, "--- External Threat Intelligence (CISA/NVD) ---\n\n", 'header')
        
        # Check if the fetch was skipped due to local execution
        if cisa_findings:
            self.alerts_text.insert(tk.END, f"Recent vulnerabilities from trusted sources (CISA/NVD/US-CERT):\n\n", 'details')
            for i, item in enumerate(cisa_findings, 1):
                self.alerts_text.insert(tk.END, f"[{i}. THREAT] {item['title']}\n", 'critical')
                self.alerts_text.insert(tk.END, f"Summary: {item['snippet']}\n", 'details')
                self.alerts_text.insert(tk.END, f"URL: ", 'details')
                self.alerts_text.insert(tk.END, f"{item['url']}\n\n", 'link')
        else:
            self.alerts_text.insert(tk.END, "External threat intelligence feature requires this application to be run in an integrated environment with internet access tools.\n", 'details')
            self.alerts_text.insert(tk.END, "Please visit the official sites manually: CISA KEV, US-CERT Alerts, and NIST NVD for the latest vulnerabilities.\n\n", 'remedy')

        # --- REMEDIATION RESOURCES (Original Static Links) ---
        os_links = {
            "Windows": [
                ("Microsoft Security Guidance Center", "https://docs.microsoft.com/en-us/windows/security/"),
                ("BitLocker Drive Encryption Management", "https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-management"),
                ("Windows Firewall with Advanced Security", "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/windows-firewall-with-advanced-security")
            ],
            "Darwin": [
                ("macOS Security Guide (Apple)", "https://support.apple.com/guide/security/welcome/web"),
                ("macOS Firewall & Network Settings", "https://support.apple.com/guide/mac-help/change-firewall-settings-mchlp2829/mac"),
                ("FileVault Encryption Status", "https://support.apple.com/en-us/HT204837")
            ],
            "Linux": [
                ("CIS Linux Benchmarks", "https://www.cisecurity.org/benchmark/centos"), 
                ("Linux Kernel Security & Hardening", "https://www.kernel.org/doc/html/latest/security/index.html"),
                ("UFW Firewall Guide", "https://help.ubuntu.com/community/UFW")
            ]
        }
        
        os_key = self.current_os
        self.alerts_text.insert(tk.END, "--- Static Remediation Resources ---\n", 'header')
        self.alerts_text.insert(tk.END, f"Official guidance specific to your **{os_key}** system:\n", 'details')
        
        for name, url in os_links.get(os_key, []):
            self.alerts_text.insert(tk.END, f"  - {name}: ", 'details')
            self.alerts_text.insert(tk.END, f"{url}\n", 'link')
        
        self.alerts_text.insert(tk.END, "\n", 'details')
        self.alerts_text.config(state='disabled')
    # --- END NEW DISPLAY FUNCTION ---

    def export_results(self):
        if not self.full_audit_results:
            messagebox.showwarning("No Results", "Run the audit first.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if file_path:
            export_data = {
                "audit_results": self.full_audit_results,
                "port_findings": self.port_findings,
                "cisa_findings": self.cisa_findings,
                "timestamp": datetime.now().isoformat(),
                "os": self.current_os
            }
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=4)
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")

if __name__ == "__main__":
    app = AuditApp()
    app.mainloop()

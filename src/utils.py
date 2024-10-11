# utils.py

import subprocess
import winreg
import os
import ctypes
import sys

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Re-run the script with administrative privileges."""
    script = sys.argv[0]
    params = ' '.join([script] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

def set_min_password_length(length):
    """Set minimum password length."""
    subprocess.run(["net", "accounts", f"/minpwlen:{length}"], check=True)

def set_max_password_age(days):
    """Set maximum password age."""
    subprocess.run(["net", "accounts", f"/maxpwage:{days}"], check=True)

def enable_windows_firewall():
    """Enable Windows Firewall for all profiles."""
    subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], check=True)

def set_uac_to_always_notify():
    """Set User Account Control to 'Always notify'."""
    reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 2)
        winreg.SetValueEx(key, "ConsentPromptBehaviorUser", 0, winreg.REG_DWORD, 1)

def turn_off_autoplay():
    """Disable AutoPlay on all drives."""
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")
    ]
    value = 255  # Disable AutoPlay on all drives
    for hive, path in reg_paths:
        with winreg.CreateKey(hive, path) as key:
            winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, value)

def enable_audit_everything():
    """Enable auditing for all categories."""
    subprocess.run(["auditpol", "/set", "/category:*", "/success:enable", "/failure:enable"], check=True)

def disable_file_sharing():
    """Disable file sharing by stopping and disabling the Server service."""
    subprocess.run(["sc", "stop", "LanmanServer"], check=True)
    subprocess.run(["sc", "config", "LanmanServer", "start=", "disabled"], check=True)

def start_windows_updates():
    """Start Windows Update service and set it to automatic."""
    subprocess.run(["sc", "config", "wuauserv", "start=", "auto"], check=True)
    subprocess.run(["sc", "start", "wuauserv"], check=True)

def enable_real_time_protection():
    """Enable Windows Defender real-time protection."""
    reg_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
        winreg.SetValueEx(key, "DisableRealtimeMonitoring", 0, winreg.REG_DWORD, 0)

def disable_let_everyone_permissions_apply_to_anonymous_users():
    """Disable 'Let Everyone permissions apply to anonymous users'."""
    reg_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "EveryoneIncludesAnonymous", 0, winreg.REG_DWORD, 0)

def disable_insecure_guest_logons():
    """Disable insecure guest logons."""
    reg_path = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
        winreg.SetValueEx(key, "AllowInsecureGuestAuth", 0, winreg.REG_DWORD, 0)

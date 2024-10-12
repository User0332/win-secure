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

def set_registry_value(hive, path, name, value_type, value):
    """Set a registry value."""
    with winreg.CreateKey(hive, path) as key:
        winreg.SetValueEx(key, name, 0, value_type, value)

def get_registry_value(hive, path, name):
    """Get a registry value."""
    with winreg.OpenKey(hive, path) as key:
        value, regtype = winreg.QueryValueEx(key, name)
    return value

# Password Policy Functions

def set_password_policy():
    """Set various password policies."""
    print("Setting password policies...")

    # Enforce password history: 24 passwords remembered
    subprocess.run(['net', 'accounts', '/uniquepw:24'], check=True)

    # Maximum password age: 30 days
    subprocess.run(['net', 'accounts', '/maxpwage:30'], check=True)

    # Minimum password age: 10 days
    subprocess.run(['net', 'accounts', '/minpwage:10'], check=True)

    # Minimum password length: 10 characters
    subprocess.run(['net', 'accounts', '/minpwlen:10'], check=True)

    # Password must meet complexity requirements: Enabled
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "PasswordComplexity",
        winreg.REG_DWORD,
        1
    )

    # Store passwords using reversible encryption: Disabled
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "ClearTextPassword",
        winreg.REG_DWORD,
        0
    )

def set_account_lockout_policy():
    """Set account lockout policies."""
    print("Setting account lockout policies...")

    # Account lockout threshold: 5 invalid logon attempts
    subprocess.run(['net', 'accounts', '/lockoutthreshold:5'], check=True)

    # Account lockout duration: 30 minutes
    subprocess.run(['net', 'accounts', '/lockoutduration:30'], check=True)

    # Reset account lockout counter after: 30 minutes
    subprocess.run(['net', 'accounts', '/lockoutwindow:30'], check=True)

def enable_audit_policy():
    """Enable auditing for all policies to success and failure."""
    print("Enabling audit policies...")
    subprocess.run(["auditpol", "/set", "/category:*", "/success:enable", "/failure:enable"], check=True)

def disable_guest_account():
    """Disable the Guest account."""
    print("Disabling Guest account...")
    subprocess.run(['net', 'user', 'Guest', '/active:no'], check=True)

def set_security_options():
    """Set various security options."""
    print("Setting security options...")

    # Interactive logon: Do not require CTRL+ALT+DEL: Disabled (i.e., require CTRL+ALT+DEL)
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD",
        winreg.REG_DWORD,
        0
    )

    # Enable "Accounts: Limit local account use of blank passwords to console logon only"
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "LimitBlankPasswordUse",
        winreg.REG_DWORD,
        1
    )

    # Interactive logon: Don't display last signed-in: Enabled
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DontDisplayLastUserName",
        winreg.REG_DWORD,
        1
    )

def disable_autoplay():
    """Disable AutoPlay on all drives."""
    print("Disabling AutoPlay...")
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")
    ]
    value = 255  # Disable AutoPlay on all drives
    for hive, path in reg_paths:
        with winreg.CreateKey(hive, path) as key:
            winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, value)

def disable_developer_mode():
    """Disable Developer Mode."""
    print("Disabling Developer Mode...")
    reg_path = r"SOFTWARE\Policies\Microsoft\Windows\AppModelUnlock"
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        reg_path,
        "AllowDevelopmentWithoutDevLicense",
        winreg.REG_DWORD,
        0
    )
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        reg_path,
        "AllowAllTrustedApps",
        winreg.REG_DWORD,
        0
    )

def disable_remote_access():
    """Disable Remote Access and Remote Assistance."""
    print("Disabling Remote Access...")
    # Disable Remote Desktop
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        winreg.REG_DWORD,
        1
    )

    # Disable Remote Assistance
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
        "fAllowToGetHelp",
        winreg.REG_DWORD,
        0
    )

def update_windows():
    """Start Windows Update service and check for updates."""
    print("Updating Windows...")
    # Start Windows Update service
    subprocess.run(["sc", "config", "wuauserv", "start=", "auto"], check=True)
    subprocess.run(["sc", "start", "wuauserv"], check=True)

    # Initiate Windows Update (command line methods are complex and may require additional tools)
    # For simplicity, we can prompt the user to check for updates manually
    print("Please check for Windows Updates manually by going to Settings > Update & Security > Windows Update.")

def enable_firewall():
    """Enable Windows Firewall."""
    print("Enabling Windows Firewall...")
    subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], check=True)

def set_ctrl_alt_del_required():
    """Ensure CTRL+ALT+DEL is required for login."""
    print("Ensuring CTRL+ALT+DEL is required for login...")
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "DisableCAD",
        winreg.REG_DWORD,
        0
    )

def set_time_config():
    """Configure system time settings."""
    print("Configuring system time settings...")
    # Sync time with an NTP server
    subprocess.run(["w32tm", "/config", "/syncfromflags:manual", "/manualpeerlist:pool.ntp.org"], check=True)
    subprocess.run(["w32tm", "/config", "/update"], check=True)
    subprocess.run(["w32tm", "/resync"], check=True)

def manage_users():
    """Manage user accounts."""
    print("Managing user accounts...")
    # List all user accounts
    result = subprocess.run(["net", "user"], capture_output=True, text=True)
    users = []
    for line in result.stdout.splitlines():
        if "User accounts for" in line or "-------" in line or "The command completed successfully" in line:
            continue
        users.extend(line.strip().split())

    # Remove unwanted users
    for user in users:
        if user.lower() not in ['administrator', 'guest']:
            print(f"Removing user account: {user}")
            subprocess.run(["net", "user", user, "/delete"], check=True)

def remove_unused_services():
    """Remove or disable unused services."""
    print("Disabling unnecessary services...")
    services_to_disable = [
        'RemoteRegistry',
        'Telnet',
        'SNMP',
        'FTP'
    ]
    for service in services_to_disable:
        subprocess.run(["sc", "config", service, "start=", "disabled"], check=True)
        subprocess.run(["sc", "stop", service], check=False)

def install_security_updates():
    """Install security updates."""
    print("Installing security updates...")
    # This is complex to automate; suggest manual update
    print("Please ensure all security updates are installed via Windows Update.")

def enable_bitlocker():
    """Enable BitLocker Drive Encryption."""
    print("Enabling BitLocker Drive Encryption...")
    # Requires TPM and user interaction; prompt user
    print("Please enable BitLocker manually via Control Panel > System and Security > BitLocker Drive Encryption.")

def configure_firewall_rules():
    """Configure additional firewall rules."""
    print("Configuring additional firewall rules...")
    # Example: Block inbound connections except those required
    subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"], check=True)

def set_ntfs_permissions():
    """Set NTFS permissions on critical folders."""
    print("Setting NTFS permissions on critical folders...")
    folders = [r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)"]
    for folder in folders:
        subprocess.run(["icacls", folder, "/inheritance:r"], check=True)
        subprocess.run(["icacls", folder, "/grant", "Administrators:(OI)(CI)F"], check=True)
        subprocess.run(["icacls", folder, "/grant", "SYSTEM:(OI)(CI)F"], check=True)
        subprocess.run(["icacls", folder, "/remove", "Users"], check=True)

def disable_unused_network_protocols():
    """Disable unused network protocols."""
    print("Disabling unused network protocols...")
    # This requires manipulation of network adapter settings
    print("Please disable unused network protocols manually via Network Adapter properties.")

def configure_account_policies():
    """Configure additional account policies."""
    print("Configuring additional account policies...")
    # Additional policies can be set via registry or local security policy
    # For example, disable LM hash storage
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "NoLMHash",
        winreg.REG_DWORD,
        1
    )

def disable_anonymous_sid_enumeration():
    """Disable anonymous SID/Name translation."""
    print("Disabling anonymous SID/Name translation...")
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "RestrictAnonymousSAM",
        winreg.REG_DWORD,
        1
    )

def disable_null_session_pipes_shares():
    """Disable null session pipes and shares."""
    print("Disabling null session pipes and shares...")
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "NullSessionPipes",
        winreg.REG_MULTI_SZ,
        []
    )
    set_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "NullSessionShares",
        winreg.REG_MULTI_SZ,
        []
    )

# Additional helper functions can be added here
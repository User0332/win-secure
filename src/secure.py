# secure.py

import sys
import utils

def main():
    if not utils.is_admin():
        print("Script is not running with administrative privileges. Trying to relaunch as admin...")
        utils.run_as_admin()
        sys.exit()

    try:
        # Password and Account Policies
        utils.set_password_policy()
        utils.set_account_lockout_policy()

        # Audit Policies
        utils.enable_audit_policy()

        # Security Options
        utils.disable_guest_account()
        utils.set_security_options()

        # Disable AutoPlay and Developer Mode
        utils.disable_autoplay()
        utils.disable_developer_mode()

        # Disable Remote Access
        utils.disable_remote_access()

        # Update Windows
        utils.update_windows()

        # Enable Firewall
        utils.enable_firewall()

        # Ensure CTRL+ALT+DEL is required
        utils.set_ctrl_alt_del_required()

        # Configure Time Settings
        utils.set_time_config()

        # Manage Users
        utils.manage_users()

        # Remove Unused Services
        utils.remove_unused_services()

        # Install Security Updates
        utils.install_security_updates()

        # Enable BitLocker
        utils.enable_bitlocker()

        # Configure Firewall Rules
        utils.configure_firewall_rules()

        # Set NTFS Permissions
        utils.set_ntfs_permissions()

        # Disable Unused Network Protocols
        utils.disable_unused_network_protocols()

        # Configure Account Policies
        utils.configure_account_policies()

        # Disable Anonymous SID Enumeration
        utils.disable_anonymous_sid_enumeration()

        # Disable Null Session Pipes and Shares
        utils.disable_null_session_pipes_shares()

        print("\nSystem has been secured according to the specified settings.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

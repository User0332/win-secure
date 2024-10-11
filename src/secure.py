# secure.py

import sys
import utils

def main():
    if not utils.is_admin():
        print("Script is not running with administrative privileges. Trying to relaunch as admin...")
        utils.run_as_admin()
        sys.exit()

    try:
        print("Setting minimum password length to 7...")
        utils.set_min_password_length(7)

        print("Setting maximum password age to 30...")
        utils.set_max_password_age(30)

        print("Enabling Windows Firewall...")
        utils.enable_windows_firewall()

        print("Setting User Account Control to 'Always notify'...")
        utils.set_uac_to_always_notify()

        print("Turning off AutoPlay...")
        utils.turn_off_autoplay()

        print("Enabling auditing for all events...")
        utils.enable_audit_everything()

        print("Disabling file sharing...")
        utils.disable_file_sharing()

        print("Starting Windows Updates...")
        utils.start_windows_updates()

        print("Enabling real-time protection...")
        utils.enable_real_time_protection()

        print("Disabling 'Let Everyone permissions apply to anonymous users'...")
        utils.disable_let_everyone_permissions_apply_to_anonymous_users()

        print("Disabling insecure guest logons...")
        utils.disable_insecure_guest_logons()

        print("\nSystem has been secured according to the specified settings.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;



#pragma warning disable CA1416 // Validate platform compatibility


namespace WinSecure.CSharp;
public class UserConfig
{
	public static void Configure()
	{
		ApplySecurityPolicies();
		DisableAutoPlay();
		DisableDeveloperMode();
		DisableRemoteAccess();
		UpdateWindows();
		UpdateChrome();
		HardenChrome();
		ManageApplications();
		ConfigureUserRightsAssignments();
		ConfigureSecurityOptions();
		ConfigureUserAccounts();

	}

	private static void ApplySecurityPolicies()
	{
		Console.WriteLine("Applying security policies...");

		string tempInfPath = Path.Combine(Path.GetTempPath(), "security.inf");

		string infContent = @"
[Unicode]
Unicode=yes
[System Access]
; Password policies
MinimumPasswordAge = 10
MaximumPasswordAge = 30
MinimumPasswordLength = 10
PasswordComplexity = 1
PasswordHistorySize = 24
ClearTextPassword = 0

; Account lockout policies
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3

[Registry Values]
; Interactive logon: Do not require CTRL+ALT+DEL
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
; Don't display last signed in user
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
; Limit local use of blank passwords to console logon only
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
";

		File.WriteAllText(tempInfPath, infContent);

		// Apply the security template using secedit.exe
		Process process = new Process();
		process.StartInfo.FileName = "secedit.exe";
		process.StartInfo.Arguments = $"/configure /db secedit.sdb /cfg \"{tempInfPath}\" /overwrite /quiet";
		process.StartInfo.UseShellExecute = false;
		process.StartInfo.CreateNoWindow = true;
		process.Start();

		process.WaitForExit();

		if (process.ExitCode != 0)
		{
			Console.WriteLine("Error applying security policies.");
		}
		else
		{
			Console.WriteLine("Security policies applied successfully.");
		}

		// Clean up temporary INF file
		File.Delete(tempInfPath);
	}

	private static void DisableAutoPlay()
	{
		Console.WriteLine("Disabling AutoPlay...");

		try
		{
			// Disable AutoPlay for all drives
			using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"))
			{
				key.SetValue("DisableAutoplay", 1, RegistryValueKind.DWord);
			}

			using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"))
			{
				key.SetValue("NoDriveTypeAutoRun", 255, RegistryValueKind.DWord);
			}

			Console.WriteLine("AutoPlay disabled successfully.");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error disabling AutoPlay: {ex.Message}");
		}
	}

	private static void DisableDeveloperMode()
	{
		Console.WriteLine("Disabling Developer Mode...");

		try
		{
			using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"))
			{
				key.SetValue("AllowDevelopmentWithoutDevLicense", 0, RegistryValueKind.DWord);
			}

			Console.WriteLine("Developer Mode disabled successfully.");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error disabling Developer Mode: {ex.Message}");
		}
	}

	private static void DisableRemoteAccess()
	{
		Console.WriteLine("Disabling Remote Access...");

		try
		{
			// Disable Remote Desktop
			using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server"))
			{
				key.SetValue("fDenyTSConnections", 1, RegistryValueKind.DWord);
			}

			// Disable Remote Assistance
			using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Remote Assistance"))
			{
				key.SetValue("fAllowToGetHelp", 0, RegistryValueKind.DWord);
			}

			Console.WriteLine("Remote Access disabled successfully.");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error disabling Remote Access: {ex.Message}");
		}
	}

	private static void UpdateWindows()
	{
		Console.WriteLine("Initiating Windows Update...");

		try
		{
			Process process = new Process();
			process.StartInfo.FileName = "UsoClient.exe";
			process.StartInfo.Arguments = "StartScan";
			process.StartInfo.UseShellExecute = false;
			process.StartInfo.CreateNoWindow = true;
			process.Start();

			process.WaitForExit();

			Console.WriteLine("Windows Update initiated successfully.");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error initiating Windows Update: {ex.Message}");
		}
	}

	private static void UpdateChrome()
	{
		Console.WriteLine("Initiating Google Chrome Update...");

		try
		{
			string googleUpdatePath = Path.Combine(
				Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
				"Google\\Update\\GoogleUpdate.exe"
			);

			if (!File.Exists(googleUpdatePath))
			{
				googleUpdatePath = Path.Combine(
					Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
					"Google\\Update\\GoogleUpdate.exe"
				);
			}

			if (File.Exists(googleUpdatePath))
			{
				Process process = new Process();
				process.StartInfo.FileName = googleUpdatePath;
				process.StartInfo.Arguments = "/ua /installsource scheduler";
				process.StartInfo.UseShellExecute = false;
				process.StartInfo.CreateNoWindow = true;
				process.Start();

				process.WaitForExit();

				Console.WriteLine("Google Chrome update initiated successfully.");
			}
			else
			{
				Console.WriteLine("Google Update executable not found. Chrome may not be installed or updates are managed differently.");
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error initiating Google Chrome update: {ex.Message}");
		}
	}

	private static void HardenChrome()

	{
		Console.WriteLine("Applying hardening settings to Google Chrome...");

		try
		{
			// Access the registry key for Chrome policies
			RegistryKey policyKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Google\Chrome", true);

			if (policyKey == null)
			{
				// Fallback to CurrentUser if LocalMachine is not accessible
				policyKey = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Policies\Google\Chrome", true);
			}

			if (policyKey != null)
			{
				// Disable password manager
				policyKey.SetValue("PasswordManagerEnabled", 0, RegistryValueKind.DWord);

				// Disable Autofill
				policyKey.SetValue("AutofillEnabled", 0, RegistryValueKind.DWord);

				// Enable Safe Browsing
				policyKey.SetValue("SafeBrowsingEnabled", 1, RegistryValueKind.DWord);

				// Enable Enhanced Protection
				policyKey.SetValue("SafeBrowsingProtectionLevel", 2, RegistryValueKind.DWord);

				// Disable Incognito Mode
				policyKey.SetValue("IncognitoModeAvailability", 1, RegistryValueKind.DWord);

				// Force Safe Search
				policyKey.SetValue("ForceGoogleSafeSearch", 1, RegistryValueKind.DWord);

				// Disable Developer Tools
				policyKey.SetValue("DeveloperToolsDisabled", 1, RegistryValueKind.DWord);

				// Enforce updates
				RegistryKey updatePolicyKey = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Google\Update", true);
				if (updatePolicyKey == null)
				{
					updatePolicyKey = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Policies\Google\Update", true);
				}

				if (updatePolicyKey != null)
				{
					// Set update policies
					updatePolicyKey.SetValue("AutoUpdateCheckPeriodMinutes", 43200, RegistryValueKind.DWord); // Check every 30 days
					updatePolicyKey.SetValue("UpdateDefault", 1, RegistryValueKind.DWord); // Always allow updates
					updatePolicyKey.SetValue("DisableAutoUpdateChecksCheckboxValue", 0, RegistryValueKind.DWord);

					updatePolicyKey.Close();
				}

				policyKey.Close();

				Console.WriteLine("Google Chrome hardening settings applied successfully.");
			}
			else
			{
				Console.WriteLine("Failed to access registry keys for Google Chrome policies.");
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error applying hardening settings to Google Chrome: {ex.Message}");
		}
	}

        private static void ManageApplications()
        {
            Console.WriteLine("Starting application management...");

            RemoveUnwantedApplications();
            UpdateUtilities();

            Console.WriteLine("Application management completed.");
        }

        private static void RemoveUnwantedApplications()
        {
            Console.WriteLine("Removing unwanted applications...");

            string[] unwantedApps = new string[]
            {
                "Python",
                "CCleaner64",
                "CCleaner",
                "Wireshark",
                "Npcap",
                "Pong",
                "PCCleaner",
                "NetStumbler",
                "TeamViewer",
                "nmap",
                "Burp Suite Community Edition",
                "Jellyfin Media Player",
                "AnyDesk",
                "Ophcrack"
            };

            foreach (string appName in unwantedApps)
            {
                Console.WriteLine($"Attempting to uninstall {appName}...");
                bool appFound = false;

                // Search in both 32-bit and 64-bit registry views
                appFound |= UninstallApplication(appName, RegistryHive.LocalMachine, RegistryView.Registry64);
                appFound |= UninstallApplication(appName, RegistryHive.LocalMachine, RegistryView.Registry32);
                appFound |= UninstallApplication(appName, RegistryHive.CurrentUser, RegistryView.Registry64);
                appFound |= UninstallApplication(appName, RegistryHive.CurrentUser, RegistryView.Registry32);

                if (!appFound)
                {
                    Console.WriteLine($"{appName} wasn't found.");
                }
            }

            Console.WriteLine("Unwanted applications removal completed.");
        }

        private static void UpdateUtilities()
        {
            Console.WriteLine("Updating utilities...");

            UpdateNotepadPlusPlus();
            Update7Zip();

            Console.WriteLine("Utilities update completed.");
        }

        private static void UpdateNotepadPlusPlus()
        {
            Console.WriteLine("Updating Notepad++...");

            try
            {
                string? notepadPlusPlusPath = GetInstalledApplicationPath("Notepad++");
                if (string.IsNullOrEmpty(notepadPlusPlusPath))
                {
                    Console.WriteLine("Notepad++ is not installed on this system.");
                    return;
                }

                string downloadUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest/download/npp.8.5.7.Installer.x64.exe"; // Update URL as needed
                string tempInstallerPath = Path.Combine(Path.GetTempPath(), "npp_installer.exe");

                Console.WriteLine("Downloading the latest Notepad++ installer...");
                using (WebClient client = new())
                {
                    client.DownloadFile(downloadUrl, tempInstallerPath);
                }

                Console.WriteLine("Running the Notepad++ installer...");
                Process process = new Process();
                process.StartInfo.FileName = tempInstallerPath;
                process.StartInfo.Arguments = "/S"; // Silent installation
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                Console.WriteLine("Notepad++ updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating Notepad++: {ex.Message}");
            }
        }

        private static void Update7Zip()
        {
            Console.WriteLine("Updating 7-Zip...");

            try
            {
                string? sevenZipPath = GetInstalledApplicationPath("7-Zip");
                if (string.IsNullOrEmpty(sevenZipPath))
                {
                    Console.WriteLine("7-Zip is not installed on this system.");
                    return;
                }

                string downloadUrl = "https://www.7-zip.org/a/7z2301-x64.exe"; // Update URL as needed
                string tempInstallerPath = Path.Combine(Path.GetTempPath(), "7zip_installer.exe");

                Console.WriteLine("Downloading the latest 7-Zip installer...");
                using (WebClient client = new WebClient())
                {
                    client.DownloadFile(downloadUrl, tempInstallerPath);
                }

                Console.WriteLine("Running the 7-Zip installer...");
                Process process = new Process();
                process.StartInfo.FileName = tempInstallerPath;
                process.StartInfo.Arguments = "/S"; // Silent installation
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                Console.WriteLine("7-Zip updated successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating 7-Zip: {ex.Message}");
            }
        }

        private static string? GetInstalledApplicationPath(string appName)
        {
            string displayName;
            string installLocation;

            // Search in both 32-bit and 64-bit registry views
            RegistryView[] views = { RegistryView.Registry64, RegistryView.Registry32 };
            foreach (RegistryView view in views)
            {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using RegistryKey uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstallKey == null)
                continue;

            foreach (string subKeyName in uninstallKey.GetSubKeyNames())
            {
                using RegistryKey subKey = uninstallKey.OpenSubKey(subKeyName);
                displayName = (string)subKey.GetValue("DisplayName");
                installLocation = (string)subKey.GetValue("InstallLocation");

                if (!string.IsNullOrEmpty(displayName) &&
                    displayName.IndexOf(appName, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (!string.IsNullOrEmpty(installLocation))
                    {
                        return installLocation;
                    }
                }
            }
        }

            return null;
        }

        private static bool UninstallApplication(string appName, RegistryHive hive, RegistryView view)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view))
                {
                    using (RegistryKey uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                    {
                        if (uninstallKey == null)
                            return false;

                        foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                        {
                            using (RegistryKey appKey = uninstallKey.OpenSubKey(subKeyName))
                            {
                                string displayName = (string) appKey.GetValue("DisplayName");
                                string uninstallString = (string) appKey.GetValue("UninstallString");

                                if (!string.IsNullOrEmpty(displayName) &&
                                    displayName.IndexOf(appName, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    if (!string.IsNullOrEmpty(uninstallString))
                                    {
                                        Console.WriteLine($"Uninstalling {displayName}...");

                                        // Some uninstall strings may have additional arguments
                                        string arguments = "";
                                        string fileName = uninstallString;

                                        if (uninstallString.StartsWith("\""))
                                        {
                                            int endQuote = uninstallString.IndexOf("\"", 1);
                                            if (endQuote > 0)
                                            {
                                                fileName = uninstallString.Substring(1, endQuote - 1);
                                                arguments = uninstallString.Substring(endQuote + 1).Trim();
                                            }
                                        }
                                        else
                                        {
                                            int firstSpace = uninstallString.IndexOf(" ");
                                            if (firstSpace > 0)
                                            {
                                                fileName = uninstallString.Substring(0, firstSpace);
                                                arguments = uninstallString.Substring(firstSpace + 1).Trim();
                                            }
                                        }

                                        // Add silent/unattended flags if necessary
                                        if (!arguments.Contains("/quiet") && !arguments.Contains("/silent"))
                                        {
                                            arguments += " /quiet /norestart";
                                        }

                                        try
                                        {
                                            Process uninstallProcess = new Process();
                                            uninstallProcess.StartInfo.FileName = fileName;
                                            uninstallProcess.StartInfo.Arguments = arguments;
                                            uninstallProcess.StartInfo.UseShellExecute = false;
                                            uninstallProcess.StartInfo.CreateNoWindow = true;
                                            uninstallProcess.Start();
                                            uninstallProcess.WaitForExit();

                                            Console.WriteLine($"{displayName} uninstalled successfully.");
                                        }
                                        catch (Exception ex)
                                        {
                                            Console.WriteLine($"Error uninstalling {displayName}: {ex.Message}");
                                        }
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accessing registry: {ex.Message}");
            }
            return false;
        }




	private static void ConfigureUserRightsAssignments()
	{
		Console.WriteLine("Configuring User Rights Assignments...");

		bool isDomainController = IsDomainController();

		string infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=""$CHICAGO$""
Revision=1
[Privilege Rights]
";

		// 2.2.1 Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
		infContent += "SeTrustedCredManAccessPrivilege =\n";

		// 2.2.2 / 2.2.3 Ensure 'Access this computer from the network'
		if (isDomainController)
		{
			// DC only
			infContent += "SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11,*S-1-5-9\n"; // Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS
		}
		else
		{
			// Member Server
			infContent += "SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11\n"; // Administrators, Authenticated Users
		}

		// 2.2.4 Ensure 'Act as part of the operating system' is set to 'No One'
		infContent += "SeTcbPrivilege =\n";

		// 2.2.5 Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
		if (isDomainController)
		{
			infContent += "SeMachineAccountPrivilege = *S-1-5-32-544\n"; // Administrators
		}

		// 2.2.6 Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
		infContent += "SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20\n"; // Administrators, LOCAL SERVICE, NETWORK SERVICE

		// 2.2.7 Ensure 'Allow log on locally' is set to 'Administrators'
		infContent += "SeInteractiveLogonRight = *S-1-5-32-544\n"; // Administrators

		// 2.2.8 / 2.2.9 Ensure 'Allow log on through Remote Desktop Services'
		if (isDomainController)
		{
			// DC only
			infContent += "SeRemoteInteractiveLogonRight = *S-1-5-32-544\n"; // Administrators
		}
		else
		{
			// Member Server
			infContent += "SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555\n"; // Administrators, Remote Desktop Users
		}

		// 2.2.10 Ensure 'Back up files and directories' is set to 'Administrators'
		infContent += "SeBackupPrivilege = *S-1-5-32-544\n"; // Administrators

		// 2.2.11 Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
		infContent += "SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19\n"; // Administrators, LOCAL SERVICE

		// 2.2.12 Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
		infContent += "SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19\n"; // Administrators, LOCAL SERVICE

		// 2.2.13 Ensure 'Create a pagefile' is set to 'Administrators'
		infContent += "SeCreatePagefilePrivilege = *S-1-5-32-544\n"; // Administrators

		// 2.2.14 Ensure 'Create a token object' is set to 'No One'
		infContent += "SeCreateTokenPrivilege =\n";

		// 2.2.15 Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
		infContent += "SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6\n"; // Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE

		// 2.2.16 Ensure 'Create permanent shared objects' is set to 'No One'
		infContent += "SeCreatePermanentPrivilege =\n";

		// 2.2.17 / 2.2.18 Ensure 'Create symbolic links'
		if (isDomainController)
		{
			// DC only
			infContent += "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544\n"; // Administrators
		}
		else
		{
			// Member Server
			infContent += "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544,*S-1-5-83-0\n"; // Administrators, NT VIRTUAL MACHINE\Virtual Machines
		}

		// 2.2.19 Ensure 'Debug programs' is set to 'Administrators'
		infContent += "SeDebugPrivilege = *S-1-5-32-544\n"; // Administrators

		// 2.2.20 / 2.2.21 Ensure 'Deny access to this computer from the network'
		if (isDomainController)
		{
			// DC only
			infContent += "SeDenyNetworkLogonRight = *S-1-5-32-546\n"; // Guests
		}
		else
		{
			// Member Server
			infContent += "SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-114\n"; // Guests, Local account and member of Administrators group
		}

		// 2.2.22 Ensure 'Deny log on as a batch job' to include 'Guests'
		infContent += "SeDenyBatchLogonRight = *S-1-5-32-546\n"; // Guests

		// 2.2.23 Ensure 'Deny log on as a service' to include 'Guests'
		infContent += "SeDenyServiceLogonRight = *S-1-5-32-546\n"; // Guests

		// 2.2.24 Ensure 'Deny log on locally' to include 'Guests'
		infContent += "SeDenyInteractiveLogonRight = *S-1-5-32-546\n"; // Guests

		// 2.2.25 / 2.2.26 Ensure 'Deny log on through Remote Desktop Services'
		if (isDomainController)
		{
			// DC only
			infContent += "SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546\n"; // Guests
		}
		else
		{
			// Member Server
			infContent += "SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-113\n"; // Guests, Local account
		}

		// Additional policies can be added here following the same pattern...

		// Write the INF content to a temporary file
		string tempInfPath = Path.Combine(Path.GetTempPath(), "user_rights.inf");

		try
		{
			File.WriteAllText(tempInfPath, infContent);

			// Apply the security template using secedit.exe
			Process process = new Process();
			process.StartInfo.FileName = "secedit.exe";
			process.StartInfo.Arguments = $"/configure /db secedit.sdb /cfg \"{tempInfPath}\" /overwrite /quiet";
			process.StartInfo.UseShellExecute = false;
			process.StartInfo.CreateNoWindow = true;
			process.Start();

			process.WaitForExit();

			if (process.ExitCode != 0)
			{
				Console.WriteLine("Error configuring user rights assignments.");
			}
			else
			{
				Console.WriteLine("User rights assignments configured successfully.");
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine($"Error applying user rights assignments: {ex.Message}");
		}
		finally
		{
			// Clean up temporary INF file
			if (File.Exists(tempInfPath))
			{
				File.Delete(tempInfPath);
			}
		}
	}


        private static void ConfigureSecurityOptions()
        {
            Console.WriteLine("Configuring Security Options...");

            bool isDomainController = IsDomainController();

            string infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=""$CHICAGO$""
Revision=1
[Registry Values]
";

            // Accounts Policies
            // 2.3.1.1 Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
            infContent += @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser = 4,3
";

            // 2.3.1.2 Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
            if (!isDomainController)
            {
                infContent += @"MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse = 4,1
";
            }

            // 2.3.1.3 Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
            infContent += @"MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse = 4,1
";

            // 2.3.1.4 Configure 'Accounts: Rename administrator account' (Automated)
            string newAdminName = "SecuredAdmin"; // Change this to your desired administrator account name
            infContent += $@"MACHINE\SAM\Sam\Domains\Account\Users\Names\{newAdminName} = 1,""{newAdminName}""
";

            // 2.3.1.5 Configure 'Accounts: Rename guest account' (Automated)
            string newGuestName = "SecuredGuest"; // Change this to your desired guest account name
            infContent += $@"MACHINE\SAM\Sam\Domains\Account\Users\Names\{newGuestName} = 1,""{newGuestName}""
";

            // Audit Policies
            // 2.3.2.1 Ensure 'Audit: Force audit policy subcategory settings...' is set to 'Enabled'
            infContent += @"MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy = 4,1
";

            // 2.3.2.2 Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
            infContent += @"MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail = 4,0
";

            // Devices Policies
            // 2.3.4.1 Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
            infContent += @"MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD = 1,""0""
";

            // 2.3.4.2 Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
            infContent += @"MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers = 4,1
";

            // Interactive Logon Policies
            // 2.3.7.1 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
            infContent += @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD = 4,0
";

            // 2.3.7.2 Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'
            infContent += @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName = 4,1
";

            // 2.3.7.3 Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
            int inactivityLimit = 900; // Set to 900 seconds
            infContent += $@"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs = 4,{inactivityLimit}
";

            // User Account Control Policies
            // 2.3.17.1 Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
            infContent += @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken = 4,1
";

            // 2.3.17.2 Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher
            infContent += @"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin = 4,2
";

            // Add additional policies as needed, following the same pattern

            // Write the INF content to a temporary file
            string tempInfPath = Path.Combine(Path.GetTempPath(), "security_options.inf");

            try
            {
                File.WriteAllText(tempInfPath, infContent);

                // Apply the security template using secedit.exe
                Process process = new Process();
                process.StartInfo.FileName = "secedit.exe";
                process.StartInfo.Arguments = $"/configure /db secedit.sdb /cfg \"{tempInfPath}\" /overwrite /quiet";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    Console.WriteLine("Error configuring security options.");
                }
                else
                {
                    Console.WriteLine("Security options configured successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error applying security options: {ex.Message}");
            }
            finally
            {
                // Clean up temporary INF file
                if (File.Exists(tempInfPath))
                {
                    File.Delete(tempInfPath);
                }
            }
        }

        private static bool IsDomainController()
        {
            Console.WriteLine("Checking if the machine is a Domain Controller...");

            try
            {
            using RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions");
            if (key != null)
            {
                string productType = (string)key.GetValue("ProductType");
                if (!string.IsNullOrEmpty(productType) && productType.Equals("LanmanNT", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Machine is a Domain Controller.");
                    return true;
                }
            }
        }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking domain controller status: {ex.Message}");
            }

            Console.WriteLine("Machine is not a Domain Controller.");
            return false;
        }

        private static void ConfigureUserAccounts()
        {
            Console.WriteLine("Configuring user accounts...");

            List<string> adminUsers = new List<string>();
            List<string> standardUsers = new List<string>();

            // Prompt for admin users
            Console.WriteLine("Enter the names of admin users (press Enter without typing a name to finish):");
            while (true)
            {
                Console.Write("Admin user name: ");
                string input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input))
                    break;
                adminUsers.Add(input.Trim());
            }

            // Prompt for standard users
            Console.WriteLine("Enter the names of standard users (press Enter without typing a name to finish):");
            while (true)
            {
                Console.Write("Standard user name: ");
                string input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input))
                    break;
                standardUsers.Add(input.Trim());
            }

            // Get all local users
            List<string> allLocalUsers = new List<string>();
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal userPrincipal = new UserPrincipal(ctx);
                PrincipalSearcher searcher = new PrincipalSearcher(userPrincipal);

                foreach (var result in searcher.FindAll())
                {
                    allLocalUsers.Add(result.SamAccountName);
                }
            }

            // Process admin users
            foreach (string userName in adminUsers)
            {
                if (UserExists(userName))
                {
                    if (IsUserInGroup(userName, "Administrators"))
                    {
                        // User is already an admin
                        continue;
                    }
                    else
                    {
                        Console.WriteLine($"User '{userName}' is a standard user and should be an admin. Do you want to fix this (y/n)?");
                        string response = Console.ReadLine();
                        if (response.Equals("y", StringComparison.OrdinalIgnoreCase))
                        {
                            AddUserToGroup(userName, "Administrators");
                            Console.WriteLine($"User '{userName}' has been added to the Administrators group.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"User '{userName}' does not exist. Do you want to create this user (y/n)?");
                    string response = Console.ReadLine();
                    if (response.Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        CreateLocalUser(userName, true);
                        Console.WriteLine($"Admin user '{userName}' has been created.");
                    }
                }
            }

            // Process standard users
            foreach (string userName in standardUsers)
            {
                if (UserExists(userName))
                {
                    if (!IsUserInGroup(userName, "Administrators"))
                    {
                        // User is already a standard user
                        continue;
                    }
                    else
                    {
                        Console.WriteLine($"User '{userName}' is an admin and should be a standard user. Do you want to fix this (y/n)?");
                        string response = Console.ReadLine();
                        if (response.Equals("y", StringComparison.OrdinalIgnoreCase))
                        {
                            RemoveUserFromGroup(userName, "Administrators");
                            Console.WriteLine($"User '{userName}' has been removed from the Administrators group.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"User '{userName}' does not exist. Do you want to create this user (y/n)?");
                    string response = Console.ReadLine();
                    if (response.Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        CreateLocalUser(userName, false);
                        Console.WriteLine($"Standard user '{userName}' has been created.");
                    }
                }
            }

            // Find users not specified by the administrator
            HashSet<string> specifiedUsers = new HashSet<string>(adminUsers, StringComparer.OrdinalIgnoreCase);
            specifiedUsers.UnionWith(standardUsers);

            foreach (string userName in allLocalUsers)
            {
                if (!specifiedUsers.Contains(userName) && !IsSystemAccount(userName))
                {
                    Console.WriteLine($"User '{userName}' exists but was not specified. Do you want to delete this account (y/n)?");
                    string response = Console.ReadLine();
                    if (response.Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        DeleteLocalUser(userName);
                        Console.WriteLine($"User '{userName}' has been deleted.");
                    }
                }
            }

            Console.WriteLine("User accounts configuration completed.");
        }

        private static bool UserExists(string userName)
        {
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userName);
                return user != null;
            }
        }

        private static bool IsUserInGroup(string userName, string groupName)
        {
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userName);
                GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, groupName);

                if (user != null && group != null)
                {
                    return user.IsMemberOf(group);
                }
                return false;
            }
        }

        private static void AddUserToGroup(string userName, string groupName)
        {
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userName);
                GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, groupName);

                if (user != null && group != null)
                {
                    group.Members.Add(user);
                    group.Save();
                }
            }
        }

        private static void RemoveUserFromGroup(string userName, string groupName)
        {
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userName);
                GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, groupName);

                if (user != null && group != null)
                {
                    group.Members.Remove(user);
                    group.Save();
                }
            }
        }

        private static void CreateLocalUser(string userName, bool isAdmin)
        {
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = new UserPrincipal(ctx);
                user.SetPassword("Password123!"); // You may want to prompt for a password or generate one
                user.DisplayName = userName;
                user.Name = userName;
                user.UserCannotChangePassword = false;
                user.PasswordNeverExpires = false;
                user.Save();

                if (isAdmin)
                {
                    AddUserToGroup(userName, "Administrators");
                }
                else
                {
                    AddUserToGroup(userName, "Users");
                }
            }
        }

        private static void DeleteLocalUser(string userName)
        {
            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userName);
                if (user != null)
                {
                    user.Delete();
                }
            }
        }

        private static bool IsSystemAccount(string userName)
        {
            // List of common system accounts to exclude
            string[] systemAccounts = new string[]
            {
                "Administrator",
                "Guest",
                "DefaultAccount",
                "WDAGUtilityAccount"
            };

            return Array.Exists(systemAccounts, account => account.Equals(userName, StringComparison.OrdinalIgnoreCase));
        }


}
using System.Diagnostics;
using System.Net;
using Microsoft.Win32;
using System.DirectoryServices.AccountManagement;
using System.Collections.Generic;
using System.IO;
using System.Collections.Generic;
using System;
using System.ServiceProcess;




#pragma warning disable CA1416 // Validate platform compatibility


namespace WinSecure.CSharp;
public class UserConfig
{
	public static void Configure()
	{
		DisableAutoPlay();
		DisableDeveloperMode();
		DisableRemoteAccess();
		UpdateWindows();
		UpdateChrome();
		HardenChrome();
		ManageApplications();
		ConfigureUserRightsAssignments();
		ConfigureSecurityOptions();
		//ConfigureUserAccounts();
		ApplySecurityPolicies();
		CleanTemporaryFiles();
		ConfigureFirewallAndNetworkSettings();
        //ManageGroups();
        MiscellaneousConfigurations();
        ConfigureAdvancedFirewallSettings();
        ConfigureAdvancedAuditPolicies();
        TemplateP1();
        TemplateP2();
        DeleteAllAudio();
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

		            // Ensure that passwords for all users can expire
            SetPasswordExpirationForAllUsers();

            // Prompt the administrator to enter a safe password for all users
            Console.WriteLine("Please enter a safe password to set for all users:");
            string password = ReadPassword();

            // Confirm the password
            Console.WriteLine("Please confirm the password:");
            string confirmPassword = ReadPassword();

            if (password != confirmPassword)
            {
                Console.WriteLine("Passwords do not match. Aborting password change.");
                return;
            }

            // Set the password for all users
            SetPasswordForAllUsers(password);

            Console.WriteLine("Security policies applied successfully.");

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

        private static void SetPasswordExpirationForAllUsers()
        {
            Console.WriteLine("Setting password expiration for all users...");

            try
            {
                using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
                {
                    UserPrincipal userPrincipal = new UserPrincipal(ctx);
                    PrincipalSearcher searcher = new PrincipalSearcher(userPrincipal);

                    foreach (var result in searcher.FindAll())
                    {
                    if (result is UserPrincipal user)
                    {
                        // Exclude built-in accounts
                        if (IsSystemAccount(user.SamAccountName))
                            continue;

                        user.PasswordNeverExpires = false;
                        user.Save();
                    }
                }
                }

                Console.WriteLine("Password expiration enabled for all users.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting password expiration: {ex.Message}");
            }
        }

        private static void SetPasswordForAllUsers(string password)
        {
            Console.WriteLine("Setting password for all users...");

            try
            {
                using (PrincipalContext ctx = new(ContextType.Machine))
                {
                    UserPrincipal userPrincipal = new(ctx);
                    PrincipalSearcher searcher = new(userPrincipal);

                    foreach (var result in searcher.FindAll())
                    {
                    if (result is UserPrincipal user)
                    {
                        // Exclude built-in accounts
                        if (IsSystemAccount(user.SamAccountName))
                            continue;

                        user.SetPassword(password);
                        user.Save();
                    }
                }
                }

                Console.WriteLine("Password set for all users.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting passwords: {ex.Message}");
            }
        }

        private static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo info;

            do
            {
                info = Console.ReadKey(true);
                if (info.Key != ConsoleKey.Enter)
                {
                    if (info.Key == ConsoleKey.Backspace)
                    {
                        if (password.Length > 0)
                        {
                            password = password.Remove(password.Length - 1);
                            Console.Write("\b \b");
                        }
                    }
                    else if (!char.IsControl(info.KeyChar))
                    {
                        password += info.KeyChar;
                        Console.Write("*");
                    }
                }
            } while (info.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password;
        }

        private static bool IsSystemAccount(string userName)
        {
            // List of common system accounts to exclude
            string[] systemAccounts = [
                "Administrator",
                "Guest",
                "DefaultAccount",
                "WDAGUtilityAccount",
                "krbtgt" // For domain controllers
			];

            return Array.Exists(systemAccounts, account => account.Equals(userName, StringComparison.OrdinalIgnoreCase));
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
            Console.WriteLine($"Deleting user '{userName}' and archiving their files...");

            try
            {
                // Get the user's profile directory
                string? userProfilePath = GetUserProfilePath(userName);

                // Define the backup directory
                string backupDirectory = Path.Combine(@"C:\DeletedUserBackups", userName + "_" + DateTime.Now.ToString("yyyyMMddHHmmss"));

                // Create the backup directory if it doesn't exist
                Directory.CreateDirectory(backupDirectory);

                // Copy the user's profile directory to the backup location
                if (!string.IsNullOrEmpty(userProfilePath) && Directory.Exists(userProfilePath))
                {
                    Console.WriteLine($"Backing up user profile from '{userProfilePath}' to '{backupDirectory}'...");
                    CopyDirectory(userProfilePath!, backupDirectory);
                    Console.WriteLine("Backup completed.");
                }
                else
                {
                    Console.WriteLine($"User profile directory not found for user '{userName}'. No files were backed up.");
                }

                // Log the backup information
                string logFilePath = @"C:\DeletedUserBackups\DeletedUsersLog.txt";
                string logEntry = $"User '{userName}' deleted on {DateTime.Now}. Backup located at '{backupDirectory}'{Environment.NewLine}";
                File.AppendAllText(logFilePath, logEntry);

                // Delete the user account
                using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
                {
                    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userName);
                    if (user != null)
                    {
                        user.Delete();
                        Console.WriteLine($"User '{userName}' deleted successfully.");
                    }
                    else
                    {
                        Console.WriteLine($"User '{userName}' does not exist.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting user '{userName}': {ex.Message}");
            }
        }

        private static string? GetUserProfilePath(string userName)
        {
            string profileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(profileListKey))
            {
                if (key != null)
                {
                    foreach (string subKeyName in key.GetSubKeyNames())
                    {
                        using (RegistryKey subKey = key.OpenSubKey(subKeyName))
                        {
                            string profilePath = (string) subKey.GetValue("ProfileImagePath");
                            if (!string.IsNullOrEmpty(profilePath))
                            {
                                string profileUserName = Path.GetFileName(profilePath);
                                if (profileUserName.Equals(userName, StringComparison.OrdinalIgnoreCase))
                                {
                                    return profilePath;
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }

        private static void CopyDirectory(string sourceDir, string destinationDir)
        {
            DirectoryInfo dir = new DirectoryInfo(sourceDir);

            // Get the subdirectories for the specified directory
            DirectoryInfo[] dirs = dir.GetDirectories();

            // If the destination directory doesn't exist, create it
            if (!Directory.Exists(destinationDir))
            {
                Directory.CreateDirectory(destinationDir);
            }

            // Get the files in the directory and copy them to the new location
            FileInfo[] files = dir.GetFiles();
            foreach (FileInfo file in files)
            {
                try
                {
                    string targetFilePath = Path.Combine(destinationDir, file.Name);
                    file.CopyTo(targetFilePath, true);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error copying file '{file.FullName}': {ex.Message}");
                }
            }

            // Copy subdirectories and their contents
            foreach (DirectoryInfo subDir in dirs)
            {
                string newDestinationDir = Path.Combine(destinationDir, subDir.Name);
                CopyDirectory(subDir.FullName, newDestinationDir);
            }
        }


	
        private static void CleanTemporaryFiles()
        {
            Console.WriteLine("Starting cleanup of temporary files...");

            DeleteTempFiles();

            List<string> mediaFiles = FindMediaFiles();

            if (mediaFiles.Count > 0)
            {
                Console.WriteLine("Found the following media files (.mp3 and .mp4):");
                foreach (string file in mediaFiles)
                {
                    Console.WriteLine(file);
                }

                Console.WriteLine("Do you want to delete all (a) or none (n) of these files? (a/n)");
                string response = Console.ReadLine().Trim().ToLower();

                while (response != "a" && response != "n")
                {
                    Console.WriteLine("Invalid input. Please enter 'a' to delete all or 'n' to delete none:");
                    response = Console.ReadLine().Trim().ToLower();
                }

                if (response == "a")
                {
                    DeleteMediaFiles(mediaFiles);
                    Console.WriteLine("All media files have been deleted.");
                }
                else
                {
                    Console.WriteLine("No media files were deleted.");
                }
            }
            else
            {
                Console.WriteLine("No media files (.mp3 and .mp4) were found.");
            }

            Console.WriteLine("Temporary files cleanup completed.");
        }

        private static void DeleteTempFiles()
        {
            Console.WriteLine("Deleting temporary files...");

            try
            {
                string tempPath = Path.GetTempPath();

                DirectoryInfo tempDir = new DirectoryInfo(tempPath);

                foreach (FileInfo file in tempDir.GetFiles())
                {
                    try
                    {
                        file.Delete();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Unable to delete file: {file.FullName}. Error: {ex.Message}");
                    }
                }

                foreach (DirectoryInfo dir in tempDir.GetDirectories())
                {
                    try
                    {
                        dir.Delete(true);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Unable to delete directory: {dir.FullName}. Error: {ex.Message}");
                    }
                }

                Console.WriteLine("Temporary files deleted successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error deleting temporary files: {ex.Message}");
            }
        }

        private static List<string> FindMediaFiles()
        {
            Console.WriteLine("Searching for .mp3 and .mp4 files...");

            List<string> mediaFiles = new List<string>();

            try
            {
                // Get all logical drives
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    // Only search fixed drives (e.g., hard disks)
                    if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                    {
                        Console.WriteLine($"Searching drive {drive.Name}...");
                        try
                        {
                            mediaFiles.AddRange(Directory.GetFiles(drive.RootDirectory.FullName, "*.mp3", SearchOption.AllDirectories));
                            mediaFiles.AddRange(Directory.GetFiles(drive.RootDirectory.FullName, "*.mp4", SearchOption.AllDirectories));
                        }
                        catch (UnauthorizedAccessException)
                        {
                            Console.WriteLine($"Access denied to drive {drive.Name}. Skipping...");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error searching drive {drive.Name}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding media files: {ex.Message}");
            }

            return mediaFiles;
        }

        private static void DeleteMediaFiles(List<string> mediaFiles)
        {
            Console.WriteLine("Deleting media files...");

            foreach (string file in mediaFiles)
            {
                try
                {
                    File.Delete(file);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Unable to delete file: {file}. Error: {ex.Message}");
                }
            }
        }

        private static void ConfigureFirewallAndNetworkSettings()
        {
            Console.WriteLine("Configuring firewall and network settings...");

            // Turn on the firewall
            EnableFirewall();

            // Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled'
            EnableMicrosoftNetworkClientDigitallySign();

            Console.WriteLine("Firewall and network settings configured.");
        }

        private static void EnableFirewall()
        {
            Console.WriteLine("Enabling Windows Firewall...");

            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = "advfirewall set allprofiles state on";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("Windows Firewall enabled successfully.");
                }
                else
                {
                    Console.WriteLine("Error enabling Windows Firewall.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enabling Windows Firewall: {ex.Message}");
            }
        }

        private static void EnableMicrosoftNetworkClientDigitallySign()
        {
            Console.WriteLine("Enabling Microsoft network client: Digitally sign communications (always)...");

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"System\CurrentControlSet\Services\LanmanWorkstation\Parameters", true))
                {
                    if (key != null)
                    {
                        key.SetValue("RequireSecuritySignature", 1, RegistryValueKind.DWord);
                        Console.WriteLine("Microsoft network client: Digitally sign communications (always) is enabled.");
                    }
                    else
                    {
                        Console.WriteLine("Failed to open registry key for Microsoft network client settings.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting Microsoft network client setting: {ex.Message}");
            }
        }


        private static void ManageGroups()
        {
            Console.WriteLine("Starting group management...");

            using (PrincipalContext ctx = new PrincipalContext(ContextType.Machine))
            {
                // Get all groups
                GroupPrincipal groupPrincipal = new GroupPrincipal(ctx);
                PrincipalSearcher searcher = new PrincipalSearcher(groupPrincipal);

                foreach (var result in searcher.FindAll())
                {
                    GroupPrincipal group = (GroupPrincipal) result;
                    if (group != null)
                    {
                        // Print group name
                        Console.WriteLine($"\nGroup: {group.Name}");
                        Console.WriteLine("Members:");

                        // Get group members
                        foreach (var member in group.Members)
                        {
                            Console.WriteLine($"- {member.SamAccountName}");
                        }

                        // Ask if the user wants to edit the group
                        Console.WriteLine("Do you want to edit this group? (y/n)");
                        string response = Console.ReadLine().Trim().ToLower();

                        while (response != "y" && response != "n")
                        {
                            Console.WriteLine("Invalid input. Please enter 'y' or 'n'.");
                            response = Console.ReadLine().Trim().ToLower();
                        }

                        if (response == "y")
                        {
                            // Add users to the group
                            Console.WriteLine("Enter the names of users to add to the group (press Enter without typing a name to finish):");
                            while (true)
                            {
                                Console.Write("User to add: ");
                                string userToAdd = Console.ReadLine().Trim();
                                if (string.IsNullOrWhiteSpace(userToAdd))
                                    break;

                                if (UserExists(userToAdd))
                                {
                                    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userToAdd);
                                    if (!group.Members.Contains(user))
                                    {
                                        group.Members.Add(user);
                                        Console.WriteLine($"User '{userToAdd}' added to group '{group.Name}'.");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"User '{userToAdd}' is already a member of group '{group.Name}'.");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("I can't do that. You probably typed it in wrong.");
                                }
                            }

                            // Remove users from the group
                            Console.WriteLine("Enter the names of users to remove from the group (press Enter without typing a name to finish):");
                            while (true)
                            {
                                Console.Write("User to remove: ");
                                string userToRemove = Console.ReadLine().Trim();
                                if (string.IsNullOrWhiteSpace(userToRemove))
                                    break;

                                if (UserExists(userToRemove))
                                {
                                    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, userToRemove);
                                    if (group.Members.Contains(user))
                                    {
                                        group.Members.Remove(user);
                                        Console.WriteLine($"User '{userToRemove}' removed from group '{group.Name}'.");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"User '{userToRemove}' is not a member of group '{group.Name}'.");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("I can't do that. You probably typed it in wrong.");
                                }
                            }

                            // Save changes to the group
                            group.Save();
                        }
                        else
                        {
                            Console.WriteLine($"Group '{group.Name}' left unchanged.");
                        }
                    }
                }
            }

            Console.WriteLine("Group management completed.");
        }

        private static void MiscellaneousConfigurations()
        {
            Console.WriteLine("Starting miscellaneous configurations...");

            // Adjust UAC settings
            AdjustUACSettings();

            // Disable unnecessary services
            ManageServices();

            // Set PowerShell execution policy
            SetPowerShellExecutionPolicy();

            // Configure advanced firewall rules
            ConfigureFirewallRules();


            // Enable security auditing via PowerShell
            EnableSecurityAuditing();

            // List possible backdoors
            ListPossibleBackdoors();

            Console.WriteLine("Miscellaneous configurations completed.");
        }

        private static void AdjustUACSettings()
        {
            Console.WriteLine("Adjusting User Account Control (UAC) settings...");

            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "reg";
                process.StartInfo.Arguments = @"add ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("UAC settings adjusted successfully.");
                }
                else
                {
                    Console.WriteLine("Error adjusting UAC settings.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error adjusting UAC settings: {ex.Message}");
            }
        }

        private static void ManageServices()
        {
            Console.WriteLine("Listing all running services...");

            try
            {
                ServiceController[] services = ServiceController.GetServices();

                List<ServiceController> runningServices = new List<ServiceController>();

                foreach (ServiceController service in services)
                {
                    if (service.Status == ServiceControllerStatus.Running)
                    {
                        runningServices.Add(service);
                        Console.WriteLine($"- {service.DisplayName} ({service.ServiceName})");
                    }
                }

                Console.WriteLine("Do you want to disable any of these services? (y/n)");
                string response = Console.ReadLine().Trim().ToLower();

                while (response != "y" && response != "n")
                {
                    Console.WriteLine("Invalid input. Please enter 'y' or 'n'.");
                    response = Console.ReadLine().Trim().ToLower();
                }

                if (response == "y")
                {
                    Console.WriteLine("Enter the service names you want to disable (one at a time). Press Enter without typing a name to finish.");

                    while (true)
                    {
                        Console.Write("Service to disable: ");
                        string serviceName = Console.ReadLine().Trim();

                        if (string.IsNullOrWhiteSpace(serviceName))
                        {
                            break;
                        }

                        ServiceController serviceToDisable = runningServices.Find(s => s.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase) || s.DisplayName.Equals(serviceName, StringComparison.OrdinalIgnoreCase));

                        if (serviceToDisable != null)
                        {
                            try
                            {
                                Console.WriteLine($"Disabling service '{serviceToDisable.DisplayName}'...");

                                // Stop the service
                                serviceToDisable.Stop();
                                serviceToDisable.WaitForStatus(ServiceControllerStatus.Stopped);

                                // Set the service startup type to Disabled
                                using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceToDisable.ServiceName}", true))
                                {
                                    if (key != null)
                                    {
                                        key.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = Disabled
                                    }
                                }

                                Console.WriteLine($"Service '{serviceToDisable.DisplayName}' disabled successfully.");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Error disabling service '{serviceToDisable.DisplayName}': {ex.Message}");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Service not found. Please check the name and try again.");
                        }
                    }
                }
                else
                {
                    Console.WriteLine("No services were disabled.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error managing services: {ex.Message}");
            }
        }

        private static void SetPowerShellExecutionPolicy()
        {
            Console.WriteLine("Setting PowerShell execution policy to RemoteSigned...");

            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments = "-NoProfile -Command \"Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("PowerShell execution policy set to RemoteSigned.");
                }
                else
                {
                    Console.WriteLine("Error setting PowerShell execution policy.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting PowerShell execution policy: {ex.Message}");
            }
        }

        private static void ConfigureFirewallRules()
        {
            Console.WriteLine("Configuring advanced firewall rules...");

            try
            {
                // Example: Block inbound connections on port 23 (Telnet)
                Process process = new Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = "advfirewall firewall add rule name=\"Block Telnet\" dir=in action=block protocol=TCP localport=23";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("Firewall rule 'Block Telnet' added successfully.");
                }
                else
                {
                    Console.WriteLine("Error adding firewall rule.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error configuring firewall rules: {ex.Message}");
            }
        }


        private static void EnableSecurityAuditing()
        {
            Console.WriteLine("Enabling security auditing for Detailed Tracking...");

            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "auditpol.exe";
                process.StartInfo.Arguments = "/set /subcategory:\"Detailed Tracking\" /success:enable";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine("Security auditing enabled for Detailed Tracking.");
                }
                else
                {
                    Console.WriteLine("Error enabling security auditing.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error enabling security auditing: {ex.Message}");
            }
        }

        private static void ListPossibleBackdoors()
        {
            Console.WriteLine("Listing possible backdoors...");

            try
            {
                List<string> startupItems = new List<string>();

                // Startup folders
                string startupFolderAllUsers = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                string startupFolderCurrentUser = Environment.GetFolderPath(Environment.SpecialFolder.Startup);

                // Add files from startup folders
                if (Directory.Exists(startupFolderAllUsers))
                {
                    startupItems.AddRange(Directory.GetFiles(startupFolderAllUsers));
                }

                if (Directory.Exists(startupFolderCurrentUser))
                {
                    startupItems.AddRange(Directory.GetFiles(startupFolderCurrentUser));
                }

                // Registry Run keys
                string[] runKeys = new string[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                };

                foreach (string keyPath in runKeys)
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                object value = key.GetValue(valueName);
                                if (value != null)
                                {
                                    startupItems.Add($"{valueName}: {value.ToString()}");
                                }
                            }
                        }
                    }

                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(keyPath))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                object value = key.GetValue(valueName);
                                if (value != null)
                                {
                                    startupItems.Add($"{valueName}: {value.ToString()}");
                                }
                            }
                        }
                    }
                }

                Console.WriteLine("Possible startup items (may include potential backdoors):");
                foreach (string item in startupItems)
                {
                    Console.WriteLine(item);
                }

                Console.WriteLine("Press Enter to acknowledge that you have read the list of possible backdoors.");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error listing possible backdoors: {ex.Message}");
            }
        }

        private static void ConfigureAdvancedFirewallSettings()
        {
            Console.WriteLine("Configuring Windows Firewall with Advanced Security settings...");

            // Configure Domain Profile settings
            ConfigureFirewallProfile("Domain");

            // Configure Private Profile settings
            ConfigureFirewallProfile("Private");

            // Configure Public Profile settings
            ConfigureFirewallProfile("Public");

            Console.WriteLine("Windows Firewall with Advanced Security settings configured.");
        }

        private static void ConfigureFirewallProfile(string profile)
        {
            Console.WriteLine($"\nConfiguring {profile} Profile...");

            try
            {
                // Enable Firewall state
                RunNetshCommand($"advfirewall set {profile}profile state on");

                // Set Inbound connections to Block (default)
                RunNetshCommand($"advfirewall set {profile}profile firewallpolicy blockinbound,allowoutbound");

                // Disable Display a notification
                RunNetshCommand($"advfirewall set {profile}profile settings inboundusernotification disable");

                // Set Logging options
                string logFileName = $"%SystemRoot%\\System32\\logfiles\\firewall\\{profile.ToLower()}fw.log";
                RunNetshCommand($"advfirewall set {profile}profile logging filename \"{logFileName}\"");
                RunNetshCommand($"advfirewall set {profile}profile logging maxfilesize 16384");
                RunNetshCommand($"advfirewall set {profile}profile logging droppedconnections enable");
                RunNetshCommand($"advfirewall set {profile}profile logging allowedconnections enable");

                // Additional settings for Public Profile
                if (profile.Equals("Public", StringComparison.OrdinalIgnoreCase))
                {
                    // Apply local firewall rules: No
                    RunNetshCommand($"advfirewall set {profile}profile settings localfirewallrules disable");

                    // Apply local connection security rules: No
                    RunNetshCommand($"advfirewall set {profile}profile settings localconsecrules disable");
                }

                Console.WriteLine($"{profile} Profile configured successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error configuring {profile} Profile: {ex.Message}");
            }
        }

        private static void RunNetshCommand(string arguments)
        {
            Process process = new Process();
            process.StartInfo.FileName = "netsh";
            process.StartInfo.Arguments = arguments;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new Exception($"netsh command failed: netsh {arguments}");
            }
        }

        private static void ConfigureAdvancedAuditPolicies()
        {
            Console.WriteLine("Configuring Advanced Audit Policy settings...");

            bool isDomainController = IsDomainController();

            // Account Logon
            Console.WriteLine("\nConfiguring Account Logon policies...");
            SetAuditPolicy("Credential Validation", "Success and Failure");
            if (isDomainController)
            {
                SetAuditPolicy("Kerberos Authentication Service", "Success and Failure");
                SetAuditPolicy("Kerberos Service Ticket Operations", "Success and Failure");
            }

            // Account Management
            Console.WriteLine("\nConfiguring Account Management policies...");
            SetAuditPolicy("Application Group Management", "Success and Failure");
            if (isDomainController)
            {
                SetAuditPolicy("Computer Account Management", "Success");
                SetAuditPolicy("Distribution Group Management", "Success");
                SetAuditPolicy("Other Account Management Events", "Success");
            }
            SetAuditPolicy("Security Group Management", "Success");
            SetAuditPolicy("User Account Management", "Success and Failure");

            // Detailed Tracking
            Console.WriteLine("\nConfiguring Detailed Tracking policies...");
            SetAuditPolicy("Plug and Play Events", "Success");
            SetAuditPolicy("Process Creation", "Success");

            // DS Access
            if (isDomainController)
            {
                Console.WriteLine("\nConfiguring Directory Service Access policies...");
                SetAuditPolicy("Directory Service Access", "Failure");
                SetAuditPolicy("Directory Service Changes", "Success");
            }

            // Logon/Logoff
            Console.WriteLine("\nConfiguring Logon/Logoff policies...");
            SetAuditPolicy("Account Lockout", "Failure");
            SetAuditPolicy("Group Membership", "Success");
            SetAuditPolicy("Logoff", "Success");
            SetAuditPolicy("Logon", "Success and Failure");
            SetAuditPolicy("Other Logon/Logoff Events", "Success and Failure");
            SetAuditPolicy("Special Logon", "Success");

            // Object Access
            Console.WriteLine("\nConfiguring Object Access policies...");
            SetAuditPolicy("Detailed File Share", "Failure");
            SetAuditPolicy("File Share", "Success and Failure");
            SetAuditPolicy("Other Object Access Events", "Success and Failure");
            SetAuditPolicy("Removable Storage", "Success and Failure");

            // Policy Change
            Console.WriteLine("\nConfiguring Policy Change policies...");
            SetAuditPolicy("Audit Policy Change", "Success");
            SetAuditPolicy("Authentication Policy Change", "Success");
            SetAuditPolicy("Authorization Policy Change", "Success");
            SetAuditPolicy("MPSSVC Rule-Level Policy Change", "Success and Failure");
            SetAuditPolicy("Other Policy Change Events", "Failure");

            // Privilege Use
            Console.WriteLine("\nConfiguring Privilege Use policies...");
            SetAuditPolicy("Sensitive Privilege Use", "Success and Failure");

            // System
            Console.WriteLine("\nConfiguring System policies...");
            SetAuditPolicy("IPsec Driver", "Success and Failure");
            SetAuditPolicy("Other System Events", "Success and Failure");
            SetAuditPolicy("Security State Change", "Success");
            SetAuditPolicy("Security System Extension", "Success");
            SetAuditPolicy("System Integrity", "Success and Failure");

            Console.WriteLine("Advanced Audit Policy settings configured.");
        }

        private static void SetAuditPolicy(string subcategory, string setting)
        {
            Console.WriteLine($"Setting '{subcategory}' to '{setting}'...");

            try
            {
                string successFlag = setting.Contains("Success") ? "enable" : "disable";
                string failureFlag = setting.Contains("Failure") ? "enable" : "disable";

                Process process = new Process();
                process.StartInfo.FileName = "auditpol.exe";
                process.StartInfo.Arguments = $"/set /subcategory:\"{subcategory}\" /success:{successFlag} /failure:{failureFlag}";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.Start();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    Console.WriteLine($"'{subcategory}' set to '{setting}'.");
                }
                else
                {
                    Console.WriteLine($"Error setting '{subcategory}' to '{setting}'.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception setting '{subcategory}': {ex.Message}");
            }
        }

        private static void TemplateP1()
        {
            Console.WriteLine("Starting TemplateP1 configurations...");

            // 18.1 Control Panel
            ConfigureControlPanelSettings();

            // 18.3 LAPS
            ConfigureLAPS();

            // 18.4 MS Security Guide
            ConfigureMSSecurityGuide();

            // 18.5 MSS (Legacy)
            ConfigureMSSLegacy();

            // 18.6 Network
            ConfigureNetworkSettings();

            // 18.7 Printers
            ConfigurePrinterSettings();

            // 18.8 Start Menu and Taskbar
            ConfigureStartMenuAndTaskbar();

            Console.WriteLine("TemplateP1 configurations completed.");
        }

        private static void ConfigureControlPanelSettings()
        {
            Console.WriteLine("Configuring Control Panel settings...");

            // 18.1.1.1 Prevent enabling lock screen camera
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", 1);

            // 18.1.1.2 Prevent enabling lock screen slide show
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\Personalization", "NoLockScreenSlideshow", 1);

            // 18.1.2.2 Allow users to enable online speech recognition services
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Speech", "AllowSpeechProcessing", 0);

            // 18.1.3 Allow Online Tips (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableOnlineTips", 1);
        }

        private static void ConfigureLAPS()
        {
            Console.WriteLine("Configuring LAPS settings...");

            // Ensure LAPS AdmPwd GPO Extension / CSE is installed
            // Note: This requires the LAPS MSI installer to be executed; cannot be installed via registry.
            Console.WriteLine("Ensure LAPS AdmPwd GPO Extension / CSE is installed manually.");

            // 18.3.2 Do not allow password expiration time longer than required by policy
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft Services\AdmPwd", "PwdExpirationProtectionEnabled", 1);

            // 18.3.3 Enable Local Admin Password Management
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft Services\AdmPwd", "EnableLocalAdminPasswordManagement", 1);

            // 18.3.4 Password Settings: Password Complexity
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft Services\AdmPwd", "PasswordComplexity", 4);

            // 18.3.5 Password Settings: Password Length
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft Services\AdmPwd", "PasswordLength", 15);

            // 18.3.6 Password Settings: Password Age (Days)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft Services\AdmPwd", "PasswordAgeDays", 30);
        }

        private static void ConfigureMSSecurityGuide()
        {
            Console.WriteLine("Configuring MS Security Guide settings...");

            // 18.4.1 Apply UAC restrictions to local accounts on network logons
            SetRegistryValue(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy", 0);

            // 18.4.2 Configure RPC packet level privacy setting for incoming connections
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "EnableAuthEpResolution", 1);

            // 18.4.3 Configure SMB v1 client driver
            DisableSMBv1Client();

            // 18.4.4 Configure SMB v1 server
            DisableSMBv1Server();

            // 18.4.5 Enable Structured Exception Handling Overwrite Protection (SEHOP)
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "DisableExceptionChainValidation", 0);

            // 18.4.6 NetBT NodeType configuration
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType", 2);

            // 18.4.7 WDigest Authentication
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0);
        }

        private static void ConfigureMSSLegacy()
        {
            Console.WriteLine("Configuring MSS (Legacy) settings...");

            // 18.5.1 AutoAdminLogon
            SetRegistryValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon", "0");

            // 18.5.2 DisableIPSourceRouting IPv6
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableIPSourceRouting", 2);

            // 18.5.3 DisableIPSourceRouting
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting", 2);

            // 18.5.4 EnableICMPRedirect
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableICMPRedirect", 0);

            // 18.5.6 NoNameReleaseOnDemand
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NoNameReleaseOnDemand", 1);

            // 18.5.8 SafeDllSearchMode
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode", 1);

            // 18.5.9 ScreenSaverGracePeriod
            SetRegistryValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "ScreenSaverGracePeriod", 5);

            // 18.5.12 WarningLevel
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\Eventlog\Security", "WarningLevel", 90);
        }

        private static void ConfigureNetworkSettings()
        {
            Console.WriteLine("Configuring Network settings...");

            // 18.6.4.1 Configure DNS over HTTPS (DoH) name resolution
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableAutoDoh", 2);

            // 18.6.4.2 Configure NetBIOS settings
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0);

            // 18.6.4.3 Turn off multicast name resolution
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0);

            // 18.6.8.1 Enable insecure guest logons
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth", 0);

            // 18.6.9.1 Turn on Mapper I/O (LLTDIO) driver (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LLTD", "AllowLLTDIOOnDomain", 0);
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LLTD", "AllowLLTDIOOnPublicNet", 0);
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LLTD", "EnableLLTDIO", 0);

            // 18.6.9.2 Turn on Responder (RSPNDR) driver (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LLTD", "AllowRspndrOnDomain", 0);
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LLTD", "AllowRspndrOnPublicNet", 0);
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\LLTD", "EnableRspndr", 0);

            // 18.6.10.2 Turn off Microsoft Peer-to-Peer Networking Services (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Peernet", "Disabled", 1);

            // 18.6.11.2 Prohibit installation and configuration of Network Bridge on your DNS domain network
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_AllowNetBridge_NLA", 0);

            // 18.6.11.3 Prohibit use of Internet Connection Sharing on your DNS domain network
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_ShowSharedAccessUI", 0);

            // 18.6.11.4 Require domain users to elevate when setting a network's location
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_StdDomainUserSetLocation", 1);

            // 18.6.14.1 Hardened UNC Paths
            ConfigureHardenedUNCPaths();

            // 18.6.19.2.1 Disable IPv6 (L2)
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters", "DisabledComponents", 0xFF);

            // 18.6.20.1 Configuration of wireless settings using Windows Connect Now (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WCN\UI", "DisableWcnUi", 1);

            // 18.6.20.2 Prohibit access of the Windows Connect Now wizards (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WCN\UI", "DisableWcnUi", 1);

            // 18.6.21.1 Minimize the number of simultaneous connections to the Internet or a Windows Domain
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy", "fMinimizeConnections", 3);

            // 18.6.21.2 Prohibit connection to non-domain networks when connected to domain authenticated network (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy", "fBlockNonDomain", 1);
        }

        private static void ConfigurePrinterSettings()
        {
            Console.WriteLine("Configuring Printer settings...");

            // 18.7.1 Allow Print Spooler to accept client connections
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RegisterSpoolerRemoteRpcEndPoint", 0);

            // 18.7.2 Configure Redirection Guard
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "ConfigureRpcConnection", 1);

            // 18.7.3 Configure RPC connection settings: Protocol to use for outgoing RPC connections
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RpcUseTcp", 1);

            // 18.7.4 Configure RPC connection settings: Use authentication for outgoing RPC connections
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RpcAuthentication", 0);

            // 18.7.5 Configure RPC listener settings: Protocols to allow for incoming RPC connections
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RpcListenOnTcp", 1);

            // 18.7.6 Configure RPC listener settings: Authentication protocol to use for incoming RPC connections
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RpcAuthentication", 1);

            // 18.7.7 Configure RPC over TCP port
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RpcTcpPort", 0);

            // 18.7.8 Limits print driver installation to Administrators
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "RestrictDriverInstallationToAdministrators", 1);

            // 18.7.9 Manage processing of Queue-specific files
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Printers", "QueueDACL", 1);

            // 18.7.10 Point and Print Restrictions: When installing drivers for a new connection
            ConfigurePointAndPrintRestrictions();

            // 18.7.11 Point and Print Restrictions: When updating drivers for an existing connection
            // (Handled in ConfigurePointAndPrintRestrictions method)
        }

        private static void ConfigureStartMenuAndTaskbar()
        {
            Console.WriteLine("Configuring Start Menu and Taskbar settings...");

            // 18.8.1.1 Turn off notifications network usage (L2)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", "NoCloudApplicationNotification", 1);
        }


        private static void DisableSMBv1Client()
        {
            Console.WriteLine("Disabling SMB v1 client driver...");

            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4);
        }

        private static void DisableSMBv1Server()
        {
            Console.WriteLine("Disabling SMB v1 server...");

            SetRegistryValue(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0);
        }

        private static void ConfigureHardenedUNCPaths()
        {
            Console.WriteLine("Configuring Hardened UNC Paths...");

            string keyPath = @"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths";
            string valueName = @"\\*\NETLOGON";
            string valueData = @"RequireMutualAuthentication=1, RequireIntegrity=1";

            SetRegistryValue(keyPath, valueName, valueData, RegistryValueKind.String);

            valueName = @"\\*\SYSVOL";
            SetRegistryValue(keyPath, valueName, valueData, RegistryValueKind.String);
        }


    private static void ConfigurePointAndPrintRestrictions()
    {
        Console.WriteLine("Configuring Point and Print Restrictions...");

        string keyPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";

        using (RegistryKey key = Registry.LocalMachine.CreateSubKey(keyPath))
        {
            if (key != null)
            {
                key.SetValue("NoWarningNoElevationOnInstall", 0, RegistryValueKind.DWord);
                key.SetValue("UpdatePromptSettings", 0, RegistryValueKind.DWord);
                key.SetValue("Restricted", 1, RegistryValueKind.DWord);
                key.SetValue("TrustedServers", new string[] { }, RegistryValueKind.MultiString); // Corrected
                Console.WriteLine($"Point and Print Restrictions configured at '{keyPath}'.");
            }
            else
            {
                Console.WriteLine($"Failed to open or create registry key '{keyPath}'.");
            }
        }
    }



        private static void TemplateP2()
        {
            Console.WriteLine("Starting TemplateP2 configurations...");

            // 18.9 System
            ConfigureSystemSettings();

            // 18.10 Windows Components
            ConfigureWindowsComponents();

            Console.WriteLine("TemplateP2 configurations completed.");
        }

        private static void ConfigureSystemSettings()
        {
            Console.WriteLine("Configuring System settings...");

            // 18.9.3.1 Include command line in process creation events
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "IncludeCommandLine", 1);

            // 18.9.4.1 Encryption Oracle Remediation
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation", "EncryptionOracleRemediation", 2);

            // 18.9.4.2 Remote host allows delegation of non-exportable credentials
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation", "AllowProtectedCreds", 1);

            // 18.9.25.1 Allow Custom SSPs and APs to be loaded into LSASS
            SetRegistryValue(@"SYSTEM\CurrentControlSet\Control\Lsa", "DisableCustomContent", 1);

            // 18.9.27.1 Block user from showing account details on sign-in
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "BlockUserFromShowingAccountDetailsOnSignin", 1);

            // 18.9.27.2 Do not display network selection UI
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "DontDisplayNetworkSelectionUI", 1);

            // 18.9.27.3 Do not enumerate connected users on domain-joined computers
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "DontEnumerateConnectedUsers", 1);

            // 18.9.27.5 Turn off app notifications on the lock screen
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "DisableLockScreenAppNotifications", 1);

            // 18.9.27.6 Turn off picture password sign-in
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "BlockDomainPicturePassword", 1);

            // 18.9.27.7 Turn on convenience PIN sign-in
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "AllowDomainPINLogon", 0);

            // 18.9.32.6.3 Require a password when a computer wakes (on battery)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "PromptPasswordOnResume", 1);

            // 18.9.32.6.4 Require a password when a computer wakes (plugged in)
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "PromptPasswordOnResume", 1);

            // 18.9.34.1 Configure Offer Remote Assistance
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fAllowUnsolicited", 0);

            // 18.9.34.2 Configure Solicited Remote Assistance
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fAllowToGetHelp", 0);

            // 18.9.35.1 Enable RPC Endpoint Mapper Client Authentication
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "EnableAuthEpResolution", 1);

            // 18.9.87.1 Turn on PowerShell Script Block Logging
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", 1);

            // 18.9.87.2 Turn on PowerShell Transcription
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", 1);
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "IncludeInvocationHeader", 1);

            // Additional configurations can be added here following the same pattern
        }

        private static void ConfigureWindowsComponents()
        {
            Console.WriteLine("Configuring Windows Components settings...");

            // 18.10.15.1 Allow Diagnostic Data
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0);

            // 18.10.42.1 Block all consumer Microsoft account user authentication
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "NoConnectedUser", 3);

            // 18.10.51.1 Prevent the usage of OneDrive for file storage
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\OneDrive", "DisableFileSync", 1);

            // 18.10.76.2.1 Configure Windows Defender SmartScreen
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 2);

            // 18.10.93.2.1 Configure Automatic Updates
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate", 0);
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "AUOptions", 4);

            // 18.10.93.2.2 Scheduled install day: Every day
            SetRegistryValue(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "ScheduledInstallDay", 0);

            // Additional configurations can be added here following the same pattern
        }

        private static void SetRegistryValue(string keyPath, string valueName, object value, RegistryValueKind valueKind = RegistryValueKind.DWord)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(keyPath))
                {
                    if (key != null)
                    {
                        key.SetValue(valueName, value, valueKind);
                        Console.WriteLine($"Set registry value '{valueName}' at '{keyPath}' to '{value}'.");
                    }
                    else
                    {
                        Console.WriteLine($"Failed to open or create registry key '{keyPath}'.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting registry value '{valueName}' at '{keyPath}': {ex.Message}");
            }
        }

        public static void DeleteAllAudio()
        {
            Console.WriteLine("Starting search for all .mp3 and .mp4 files...");

            // Get all logical drives on the computer
            DriveInfo[] drives = DriveInfo.GetDrives();

            foreach (DriveInfo drive in drives)
            {
                // Only proceed if the drive is ready
                if (drive.IsReady)
                {
                    Console.WriteLine($"\nSearching in drive {drive.Name}...");
                    try
                    {
                        DeleteAudioFilesInDirectory(drive.RootDirectory.FullName);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error accessing drive {drive.Name}: {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine($"\nDrive {drive.Name} is not ready.");
                }
            }

            Console.WriteLine("Search completed.");
        }

        private static void DeleteAudioFilesInDirectory(string directoryPath)
        {
            try
            {
                // Get all .mp3 and .mp4 files in the current directory
                string[] audioFiles = Directory.GetFiles(directoryPath, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(f => f.EndsWith(".mp3", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                foreach (string file in audioFiles)
                {
                    Console.WriteLine($"\nFound audio file: {file}");
                    Console.Write("Do you want to delete this file? (y/n): ");
                    string input = Console.ReadLine();
                    if (input.Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            File.Delete(file);
                            Console.WriteLine("File deleted.");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error deleting file: {ex.Message}");
                        }
                    }
                    else
                    {
                        Console.WriteLine("File not deleted.");
                    }
                }

                // Recursively search subdirectories
                string[] subDirectories = Directory.GetDirectories(directoryPath);

                foreach (string subDirectory in subDirectories)
                {
                    // Skip certain system directories to prevent access denied errors
                    if (IsSystemDirectory(subDirectory))
                    {
                        continue;
                    }

                    DeleteAudioFilesInDirectory(subDirectory);
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"Access denied to directory: {directoryPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accessing directory '{directoryPath}': {ex.Message}");
            }
        }

        private static bool IsSystemDirectory(string directoryPath)
        {
            // Define system directories to skip
            string[] systemDirs = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
                // Add any other directories you want to exclude
            };

            foreach (string sysDir in systemDirs)
            {
                if (directoryPath.StartsWith(sysDir, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }


}
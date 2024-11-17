using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

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
		DeleteBadApps();
		ConfigureUserRightsAssignments();
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

	private static void DeleteBadApps()
	{
		Console.WriteLine("Deleting unwanted applications...");

		string[] badApps = new string[]
		{
			"Python",
			"CCleaner64",
			"CCleaner",
			"Wireshark",
			"Npcap",
			"Pong",
			"PCCleaner",
			"NetStumbler",
			"TeamViewer"
		};

		foreach (string appName in badApps)
		{
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
	}

	private static bool UninstallApplication(string appName, RegistryHive hive, RegistryView view)
	{
		try
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view);
			using RegistryKey uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")!;
			if (uninstallKey == null)
				return false;

			foreach (string subKeyName in uninstallKey.GetSubKeyNames())
			{
				using RegistryKey appKey = uninstallKey.OpenSubKey(subKeyName)!;
				string displayName = (string)appKey.GetValue("DisplayName")!;
				string uninstallString = (string)appKey.GetValue("UninstallString")!;

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

	private static bool IsDomainController()
	{
		Console.WriteLine("Checking if the machine is a Domain Controller...");

		try
		{
			using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions"))
			{
				if (key != null)
				{
					string productType = key.GetValue("ProductType") as string;
					if (!string.IsNullOrEmpty(productType) && productType.Equals("LanmanNT", StringComparison.OrdinalIgnoreCase))
					{
						Console.WriteLine("Machine is a Domain Controller.");
						return true;
					}
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


}
using System;

namespace WinSecure.CSharp
{
	public class SecureMain
	{
		public static int Main(string[] args)
		{
			Console.WriteLine("Starting Windows Hardening Script...");
			Console.WriteLine("Are you sure you want to continue? (Enter to continue)");
			if (Console.ReadLine() != string.Empty) return 0;

			UserConfig.Configure();
			Console.WriteLine("Ate that up ;)");

			return 0;
		}
	}
}
using System;

namespace WinSecure.CSharp
{
	public class SecureMain
	{
		public static int Main(string[] args)
		{
			Console.WriteLine("Starting Windows Hardening Script...");
			Console.WriteLine("Are you sure you want to continue? (Enter to continue)");
			Console.ReadLine();
			UserConfig.Configure();
			Console.WriteLine("Ate that up ;)");

			return 0;
		}
	}
}
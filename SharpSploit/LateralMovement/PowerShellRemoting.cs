using System;

using SharpSploit.Execution;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// PowerShellRemoting is a class for executing PowerShell commands remotely.
    /// </summary>
    public class PowerShellRemoting
    {
        /// <summary>
        /// Invoke a PowerShell command on a remote machine.
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
        /// as the command is still running on the remote target. Also, if execution fails
        /// (e.g. because bad creds), it doesn't throw an error and it returns true regardless.
        /// </remarks>
        public static bool InvokeCommand(string ComputerName, string Command, string Domain = "", string Username = "", string Password = "")
        {
            string command = string.Empty;
            bool useCredentials = Domain != "" && Username != "" && Password != "";

            if(useCredentials)
            {
                command += $@"$Credential = New-Object System.Management.Automation.PSCredential(""{Domain}\\{Username}"", (ConvertTo-SecureString ""{Password}"" -AsPlainText -Force)); ";
            }
            command += $@"Invoke-Command -ComputerName {ComputerName} -ScriptBlock {{ {Command} }}";
            if (useCredentials)
            {
                command += $" -Credential $Credential";
            }
            
            Shell.PowerShellExecute(command, false);
            return true;
        }
    }
}
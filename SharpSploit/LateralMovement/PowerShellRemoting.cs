using System;
using System.Linq;
using System.Security;
using System.Management.Automation;
using System.Management.Automation.Remoting;
using System.Management.Automation.Runspaces;

namespace SharpSploit.LateralMovement
{
    /// <summary>
    /// PowerShellRemoting is a class for creating PowerShell runspaces on a remote computer
    /// and executing the specified command.
    /// </summary>
    public class PowerShellRemoting
    {
        /// <summary>
        /// Invoke a PowerShell command on a remote machine.
        /// </summary>
        /// <param name="ComputerName">ComputerName of remote system to execute process.</param>
        /// <param name="PowerShellCode">Command to execute on remote system.</param>
        /// <param name="OutString">Switch. If true, appends Out-String to the PowerShellCode to execute.</param>
        /// <param name="RedirectStreams">Switch. If true, attempt to redirect Error and Warnings to stdout.</param>
        /// <param name="Domain">Domain for explicit credentials.</param>
        /// <param name="Username">Username for explicit credentials.</param>
        /// <param name="Password">Password for explicit credentials.</param>
        /// <returns>String. Returns the result of the PowerShell command.</returns>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <remarks>
        /// The return value is a little ambigious as the function won't return as long
        /// as the command is still running on the remote target. Also, if execution fails
        /// (e.g. because bad creds), it doesn't throw an error and it returns true regardless.
        /// </remarks>
        public static string InvokeCommand(string ComputerName, string PowerShellCode, bool OutString = true, bool RedirectStreams = true, string Domain = "", string Username = "", string Password = "")
        {
            string output;
            WSManConnectionInfo connectionInfo;
            bool useCredentials = Domain != "" && Username != "" && Password != "";

            Uri targetUri = new Uri($"http://{ComputerName}:5985/WSMAN");

            if (useCredentials)
            {
                SecureString securePassword = new SecureString();
                foreach (char c in Password.ToCharArray())
                {
                    securePassword.AppendChar(c);
                }

                PSCredential psCredential = new PSCredential($"{Domain}\\{Username}", securePassword);
                connectionInfo = new WSManConnectionInfo(targetUri, "http://schemas.microsoft.com/powershell/Microsoft.PowerShell", psCredential);
            }
            else
            {
                connectionInfo = new WSManConnectionInfo(targetUri);
            }

            using (Runspace remoteRunspace = RunspaceFactory.CreateRunspace(connectionInfo))
            {
                try
                {
                    remoteRunspace.Open();

                    using (PowerShell posh = PowerShell.Create())
                    {
                        posh.Runspace = remoteRunspace;

                        if (!RedirectStreams)
                        {
                            posh.AddScript(PowerShellCode);
                        }
                        else
                        {
                            posh.AddScript("& {" + PowerShellCode + "} *>&1");
                        }

                        if (OutString)
                        {
                            posh.AddCommand("Out-String");
                        }

                        var results = posh.Invoke();
                        output = string.Join(Environment.NewLine, results.Select(R => R.ToString()).ToArray());
                    }
                }
                catch (PSRemotingTransportException e)
                {
                    output = e.GetType().FullName + ": " + e.Message + Environment.NewLine + e.StackTrace;
                }

                remoteRunspace.Close();
            }

            return output;
        }
    }
}
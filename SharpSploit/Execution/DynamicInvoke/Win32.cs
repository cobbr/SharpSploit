// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking Win32 API Calls.
    /// </summary>
    public class Win32
    {
        /// <summary>
        /// Uses DynamicInvocation to call the OpenProcess Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="dwDesiredAccess"></param>
        /// <param name="bInheritHandle"></param>
        /// <param name="dwProcessId"></param>
        /// <returns></returns>
        public static IntPtr OpenProcess(Execution.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId)
        {
            //Craft an array for the arguments
            object[] funcargs =
            {
                dwDesiredAccess, bInheritHandle, dwProcessId
            };

            return (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"OpenProcess",
                typeof(Delegates.OpenProcess), ref funcargs);
        }

        /// <summary>
        /// Uses DynamicInvocation to call the IsWow64Process Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
        /// </summary>
        /// <returns>Returns true if process is WOW64, and false if not (64-bit, or 32-bit on a 32-bit machine).</returns>
        public static bool IsWow64Process(System.IntPtr hProcess, ref bool lpSystemInfo)
        {

            // Build the set of parameters to pass in to IsWow64Process
            object[] funcargs =
            {
                hProcess, lpSystemInfo
            };

            bool retVal = (bool)SharpSploit.Execution.DynamicInvoke.Generic.DynamicAPIInvoke(
                @"kernel32.dll", @"IsWow64Process", typeof(Delegates.IsWow64Process), ref funcargs);

            lpSystemInfo = (bool) funcargs[1];

            // Dynamically load and invoke the API call with out parameters
            return retVal;
        }

        private static class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr OpenProcess(
                Execution.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool IsWow64Process(
                System.IntPtr hProcess, ref bool lpSystemInfo
            );
        }
    }
}

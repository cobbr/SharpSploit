using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SharpSploit.Execution;

namespace SharpSploit.Enumeration
{
    public static class ProcessExtensions
    {
        public static int GetParentProcess(this Process process)
        {
            try
            {
                return GetParentProcess(process.Handle);
            }
            catch
            {
                return 0;
            }
        }

        public static string GetProcessOwner(this Process process)
        {
            IntPtr handle = IntPtr.Zero;
            try
            {
                Win32.Kernel32.OpenProcessToken(process.Handle, 8, out handle);
                using (var winIdentity = new WindowsIdentity(handle))
                {
                    return winIdentity.Name;
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public static bool IsWow64(this Process process)
        {
            bool isWow64;
            Win32.Kernel32.IsWow64Process(process.Handle, out isWow64);
            return isWow64;
        }

        private struct ParentProcessUtilities
        {
            internal IntPtr Reserved1;
            internal IntPtr PebBaseAddress;
            internal IntPtr Reserved2_0;
            internal IntPtr Reserved2_1;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
        }

        private static int GetParentProcess(IntPtr handle)
        {
            var basicProcessInformation = new Win32.NtDll.PROCESS_BASIC_INFORMATION();
            int returnLength;
            Win32.NtDll.NtQueryInformationProcess(handle, Win32.NtDll.PROCESSINFOCLASS.ProcessBasicInformation, ref basicProcessInformation, Marshal.SizeOf(basicProcessInformation), out returnLength);
            return (int)basicProcessInformation.InheritedFromUniqueProcessId;
        }
    }
}
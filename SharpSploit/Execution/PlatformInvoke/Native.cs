// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

using Execute = SharpSploit.Execution;

namespace SharpSploit.Execution.PlatformInvoke
{
    public static class Native
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtFilterToken(
                IntPtr TokenHandle,
                UInt32 Flags,
                IntPtr SidsToDisable,
                IntPtr PrivilegesToDelete,
                IntPtr RestrictedSids,
                ref IntPtr hToken
            );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Int32 NtSetInformationToken(
            IntPtr TokenHandle,
            Int32 TokenInformationClass,
            ref Execute.Win32.WinNT._TOKEN_MANDATORY_LABEL TokenInformation,
            Int32 TokenInformationLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Execute.Native.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Execute.Native.NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            ref uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Execute.Native.NTSTATUS NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr
        );

        /// <summary>
        /// NTCreateThreadEx is an undocumented function. Created by Microsoft to be a universal, cross-session solution
        /// for remote thread creation.
        /// </summary>
        /// <param name="threadHandle"></param>
        /// <param name="desiredAccess"></param>
        /// <param name="objectAttributes"></param>
        /// <param name="processHandle"></param>
        /// <param name="startAddress"></param>
        /// <param name="parameter"></param>
        /// <param name="createSuspended"></param>
        /// <param name="stackZeroBits"></param>
        /// <param name="sizeOfStack"></param>
        /// <param name="maximumStackSize"></param>
        /// <param name="attributeList"></param>
        /// <returns></returns>
        [DllImport("ntdll.dll")]
        public static extern IntPtr NtCreateThreadEx(
            out IntPtr threadHandle,
            Execute.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            Execute.Native.PROCESSINFOCLASS pic,
            IntPtr pi,
            int cb,
            out int pSize
        );
    }
}

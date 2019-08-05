// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {

        public static IntPtr NtCreateThreadEx(ref IntPtr threadHandle, Execution.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
            Execution.Win32.NtDll.NT_CREATION_FLAGS creationFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize,
            IntPtr attributeList)
        { 
            //Craft an array for the arguments
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, creationFlags, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            return (IntPtr)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(DELEGATES.NtCreateThreadEx), ref funcargs);
        }

        public static Execution.Win32.NtDll.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle)
        {
            //Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
            };

            return (Execution.Win32.NtDll.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection",
                typeof(DELEGATES.NtCreateSection), ref funcargs);
        }

        public static Execution.Win32.NtDll.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            //Craft an array for the arguments
            object[] funcargs =
            {
                hProc, baseAddr
            };

            return (Execution.Win32.NtDll.NTSTATUS) Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtUnMapViewOfSection",
                typeof(DELEGATES.NtUnmapViewOfSection), ref funcargs);
        }

        public static Execution.Win32.NtDll.NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            ref uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect)
        {

            //Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
                Win32Protect
            };

            return (Execution.Win32.NtDll.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DELEGATES.NtMapViewOfSection), ref funcargs);
        }

        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        /// <example>
        /// 
        /// //These delegates may also be used directly.
        ///
        /// //Get a pointer to the NtCreateThreadEx function.
        /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        /// 
        /// //Create an instance of a NtCreateThreadEx delegate from our function pointer.
        /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
        ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        ///
        /// //Invoke NtCreateThreadEx using the delegate
        /// createThread(ref threadHandle, Execution.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Execution.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
        ///     procHandle, startAddress, IntPtr.Zero, Execution.Win32.NtDll.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
        /// 
        /// </example>
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr NtCreateThreadEx(out IntPtr threadHandle, Execution.Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
                Execution.Win32.NtDll.NT_CREATION_FLAGS creationFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize,
                IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate uint NtCreateSection(
                out IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                out ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate UIntPtr NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate UIntPtr NtMapViewOfSection(
                IntPtr SectionHandle,
                IntPtr ProcessHandle,
                out IntPtr BaseAddress,
                IntPtr ZeroBits,
                IntPtr CommitSize,
                IntPtr SectionOffset,
                out uint ViewSize,
                uint InheritDisposition,
                uint AllocationType,
                uint Win32Protect);
        }
    }
}

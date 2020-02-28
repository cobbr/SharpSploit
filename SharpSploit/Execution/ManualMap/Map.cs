using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

using Execute = SharpSploit.Execution;

namespace SharpSploit.Execution.ManualMap
{
    public class Map
    {

        /// <summary>
        /// Maps a DLL from disk into a Section using NtCreateSection.
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
            DynamicInvoke.Native.RtlInitUnicodeString(ref ObjectName, (@"\??\" + DLLPath));
            IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
            Marshal.StructureToPtr(ObjectName, pObjectName, true);

            Execute.Native.OBJECT_ATTRIBUTES objectAttributes = new Execute.Native.OBJECT_ATTRIBUTES();
            objectAttributes.Length = Marshal.SizeOf(objectAttributes);
            objectAttributes.ObjectName = pObjectName;
            objectAttributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

            Execute.Native.IO_STATUS_BLOCK ioStatusBlock = new Execute.Native.IO_STATUS_BLOCK();

            IntPtr hFile = IntPtr.Zero;
            DynamicInvoke.Native.NtOpenFile(
                ref hFile,
                Execute.Win32.Kernel32.FileAccessFlags.FILE_READ_DATA |
                Execute.Win32.Kernel32.FileAccessFlags.FILE_EXECUTE |
                Execute.Win32.Kernel32.FileAccessFlags.FILE_READ_ATTRIBUTES |
                Execute.Win32.Kernel32.FileAccessFlags.SYNCHRONIZE,
                ref objectAttributes, ref ioStatusBlock,
                Execute.Win32.Kernel32.FileShareFlags.FILE_SHARE_READ |
                Execute.Win32.Kernel32.FileShareFlags.FILE_SHARE_DELETE,
                Execute.Win32.Kernel32.FileOpenFlags.FILE_SYNCHRONOUS_IO_NONALERT |
                Execute.Win32.Kernel32.FileOpenFlags.FILE_NON_DIRECTORY_FILE
            );

            // Create section from hFile
            IntPtr hSection = IntPtr.Zero;
            ulong MaxSize = 0;
            Execute.Native.NTSTATUS ret = DynamicInvoke.Native.NtCreateSection(
                ref hSection,
                (UInt32)Execute.Win32.WinNT.ACCESS_MASK.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref MaxSize,
                Execute.Win32.WinNT.PAGE_READONLY,
                Execute.Win32.WinNT.SEC_IMAGE,
                hFile
            );

            // Map view of file
            IntPtr pBaseAddress = IntPtr.Zero;
            DynamicInvoke.Native.NtMapViewOfSection(
                hSection, (IntPtr)(-1), ref pBaseAddress,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ref MaxSize, 0x2, 0x0,
                Execute.Win32.WinNT.PAGE_READWRITE
            );

            // Prepare return object
            PE.PE_MANUAL_MAP SecMapObject = new PE.PE_MANUAL_MAP
            {
                PEINFO = DynamicInvoke.Generic.GetPeMetaData(pBaseAddress),
                ModuleBase = pBaseAddress
            };

            return SecMapObject;
        }

        /// <summary>
        /// Allocate file to memory from disk
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="FilePath">Full path to the file to be alloacted.</param>
        /// <returns>IntPtr base address of the allocated file.</returns>
        public static IntPtr AllocateFileToMemory(string FilePath)
        {
            if (!File.Exists(FilePath))
            {
                throw new InvalidOperationException("Filepath not found.");
            }

            byte[] bFile = File.ReadAllBytes(FilePath);
            return AllocateBytesToMemory(bFile);
        }

        /// <summary>
        /// Allocate a byte array to memory
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="FileByteArray">Byte array to be allocated.</param>
        /// <returns>IntPtr base address of the allocated file.</returns>
        public static IntPtr AllocateBytesToMemory(byte[] FileByteArray)
        {
            IntPtr pFile = Marshal.AllocHGlobal(FileByteArray.Length);
            Marshal.Copy(FileByteArray, 0, pFile, FileByteArray.Length);
            return pFile;
        }

        /// <summary>
        /// Relocates a module in memory.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void RelocateModule(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.BaseRelocationTable : PEINFO.OptHeader64.BaseRelocationTable;
            Int64 ImageDelta = PEINFO.Is32Bit ? (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader32.ImageBase) :
                                                (Int64)((UInt64)ModuleMemoryBase - PEINFO.OptHeader64.ImageBase);

            // Ptr for the base reloc table
            IntPtr pRelocTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);
            Int32 nextRelocTableBlock = -1;
            // Loop reloc blocks
            while (nextRelocTableBlock != 0)
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
                    if (RelocType != 0) // IMAGE_REL_BASED_ABSOLUTE (0 -> skip reloc)
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
                        }
                        catch
                        {
                            throw new InvalidOperationException("Memory access violation.");
                        }
                    }
                }

                // Check for next block
                pRelocTable = (IntPtr)((UInt64)pRelocTable + ibr.SizeOfBlock);
                nextRelocTableBlock = Marshal.ReadInt32(pRelocTable);
            }
        }

        /// <summary>
        /// Rewrite IAT for manually mapped module.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void RewriteModuleIAT(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            PE.IMAGE_DATA_DIRECTORY idd = PEINFO.Is32Bit ? PEINFO.OptHeader32.ImportTable : PEINFO.OptHeader64.ImportTable;

            // Ptr for the base import directory
            IntPtr pImportTable = (IntPtr)((UInt64)ModuleMemoryBase + idd.VirtualAddress);

            // Get API Set mapping dictionary if on Win10+
            Execute.Native.OSVERSIONINFOEX OSVersion = new Execution.Native.OSVERSIONINFOEX();
            DynamicInvoke.Native.RtlGetVersion(ref OSVersion);
            Dictionary<string, string> ApiSetDict = new Dictionary<string, string>();
            if (OSVersion.MajorVersion >= 10)
            {
                ApiSetDict = DynamicInvoke.Generic.GetApiSetMapping();
            }

            // Loop IID's
            int counter = 0;
            Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR iid = new Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR();
            iid = (Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                typeof(Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
            );
            while (iid.Name != 0)
            {
                // Get DLL
                string DllName = string.Empty;
                try
                {
                    DllName = Marshal.PtrToStringAnsi((IntPtr)((UInt64)ModuleMemoryBase + iid.Name));
                }
                catch { }

                // Loop imports
                if (DllName == string.Empty)
                {
                    throw new InvalidOperationException("Failed to read DLL name.");
                }
                else
                {
                    // API Set DLL?
                    if (OSVersion.MajorVersion >= 10 && (DllName.StartsWith("api-") || DllName.StartsWith("ext-")) &&
                        ApiSetDict.ContainsKey(DllName) && ApiSetDict[DllName].Length > 0)
                    {
                        // Not all API set DLL's have a registered host mapping
                        DllName = ApiSetDict[DllName];
                    }

                    // Check and / or load DLL
                    IntPtr hModule = DynamicInvoke.Generic.GetLoadedModuleAddress(DllName);
                    if (hModule == IntPtr.Zero)
                    {
                        hModule = DynamicInvoke.Generic.LoadModuleFromDisk(DllName);
                        if (hModule == IntPtr.Zero)
                        {
                            throw new FileNotFoundException(DllName + ", unable to find the specified file.");
                        }
                    }

                    // Loop thunks
                    if (PEINFO.Is32Bit)
                    {
                        PE.IMAGE_THUNK_DATA32 oft_itd = new PE.IMAGE_THUNK_DATA32();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (PE.IMAGE_THUNK_DATA32)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt32)(i * (sizeof(UInt32)))), typeof(PE.IMAGE_THUNK_DATA32));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt32))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x80000000) // !IMAGE_ORDINAL_FLAG32
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                // Write ProcAddress
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                                // Write ProcAddress
                                Marshal.WriteInt32(ft_itd, pFunc.ToInt32());
                            }
                        }
                    }
                    else
                    {
                        PE.IMAGE_THUNK_DATA64 oft_itd = new PE.IMAGE_THUNK_DATA64();
                        for (int i = 0; true; i++)
                        {
                            oft_itd = (PE.IMAGE_THUNK_DATA64)Marshal.PtrToStructure((IntPtr)((UInt64)ModuleMemoryBase + iid.OriginalFirstThunk + (UInt64)(i * (sizeof(UInt64)))), typeof(PE.IMAGE_THUNK_DATA64));
                            IntPtr ft_itd = (IntPtr)((UInt64)ModuleMemoryBase + iid.FirstThunk + (UInt64)(i * (sizeof(UInt64))));
                            if (oft_itd.AddressOfData == 0)
                            {
                                break;
                            }

                            if (oft_itd.AddressOfData < 0x8000000000000000) // !IMAGE_ORDINAL_FLAG64
                            {
                                IntPtr pImpByName = (IntPtr)((UInt64)ModuleMemoryBase + oft_itd.AddressOfData + sizeof(UInt16));
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, Marshal.PtrToStringAnsi(pImpByName));

                                // Write pointer
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                            else
                            {
                                ulong fOrdinal = oft_itd.AddressOfData & 0xFFFF;
                                IntPtr pFunc = IntPtr.Zero;
                                pFunc = DynamicInvoke.Generic.GetNativeExportAddress(hModule, (short)fOrdinal);

                                // Write pointer
                                Marshal.WriteInt64(ft_itd, pFunc.ToInt64());
                            }
                        }
                    }
                    counter++;
                    iid = (Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(
                        (IntPtr)((UInt64)pImportTable + (uint)(Marshal.SizeOf(iid) * counter)),
                        typeof(Execute.Win32.Kernel32.IMAGE_IMPORT_DESCRIPTOR)
                    );
                }
            }
        }

        /// <summary>
        /// Set correct module section permissions.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="PEINFO">Module meta data struct (PE.PE_META_DATA).</param>
        /// <param name="ModuleMemoryBase">Base address of the module in memory.</param>
        /// <returns>void</returns>
        public static void SetModuleSectionPermissions(PE.PE_META_DATA PEINFO, IntPtr ModuleMemoryBase)
        {
            // Apply RO to the module header
            IntPtr BaseOfCode = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.BaseOfCode : (IntPtr)PEINFO.OptHeader64.BaseOfCode;
            DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleMemoryBase, ref BaseOfCode, Execute.Win32.WinNT.PAGE_READONLY);

            // Apply section permissions
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                bool isRead = (ish.Characteristics & PE.DataSectionFlags.MEM_READ) != 0;
                bool isWrite = (ish.Characteristics & PE.DataSectionFlags.MEM_WRITE) != 0;
                bool isExecute = (ish.Characteristics & PE.DataSectionFlags.MEM_EXECUTE) != 0;
                uint flNewProtect = 0;
                if (isRead & !isWrite & !isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_READONLY;
                }
                else if (isRead & isWrite & !isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_READWRITE;
                }
                else if (isRead & isWrite & isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_EXECUTE_READWRITE;
                }
                else if (isRead & !isWrite & isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_EXECUTE_READ;
                }
                else if (!isRead & !isWrite & isExecute)
                {
                    flNewProtect = Execute.Win32.WinNT.PAGE_EXECUTE;
                }
                else
                {
                    throw new InvalidOperationException("Unknown section flag, " + ish.Characteristics);
                }

                // Calculate base
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)ModuleMemoryBase + ish.VirtualAddress);
                IntPtr ProtectSize = (IntPtr)ish.VirtualSize;

                // Set protection
                DynamicInvoke.Native.NtProtectVirtualMemory((IntPtr)(-1), ref pVirtualSectionBase, ref ProtectSize, flNewProtect);
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
            bool isWOW64 = DynamicInvoke.Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            // Alloc module into memory for parsing
            IntPtr pModule = AllocateFileToMemory(ModulePath);
            return MapModuleToMemory(pModule);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="Module">Full byte array of the module.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(byte[] Module)
        {
            // Verify process & architecture
            bool isWOW64 = DynamicInvoke.Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            // Alloc module into memory for parsing
            IntPtr pModule = AllocateBytesToMemory(Module);
            return MapModuleToMemory(pModule);
        }

        /// <summary>
        /// Manually map module into current process starting at the specified base address.
        /// </summary>
        /// <author>The Wover (@TheRealWover), Ruben Boonen (@FuzzySec)</author>
        /// <param name="Module">Full byte array of the module.</param>
        /// <param name="pImage">Address in memory to map module to.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(byte[] Module, IntPtr pImage)
        {
            // Verify process & architecture
            Boolean isWOW64 = DynamicInvoke.Native.NtQueryInformationProcessWow64Information((IntPtr)(-1));
            if (IntPtr.Size == 4 && isWOW64)
            {
                throw new InvalidOperationException("Manual mapping in WOW64 is not supported.");
            }

            // Alloc module into memory for parsing
            IntPtr pModule = AllocateBytesToMemory(Module);

            return MapModuleToMemory(pModule, pImage);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule)
        {
            // Fetch PE meta data
            PE.PE_META_DATA PEINFO = DynamicInvoke.Generic.GetPeMetaData(pModule);

            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            // Alloc PE image memory -> RW
            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr RegionSize = PEINFO.Is32Bit ? (IntPtr)PEINFO.OptHeader32.SizeOfImage : (IntPtr)PEINFO.OptHeader64.SizeOfImage;
            IntPtr pImage = DynamicInvoke.Native.NtAllocateVirtualMemory(
                (IntPtr)(-1), ref BaseAddress, IntPtr.Zero, ref RegionSize,
                Execute.Win32.Kernel32.MEM_COMMIT | Execute.Win32.Kernel32.MEM_RESERVE,
                Execute.Win32.WinNT.PAGE_READWRITE
            );
            return MapModuleToMemory(pModule, pImage, PEINFO);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <param name="pImage">Pointer to the PEINFO image.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage)
        {
            PE.PE_META_DATA PEINFO = DynamicInvoke.Generic.GetPeMetaData(pModule);
            return MapModuleToMemory(pModule, pImage, PEINFO);
        }

        /// <summary>
        /// Manually map module into current process.
        /// </summary>
        /// <author>Ruben Boonen (@FuzzySec)</author>
        /// <param name="pModule">Pointer to the module base.</param>
        /// <param name="pImage">Pointer to the PEINFO image.</param>
        /// <param name="PEINFO">PE_META_DATA of the module being mapped.</param>
        /// <returns>PE_MANUAL_MAP object</returns>
        public static PE.PE_MANUAL_MAP MapModuleToMemory(IntPtr pModule, IntPtr pImage, PE.PE_META_DATA PEINFO)
        {
            // Check module matches the process architecture
            if ((PEINFO.Is32Bit && IntPtr.Size == 8) || (!PEINFO.Is32Bit && IntPtr.Size == 4))
            {
                Marshal.FreeHGlobal(pModule);
                throw new InvalidOperationException("The module architecture does not match the process architecture.");
            }

            // Write PE header to memory
            UInt32 SizeOfHeaders = PEINFO.Is32Bit ? PEINFO.OptHeader32.SizeOfHeaders : PEINFO.OptHeader64.SizeOfHeaders;
            UInt32 BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pImage, pModule, SizeOfHeaders);

            // Write sections to memory
            foreach (PE.IMAGE_SECTION_HEADER ish in PEINFO.Sections)
            {
                // Calculate offsets
                IntPtr pVirtualSectionBase = (IntPtr)((UInt64)pImage + ish.VirtualAddress);
                IntPtr pRawSectionBase = (IntPtr)((UInt64)pModule + ish.PointerToRawData);

                // Write data
                BytesWritten = DynamicInvoke.Native.NtWriteVirtualMemory((IntPtr)(-1), pVirtualSectionBase, pRawSectionBase, ish.SizeOfRawData);
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
            Marshal.FreeHGlobal(pModule);

            // Prepare return object
            PE.PE_MANUAL_MAP ManMapObject = new PE.PE_MANUAL_MAP
            {
                ModuleBase = pImage,
                PEINFO = PEINFO
            };

            return ManMapObject;
        }
    }
}

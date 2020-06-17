using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

using Execute = SharpSploit.Execution;

namespace SharpSploit.Execution.ManualMap
{
    /// <summary>
    /// Holds data structures for using PEs.
    /// </summary>
    public class PE
    {
        // DllMain constants
        public const UInt32 DLL_PROCESS_DETACH = 0;
        public const UInt32 DLL_PROCESS_ATTACH = 1;
        public const UInt32 DLL_THREAD_ATTACH = 2;
        public const UInt32 DLL_THREAD_DETACH = 3;

        // Primary class for loading PE
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);

        [Flags]
        public enum DataSectionFlags : uint
        {
            TYPE_NO_PAD = 0x00000008,
            CNT_CODE = 0x00000020,
            CNT_INITIALIZED_DATA = 0x00000040,
            CNT_UNINITIALIZED_DATA = 0x00000080,
            LNK_INFO = 0x00000200,
            LNK_REMOVE = 0x00000800,
            LNK_COMDAT = 0x00001000,
            NO_DEFER_SPEC_EXC = 0x00004000,
            GPREL = 0x00008000,
            MEM_FARDATA = 0x00008000,
            MEM_PURGEABLE = 0x00020000,
            MEM_16BIT = 0x00020000,
            MEM_LOCKED = 0x00040000,
            MEM_PRELOAD = 0x00080000,
            ALIGN_1BYTES = 0x00100000,
            ALIGN_2BYTES = 0x00200000,
            ALIGN_4BYTES = 0x00300000,
            ALIGN_8BYTES = 0x00400000,
            ALIGN_16BYTES = 0x00500000,
            ALIGN_32BYTES = 0x00600000,
            ALIGN_64BYTES = 0x00700000,
            ALIGN_128BYTES = 0x00800000,
            ALIGN_256BYTES = 0x00900000,
            ALIGN_512BYTES = 0x00A00000,
            ALIGN_1024BYTES = 0x00B00000,
            ALIGN_2048BYTES = 0x00C00000,
            ALIGN_4096BYTES = 0x00D00000,
            ALIGN_8192BYTES = 0x00E00000,
            ALIGN_MASK = 0x00F00000,
            LNK_NRELOC_OVFL = 0x01000000,
            MEM_DISCARDABLE = 0x02000000,
            MEM_NOT_CACHED = 0x04000000,
            MEM_NOT_PAGED = 0x08000000,
            MEM_SHARED = 0x10000000,
            MEM_EXECUTE = 0x20000000,
            MEM_READ = 0x40000000,
            MEM_WRITE = 0x80000000
        }


        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            [FieldOffset(0)]
            public UInt32 Characteristics;
            [FieldOffset(4)]
            public UInt32 TimeDateStamp;
            [FieldOffset(8)]
            public UInt16 MajorVersion;
            [FieldOffset(10)]
            public UInt16 MinorVersion;
            [FieldOffset(12)]
            public UInt32 Name;
            [FieldOffset(16)]
            public UInt32 Base;
            [FieldOffset(20)]
            public UInt32 NumberOfFunctions;
            [FieldOffset(24)]
            public UInt32 NumberOfNames;
            [FieldOffset(28)]
            public UInt32 AddressOfFunctions;
            [FieldOffset(32)]
            public UInt32 AddressOfNames;
            [FieldOffset(36)]
            public UInt32 AddressOfOrdinals;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PE_META_DATA
        {
            public UInt32 Pe;
            public Boolean Is32Bit;
            public IMAGE_FILE_HEADER ImageFileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptHeader64;
            public IMAGE_SECTION_HEADER[] Sections;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PE_MANUAL_MAP
        {
            public String DecoyModule;
            public IntPtr ModuleBase;
            public PE_META_DATA PEINFO;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA32
        {
            [FieldOffset(0)]
            public UInt32 ForwarderString;
            [FieldOffset(0)]
            public UInt32 Function;
            [FieldOffset(0)]
            public UInt32 Ordinal;
            [FieldOffset(0)]
            public UInt32 AddressOfData;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA64
        {
            [FieldOffset(0)]
            public UInt64 ForwarderString;
            [FieldOffset(0)]
            public UInt64 Function;
            [FieldOffset(0)]
            public UInt64 Ordinal;
            [FieldOffset(0)]
            public UInt64 AddressOfData;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ApiSetNamespace
        {
            [FieldOffset(0x0C)]
            public int Count;

            [FieldOffset(0x10)]
            public int EntryOffset;
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        public struct ApiSetNamespaceEntry
        {
            [FieldOffset(0x04)]
            public int NameOffset;

            [FieldOffset(0x08)]
            public int NameLength;

            [FieldOffset(0x10)]
            public int ValueOffset;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ApiSetValueEntry
        {
            [FieldOffset(0x0C)]
            public int ValueOffset;

            [FieldOffset(0x10)]
            public int ValueCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public Native.LIST_ENTRY InLoadOrderLinks;
            public Native.LIST_ENTRY InMemoryOrderLinks;
            public Native.LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public UInt32 SizeOfImage;
            public Native.UNICODE_STRING FullDllName;
            public Native.UNICODE_STRING BaseDllName;
        }
    }//end class

    /// <summary>
    /// Class for manually mapping PEs.
    /// </summary>
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

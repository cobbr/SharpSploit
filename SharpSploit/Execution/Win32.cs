// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace SharpSploit.Execution
{
    /// <summary>
    /// Win32 is a library of enums and structures for Win32 API functions.
    /// </summary>
    /// <remarks>
    /// A majority of this library is adapted from signatures found at www.pinvoke.net.
    /// </remarks>
    public static class Win32
    {
        public static class Kernel32
        {
            public static uint MEM_COMMIT = 0x1000;
            public static uint MEM_RESERVE = 0x2000;
            public static uint MEM_RESET = 0x80000;
            public static uint MEM_RESET_UNDO = 0x1000000;
            public static uint MEM_LARGE_PAGES = 0x20000000;
            public static uint MEM_PHYSICAL = 0x400000;
            public static uint MEM_TOP_DOWN = 0x100000;
            public static uint MEM_WRITE_WATCH = 0x200000;
            public static uint MEM_COALESCE_PLACEHOLDERS = 0x1;
            public static uint MEM_PRESERVE_PLACEHOLDER = 0x2;
            public static uint MEM_DECOMMIT = 0x4000;
            public static uint MEM_RELEASE = 0x8000;

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_BASE_RELOCATION
            {
                public uint VirtualAdress;
                public uint SizeOfBlock;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_IMPORT_DESCRIPTOR
            {
                public uint OriginalFirstThunk;
                public uint TimeDateStamp;
                public uint ForwarderChain;
                public uint Name;
                public uint FirstThunk;
            }

            public struct SYSTEM_INFO
            {
                public ushort wProcessorArchitecture;
                public ushort wReserved;
                public uint dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public UIntPtr dwActiveProcessorMask;
                public uint dwNumberOfProcessors;
                public uint dwProcessorType;
                public uint dwAllocationGranularity;
                public ushort wProcessorLevel;
                public ushort wProcessorRevision;
            };

            public enum Platform
            {
                x86,
                x64,
                IA64,
                Unknown
            }

            [Flags]
            public enum ProcessAccessFlags : UInt32
            {
                // https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
                PROCESS_ALL_ACCESS = 0x001F0FFF,
                PROCESS_CREATE_PROCESS = 0x0080,
                PROCESS_CREATE_THREAD = 0x0002,
                PROCESS_DUP_HANDLE = 0x0040,
                PROCESS_QUERY_INFORMATION = 0x0400,
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
                PROCESS_SET_INFORMATION = 0x0200,
                PROCESS_SET_QUOTA = 0x0100,
                PROCESS_SUSPEND_RESUME = 0x0800,
                PROCESS_TERMINATE = 0x0001,
                PROCESS_VM_OPERATION = 0x0008,
                PROCESS_VM_READ = 0x0010,
                PROCESS_VM_WRITE = 0x0020,
                SYNCHRONIZE = 0x00100000
            }

            [Flags]
            public enum FileAccessFlags : UInt32
            {
                DELETE = 0x10000,
                FILE_READ_DATA = 0x1,
                FILE_READ_ATTRIBUTES = 0x80,
                FILE_READ_EA = 0x8,
                READ_CONTROL = 0x20000,
                FILE_WRITE_DATA = 0x2,
                FILE_WRITE_ATTRIBUTES = 0x100,
                FILE_WRITE_EA = 0x10,
                FILE_APPEND_DATA = 0x4,
                WRITE_DAC = 0x40000,
                WRITE_OWNER = 0x80000,
                SYNCHRONIZE = 0x100000,
                FILE_EXECUTE = 0x20
            }

            [Flags]
            public enum FileShareFlags : UInt32
            {
                FILE_SHARE_NONE = 0x0,
                FILE_SHARE_READ = 0x1,
                FILE_SHARE_WRITE = 0x2,
                FILE_SHARE_DELETE = 0x4
            }

            [Flags]
            public enum FileOpenFlags : UInt32
            {
                FILE_DIRECTORY_FILE = 0x1,
                FILE_WRITE_THROUGH = 0x2,
                FILE_SEQUENTIAL_ONLY = 0x4,
                FILE_NO_INTERMEDIATE_BUFFERING = 0x8,
                FILE_SYNCHRONOUS_IO_ALERT = 0x10,
                FILE_SYNCHRONOUS_IO_NONALERT = 0x20,
                FILE_NON_DIRECTORY_FILE = 0x40,
                FILE_CREATE_TREE_CONNECTION = 0x80,
                FILE_COMPLETE_IF_OPLOCKED = 0x100,
                FILE_NO_EA_KNOWLEDGE = 0x200,
                FILE_OPEN_FOR_RECOVERY = 0x400,
                FILE_RANDOM_ACCESS = 0x800,
                FILE_DELETE_ON_CLOSE = 0x1000,
                FILE_OPEN_BY_FILE_ID = 0x2000,
                FILE_OPEN_FOR_BACKUP_INTENT = 0x4000,
                FILE_NO_COMPRESSION = 0x8000
            }

            [Flags]
            public enum StandardRights : uint
            {
                Delete = 0x00010000,
                ReadControl = 0x00020000,
                WriteDac = 0x00040000,
                WriteOwner = 0x00080000,
                Synchronize = 0x00100000,
                Required = 0x000f0000,
                Read = ReadControl,
                Write = ReadControl,
                Execute = ReadControl,
                All = 0x001f0000,

                SpecificRightsAll = 0x0000ffff,
                AccessSystemSecurity = 0x01000000,
                MaximumAllowed = 0x02000000,
                GenericRead = 0x80000000,
                GenericWrite = 0x40000000,
                GenericExecute = 0x20000000,
                GenericAll = 0x10000000
            }

            [Flags]
            public enum ThreadAccess : uint
            {
                Terminate = 0x0001,
                SuspendResume = 0x0002,
                Alert = 0x0004,
                GetContext = 0x0008,
                SetContext = 0x0010,
                SetInformation = 0x0020,
                QueryInformation = 0x0040,
                SetThreadToken = 0x0080,
                Impersonate = 0x0100,
                DirectImpersonation = 0x0200,
                SetLimitedInformation = 0x0400,
                QueryLimitedInformation = 0x0800,
                All = StandardRights.Required | StandardRights.Synchronize | 0x3ff
            }
        }

        public static class User32
        {
            public static int WH_KEYBOARD_LL { get; } = 13;
            public static int WM_KEYDOWN { get; } = 0x0100;

            public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
        }

        public static class Netapi32
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_USERS_INFO_0
            {
                [MarshalAs(UnmanagedType.LPWStr)] internal string name;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LOCALGROUP_USERS_INFO_1
            {
                [MarshalAs(UnmanagedType.LPWStr)] public string name;
                [MarshalAs(UnmanagedType.LPWStr)] public string comment;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_MEMBERS_INFO_2
            {
                public IntPtr lgrmi2_sid;
                public int lgrmi2_sidusage;
                [MarshalAs(UnmanagedType.LPWStr)] public string lgrmi2_domainandname;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct WKSTA_USER_INFO_1
            {
                public string wkui1_username;
                public string wkui1_logon_domain;
                public string wkui1_oth_domains;
                public string wkui1_logon_server;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SESSION_INFO_10
            {
                public string sesi10_cname;
                public string sesi10_username;
                public int sesi10_time;
                public int sesi10_idle_time;
            }

            public enum SID_NAME_USE : UInt16
            {
                SidTypeUser = 1,
                SidTypeGroup = 2,
                SidTypeDomain = 3,
                SidTypeAlias = 4,
                SidTypeWellKnownGroup = 5,
                SidTypeDeletedAccount = 6,
                SidTypeInvalid = 7,
                SidTypeUnknown = 8,
                SidTypeComputer = 9
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct SHARE_INFO_1
            {
                public string shi1_netname;
                public uint shi1_type;
                public string shi1_remark;

                public SHARE_INFO_1(string netname, uint type, string remark)
                {
                    this.shi1_netname = netname;
                    this.shi1_type = type;
                    this.shi1_remark = remark;
                }
            }
        }

        public static class Advapi32
        {

            // http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
            public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
            public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
            public const UInt32 TOKEN_DUPLICATE = 0x0002;
            public const UInt32 TOKEN_IMPERSONATE = 0x0004;
            public const UInt32 TOKEN_QUERY = 0x0008;
            public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
            public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
            public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
            public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
            public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
            public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID);
            public const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);

            // https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
            [Flags]
            public enum CREATION_FLAGS : uint
            {
                NONE = 0x00000000,
                DEBUG_PROCESS = 0x00000001,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                CREATE_SUSPENDED = 0x00000004,
                DETACHED_PROCESS = 0x00000008,
                CREATE_NEW_CONSOLE = 0x00000010,
                NORMAL_PRIORITY_CLASS = 0x00000020,
                IDLE_PRIORITY_CLASS = 0x00000040,
                HIGH_PRIORITY_CLASS = 0x00000080,
                REALTIME_PRIORITY_CLASS = 0x00000100,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                CREATE_FORCEDOS = 0x00002000,
                BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
                ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
                INHERIT_PARENT_AFFINITY = 0x00010000,
                INHERIT_CALLER_PRIORITY = 0x00020000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
                PROCESS_MODE_BACKGROUND_END = 0x00200000,
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NO_WINDOW = 0x08000000,
                PROFILE_USER = 0x10000000,
                PROFILE_KERNEL = 0x20000000,
                PROFILE_SERVER = 0x40000000,
                CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
            }

            [Flags]
            public enum LOGON_FLAGS
            {
                NONE = 0x00000000,
                LOGON_WITH_PROFILE = 0x00000001,
                LOGON_NETCREDENTIALS_ONLY = 0x00000002
            }

            public enum LOGON_TYPE
            {
                LOGON32_LOGON_INTERACTIVE = 2,
                LOGON32_LOGON_NETWORK,
                LOGON32_LOGON_BATCH,
                LOGON32_LOGON_SERVICE,
                LOGON32_LOGON_UNLOCK = 7,
                LOGON32_LOGON_NETWORK_CLEARTEXT,
                LOGON32_LOGON_NEW_CREDENTIALS
            }

            public enum LOGON_PROVIDER
            {
                LOGON32_PROVIDER_DEFAULT,
                LOGON32_PROVIDER_WINNT35,
                LOGON32_PROVIDER_WINNT40,
                LOGON32_PROVIDER_WINNT50
            }

            [Flags]
            public enum SCM_ACCESS : uint
            {
                SC_MANAGER_CONNECT = 0x00001,
                SC_MANAGER_CREATE_SERVICE = 0x00002,
                SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
                SC_MANAGER_LOCK = 0x00008,
                SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
                SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,

                SC_MANAGER_ALL_ACCESS = ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                    SC_MANAGER_CONNECT |
                    SC_MANAGER_CREATE_SERVICE |
                    SC_MANAGER_ENUMERATE_SERVICE |
                    SC_MANAGER_LOCK |
                    SC_MANAGER_QUERY_LOCK_STATUS |
                    SC_MANAGER_MODIFY_BOOT_CONFIG,

                GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                    SC_MANAGER_ENUMERATE_SERVICE |
                    SC_MANAGER_QUERY_LOCK_STATUS,

                GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                    SC_MANAGER_CREATE_SERVICE |
                    SC_MANAGER_MODIFY_BOOT_CONFIG,

                GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                    SC_MANAGER_CONNECT | SC_MANAGER_LOCK,

                GENERIC_ALL = SC_MANAGER_ALL_ACCESS,
            }

            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F
            }

            [Flags]
            public enum SERVICE_ACCESS : uint
            {
                SERVICE_QUERY_CONFIG = 0x00001,
                SERVICE_CHANGE_CONFIG = 0x00002,
                SERVICE_QUERY_STATUS = 0x00004,
                SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
                SERVICE_START = 0x00010,
                SERVICE_STOP = 0x00020,
                SERVICE_PAUSE_CONTINUE = 0x00040,
                SERVICE_INTERROGATE = 0x00080,
                SERVICE_USER_DEFINED_CONTROL = 0x00100,

                SERVICE_ALL_ACCESS = (ACCESS_MASK.STANDARD_RIGHTS_REQUIRED |
                    SERVICE_QUERY_CONFIG |
                    SERVICE_CHANGE_CONFIG |
                    SERVICE_QUERY_STATUS |
                    SERVICE_ENUMERATE_DEPENDENTS |
                    SERVICE_START |
                    SERVICE_STOP |
                    SERVICE_PAUSE_CONTINUE |
                    SERVICE_INTERROGATE |
                    SERVICE_USER_DEFINED_CONTROL),

                GENERIC_READ = ACCESS_MASK.STANDARD_RIGHTS_READ |
                    SERVICE_QUERY_CONFIG |
                    SERVICE_QUERY_STATUS |
                    SERVICE_INTERROGATE |
                    SERVICE_ENUMERATE_DEPENDENTS,

                GENERIC_WRITE = ACCESS_MASK.STANDARD_RIGHTS_WRITE |
                    SERVICE_CHANGE_CONFIG,

                GENERIC_EXECUTE = ACCESS_MASK.STANDARD_RIGHTS_EXECUTE |
                    SERVICE_START |
                    SERVICE_STOP |
                    SERVICE_PAUSE_CONTINUE |
                    SERVICE_USER_DEFINED_CONTROL,

                ACCESS_SYSTEM_SECURITY = ACCESS_MASK.ACCESS_SYSTEM_SECURITY,
                DELETE = ACCESS_MASK.DELETE,
                READ_CONTROL = ACCESS_MASK.READ_CONTROL,
                WRITE_DAC = ACCESS_MASK.WRITE_DAC,
                WRITE_OWNER = ACCESS_MASK.WRITE_OWNER,
            }

            [Flags]
            public enum SERVICE_TYPE : uint
            {
                SERVICE_KERNEL_DRIVER = 0x00000001,
                SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
                SERVICE_WIN32_OWN_PROCESS = 0x00000010,
                SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
                SERVICE_INTERACTIVE_PROCESS = 0x00000100,
            }

            public enum SERVICE_START : uint
            {
                SERVICE_BOOT_START = 0x00000000,
                SERVICE_SYSTEM_START = 0x00000001,
                SERVICE_AUTO_START = 0x00000002,
                SERVICE_DEMAND_START = 0x00000003,
                SERVICE_DISABLED = 0x00000004,
            }

            public enum SERVICE_ERROR
            {
                SERVICE_ERROR_IGNORE = 0x00000000,
                SERVICE_ERROR_NORMAL = 0x00000001,
                SERVICE_ERROR_SEVERE = 0x00000002,
                SERVICE_ERROR_CRITICAL = 0x00000003,
            }
        }

        public static class Dbghelp
        {
            public enum MINIDUMP_TYPE
            {
                MiniDumpNormal = 0x00000000,
                MiniDumpWithDataSegs = 0x00000001,
                MiniDumpWithFullMemory = 0x00000002,
                MiniDumpWithHandleData = 0x00000004,
                MiniDumpFilterMemory = 0x00000008,
                MiniDumpScanMemory = 0x00000010,
                MiniDumpWithUnloadedModules = 0x00000020,
                MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
                MiniDumpFilterModulePaths = 0x00000080,
                MiniDumpWithProcessThreadData = 0x00000100,
                MiniDumpWithPrivateReadWriteMemory = 0x00000200,
                MiniDumpWithoutOptionalData = 0x00000400,
                MiniDumpWithFullMemoryInfo = 0x00000800,
                MiniDumpWithThreadInfo = 0x00001000,
                MiniDumpWithCodeSegs = 0x00002000,
                MiniDumpWithoutAuxiliaryState = 0x00004000,
                MiniDumpWithFullAuxiliaryState = 0x00008000,
                MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
                MiniDumpIgnoreInaccessibleMemory = 0x00020000,
                MiniDumpWithTokenInformation = 0x00040000,
                MiniDumpWithModuleHeaders = 0x00080000,
                MiniDumpFilterTriage = 0x00100000,
                MiniDumpValidTypeFlags = 0x001fffff
            }
        }

        public class WinBase
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct _SYSTEM_INFO
            {
                public UInt16 wProcessorArchitecture;
                public UInt16 wReserved;
                public UInt32 dwPageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public IntPtr dwActiveProcessorMask;
                public UInt32 dwNumberOfProcessors;
                public UInt32 dwProcessorType;
                public UInt32 dwAllocationGranularity;
                public UInt16 wProcessorLevel;
                public UInt16 wProcessorRevision;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SECURITY_ATTRIBUTES
            {
                UInt32 nLength;
                IntPtr lpSecurityDescriptor;
                Boolean bInheritHandle;
            };
        }

        public class WinNT
        {
            public const UInt32 PAGE_NOACCESS = 0x01;
            public const UInt32 PAGE_READONLY = 0x02;
            public const UInt32 PAGE_READWRITE = 0x04;
            public const UInt32 PAGE_WRITECOPY = 0x08;
            public const UInt32 PAGE_EXECUTE = 0x10;
            public const UInt32 PAGE_EXECUTE_READ = 0x20;
            public const UInt32 PAGE_EXECUTE_READWRITE = 0x40;
            public const UInt32 PAGE_EXECUTE_WRITECOPY = 0x80;
            public const UInt32 PAGE_GUARD = 0x100;
            public const UInt32 PAGE_NOCACHE = 0x200;
            public const UInt32 PAGE_WRITECOMBINE = 0x400;
            public const UInt32 PAGE_TARGETS_INVALID = 0x40000000;
            public const UInt32 PAGE_TARGETS_NO_UPDATE = 0x40000000;

            public const UInt32 SEC_COMMIT = 0x08000000;
            public const UInt32 SEC_IMAGE = 0x1000000;
            public const UInt32 SEC_IMAGE_NO_EXECUTE = 0x11000000;
            public const UInt32 SEC_LARGE_PAGES = 0x80000000;
            public const UInt32 SEC_NOCACHE = 0x10000000;
            public const UInt32 SEC_RESERVE = 0x4000000;
            public const UInt32 SEC_WRITECOMBINE = 0x40000000;

            public const UInt32 SE_PRIVILEGE_ENABLED = 0x2;
            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x4;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

            public const UInt64 SE_GROUP_ENABLED = 0x00000004L;
            public const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
            public const UInt64 SE_GROUP_INTEGRITY = 0x00000020L;
            public const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
            public const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
            public const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
            public const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
            public const UInt64 SE_GROUP_OWNER = 0x00000008L;
            public const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
            public const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

            public enum _SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum _TOKEN_ELEVATION_TYPE
            {
                TokenElevationTypeDefault = 1,
                TokenElevationTypeFull,
                TokenElevationTypeLimited
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION32
            {
                public UInt32 BaseAddress;
                public UInt32 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _MEMORY_BASIC_INFORMATION64
            {
                public UInt64 BaseAddress;
                public UInt64 AllocationBase;
                public UInt32 AllocationProtect;
                public UInt32 __alignment1;
                public UInt64 RegionSize;
                public UInt32 State;
                public UInt32 Protect;
                public UInt32 Type;
                public UInt32 __alignment2;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID_AND_ATTRIBUTES
            {
                public _LUID Luid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LUID
            {
                public UInt32 LowPart;
                public UInt32 HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_STATISTICS
            {
                public _LUID TokenId;
                public _LUID AuthenticationId;
                public UInt64 ExpirationTime;
                public TOKEN_TYPE TokenType;
                public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
                public UInt32 DynamicCharged;
                public UInt32 DynamicAvailable;
                public UInt32 GroupCount;
                public UInt32 PrivilegeCount;
                public _LUID ModifiedId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_PRIVILEGES
            {
                public UInt32 PrivilegeCount;
                public _LUID_AND_ATTRIBUTES Privileges;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_MANDATORY_LABEL
            {
                public _SID_AND_ATTRIBUTES Label;
            }

            public struct _SID
            {
                public byte Revision;
                public byte SubAuthorityCount;
                public WinNT._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public ulong[] SubAuthority;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_IDENTIFIER_AUTHORITY
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _SID_AND_ATTRIBUTES
            {
                public IntPtr Sid;
                public UInt32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _PRIVILEGE_SET
            {
                public UInt32 PrivilegeCount;
                public UInt32 Control;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public _LUID_AND_ATTRIBUTES[] Privilege;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _TOKEN_USER
            {
                public _SID_AND_ATTRIBUTES User;
            }

            public enum _SID_NAME_USE
            {
                SidTypeUser = 1,
                SidTypeGroup,
                SidTypeDomain,
                SidTypeAlias,
                SidTypeWellKnownGroup,
                SidTypeDeletedAccount,
                SidTypeInvalid,
                SidTypeUnknown,
                SidTypeComputer,
                SidTypeLabel
            }

            public enum _TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                TokenIsAppContainer,
                TokenCapabilities,
                TokenAppContainerSid,
                TokenAppContainerNumber,
                TokenUserClaimAttributes,
                TokenDeviceClaimAttributes,
                TokenRestrictedUserClaimAttributes,
                TokenRestrictedDeviceClaimAttributes,
                TokenDeviceGroups,
                TokenRestrictedDeviceGroups,
                TokenSecurityAttributes,
                TokenIsRestricted,
                MaxTokenInfoClass
            }

            // http://www.pinvoke.net/default.aspx/Enums.ACCESS_MASK
            [Flags]
            public enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,
                STANDARD_RIGHTS_ALL = 0x001F0000,
                SPECIFIC_RIGHTS_ALL = 0x0000FFF,
                ACCESS_SYSTEM_SECURITY = 0x01000000,
                MAXIMUM_ALLOWED = 0x02000000,
                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL_ACCESS = 0x0000037F,

                SECTION_ALL_ACCESS = 0x10000000,
                SECTION_QUERY = 0x0001,
                SECTION_MAP_WRITE = 0x0002,
                SECTION_MAP_READ = 0x0004,
                SECTION_MAP_EXECUTE = 0x0008,
                SECTION_EXTEND_SIZE = 0x0010
        };
        }

        public class ProcessThreadsAPI
        {
            [Flags]
            internal enum STARTF : uint
            {
                STARTF_USESHOWWINDOW = 0x00000001,
                STARTF_USESIZE = 0x00000002,
                STARTF_USEPOSITION = 0x00000004,
                STARTF_USECOUNTCHARS = 0x00000008,
                STARTF_USEFILLATTRIBUTE = 0x00000010,
                STARTF_RUNFULLSCREEN = 0x00000020,
                STARTF_FORCEONFEEDBACK = 0x00000040,
                STARTF_FORCEOFFFEEDBACK = 0x00000080,
                STARTF_USESTDHANDLES = 0x00000100,
            }

            // https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFO
            {
                public UInt32 cb;
                public String lpReserved;
                public String lpDesktop;
                public String lpTitle;
                public UInt32 dwX;
                public UInt32 dwY;
                public UInt32 dwXSize;
                public UInt32 dwYSize;
                public UInt32 dwXCountChars;
                public UInt32 dwYCountChars;
                public UInt32 dwFillAttribute;
                public UInt32 dwFlags;
                public UInt16 wShowWindow;
                public UInt16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            };

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _STARTUPINFOEX
            {
                _STARTUPINFO StartupInfo;
                // PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
            };

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct _PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public UInt32 dwProcessId;
                public UInt32 dwThreadId;
            };
        }

        public class WinCred
        {
#pragma warning disable 0618
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct _CREDENTIAL
            {
                public CRED_FLAGS Flags;
                public UInt32 Type;
                public IntPtr TargetName;
                public IntPtr Comment;
                public FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public UInt32 Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public IntPtr TargetAlias;
                public IntPtr UserName;
            }
#pragma warning restore 0618

            public enum CRED_FLAGS : uint
            {
                NONE = 0x0,
                PROMPT_NOW = 0x2,
                USERNAME_TARGET = 0x4
            }

            public enum CRED_PERSIST : uint
            {
                Session = 1,
                LocalMachine,
                Enterprise
            }

            public enum CRED_TYPE : uint
            {
                Generic = 1,
                DomainPassword,
                DomainCertificate,
                DomainVisiblePassword,
                GenericCertificate,
                DomainExtended,
                Maximum,
                MaximumEx = Maximum + 1000,
            }
        }

        public class Secur32
        {
            public struct _SECURITY_LOGON_SESSION_DATA
            {
                public UInt32 Size;
                public WinNT._LUID LoginID;
                public _LSA_UNICODE_STRING Username;
                public _LSA_UNICODE_STRING LoginDomain;
                public _LSA_UNICODE_STRING AuthenticationPackage;
                public UInt32 LogonType;
                public UInt32 Session;
                public IntPtr pSid;
                public UInt64 LoginTime;
                public _LSA_UNICODE_STRING LogonServer;
                public _LSA_UNICODE_STRING DnsDomainName;
                public _LSA_UNICODE_STRING Upn;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct _LSA_UNICODE_STRING
            {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }
        }  
    }
}
// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Runtime.InteropServices;
using MW32 = Microsoft.Win32;

namespace SharpSploit.Execution
{
    /// <summary>
    /// Win32 is a library of PInvoke signatures for Win32 API functions.
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

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentThread();

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            public static extern IntPtr GetProcAddress(
                IntPtr hModule,
                string procName
            );

            [DllImport("kernel32.dll")]
            public static extern void GetSystemInfo(
                out WinBase._SYSTEM_INFO lpSystemInfo
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GlobalSize(
                IntPtr hMem
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool IsWow64Process(
                IntPtr hProcess,
                out bool Wow64Process
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(
                ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean OpenProcessToken(
                IntPtr hProcess,
                UInt32 dwDesiredAccess,
                out IntPtr hToken
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean OpenThreadToken(
                IntPtr ThreadHandle,
                UInt32 DesiredAccess,
                Boolean OpenAsSelf,
                ref IntPtr TokenHandle
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenThread(
                UInt32 dwDesiredAccess,
                Boolean bInheritHandle,
                UInt32 dwThreadId
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean ReadProcessMemory(
                IntPtr hProcess,
                UInt32 lpBaseAddress,
                IntPtr lpBuffer,
                UInt32 nSize,
                ref UInt32 lpNumberOfBytesRead
            );

            [DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory")]
            public static extern Boolean ReadProcessMemory64(
                IntPtr hProcess,
                UInt64 lpBaseAddress,
                IntPtr lpBuffer,
                UInt64 nSize,
                ref UInt32 lpNumberOfBytesRead
            );

            [DllImport("kernel32.dll")]
            public static extern UInt32 SearchPath(
                String lpPath,
                String lpFileName,
                String lpExtension,
                UInt32 nBufferLength,
                [MarshalAs(UnmanagedType.LPTStr)]
                StringBuilder lpBuffer,
                ref IntPtr lpFilePart
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx32(
                IntPtr hProcess,
                IntPtr lpAddress,
                out WinNT._MEMORY_BASIC_INFORMATION32 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx64(
                IntPtr hProcess,
                IntPtr lpAddress,
                out WinNT._MEMORY_BASIC_INFORMATION64 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll")]
            public static extern IntPtr VirtualAlloc(
                IntPtr lpStartAddr,
                uint size,
                uint flAllocationType,
                uint flProtect
            );

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtect(
                IntPtr lpAddress,
                UIntPtr dwSize,
                uint flNewProtect,
                out uint lpflOldProtect
            );

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern IntPtr LoadLibrary(
                string lpFileName
            );

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateThread(
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr param,
                uint dwCreationFlags,
                IntPtr lpThreadId
            );

            [DllImport("kernel32.dll")]
            public static extern UInt32 WaitForSingleObject(
                IntPtr hHandle,
                UInt32 dwMilliseconds
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr LocalFree(
                IntPtr hMem
            );

            [DllImport("kernel32.dll")]
            public static extern Boolean CloseHandle(
                IntPtr hProcess
            );

            [DllImport("kernel32.dll")]
            public static extern void GetNativeSystemInfo(
                ref SYSTEM_INFO lpSystemInfo
            );

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
        }

        public static class User32
        {
            public static int WH_KEYBOARD_LL { get; } = 13;
            public static int WM_KEYDOWN { get; } = 0x0100;

            public delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr CallNextHookEx(
                IntPtr hhk,
                int nCode,
                IntPtr wParam,
                IntPtr lParam
            );

            [DllImport("user32.dll", CharSet = CharSet.Auto,  SetLastError = true)]
            public static extern IntPtr GetForegroundWindow();

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetWindowText(
                IntPtr hWnd,
                StringBuilder text,
                int count
            );

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr SetWindowsHookEx(
                int idHook,
                HookProc lpfn,
                IntPtr hMod,
                uint dwThreadId
            );

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool UnhookWindowsHookEx(IntPtr hhk);

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetWindowTextLength(IntPtr hWnd);

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern short GetKeyState(int nVirtKey);
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

            [DllImport("netapi32.dll")]
            public static extern int NetLocalGroupEnum(
                [MarshalAs(UnmanagedType.LPWStr)] string servername,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll")]
            public static extern int NetLocalGroupGetMembers(
                [MarshalAs(UnmanagedType.LPWStr)] string servername,
                [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern int NetWkstaUserEnum(
                string servername,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", SetLastError = true)]
            public static extern int NetSessionEnum(
                [In, MarshalAs(UnmanagedType.LPWStr)] string ServerName,
                [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
                [In, MarshalAs(UnmanagedType.LPWStr)] string UserName,
                int level,
                out IntPtr bufptr,
                int prefmaxlen,
                out int entriesread,
                out int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", SetLastError = true)]
            public static extern int NetApiBufferFree(IntPtr Buffer);
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


            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AdjustTokenPrivileges(
                IntPtr TokenHandle,
                Boolean DisableAllPrivileges,
                ref WinNT._TOKEN_PRIVILEGES NewState,
                UInt32 BufferLengthInBytes,
                ref WinNT._TOKEN_PRIVILEGES PreviousState,
                out UInt32 ReturnLengthInBytes
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AllocateAndInitializeSid(
                ref WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount,
                Int32 dwSubAuthority0,
                Int32 dwSubAuthority1,
                Int32 dwSubAuthority2,
                Int32 dwSubAuthority3,
                Int32 dwSubAuthority4,
                Int32 dwSubAuthority5,
                Int32 dwSubAuthority6,
                Int32 dwSubAuthority7,
                out IntPtr pSid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AllocateAndInitializeSid(
                ref WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount,
                Int32 dwSubAuthority0,
                Int32 dwSubAuthority1,
                Int32 dwSubAuthority2,
                Int32 dwSubAuthority3,
                Int32 dwSubAuthority4,
                Int32 dwSubAuthority5,
                Int32 dwSubAuthority6,
                Int32 dwSubAuthority7,
                ref WinNT._SID pSid
            );

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool ConvertSidToStringSid(
                IntPtr Sid,
                out IntPtr StringSid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessAsUser(
                IntPtr hToken,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                ref WinBase._SECURITY_ATTRIBUTES lpProcessAttributes,
                ref WinBase._SECURITY_ATTRIBUTES lpThreadAttributes,
                Boolean bInheritHandles,
                CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessAsUserW(
                IntPtr hToken,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                Boolean bInheritHandles,
                CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessWithLogonW(
                String userName,
                String domain,
                String password,
                int logonFlags,
                String applicationName,
                String commandLine,
                int creationFlags,
                IntPtr environment,
                String currentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO startupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION processInformation
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessWithTokenW(
                IntPtr hToken,
                LOGON_FLAGS dwLogonFlags,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredEnumerateW(
                String Filter,
                Int32 Flags,
                out Int32 Count,
                out IntPtr Credentials
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredFree(
                IntPtr Buffer
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredReadW(
                String target,
                WinCred.CRED_TYPE type,
                Int32 reservedFlag,
                out IntPtr credentialPtr
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredWriteW(
                ref WinCred._CREDENTIAL userCredential,
                UInt32 flags
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean DuplicateTokenEx(
                IntPtr hExistingToken,
                UInt32 dwDesiredAccess,
                ref WinBase._SECURITY_ATTRIBUTES lpTokenAttributes,
                WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                WinNT.TOKEN_TYPE TokenType,
                out IntPtr phNewToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean GetTokenInformation(
                IntPtr TokenHandle,
                WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass,
                IntPtr TokenInformation,
                UInt32 TokenInformationLength,
                out UInt32 ReturnLength
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean GetTokenInformation(
                IntPtr TokenHandle,
                WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass,
                ref WinNT._TOKEN_STATISTICS TokenInformation,
                UInt32 TokenInformationLength,
                out UInt32 ReturnLength
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean ImpersonateLoggedOnUser(
                IntPtr hToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean ImpersonateSelf(
                WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LogonUserA(
                string lpszUsername,
                string lpszDomain,
                string lpszPassword,
                LOGON_TYPE dwLogonType,
                LOGON_PROVIDER dwLogonProvider,
                out IntPtr phToken
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern bool LookupAccountSid(
                String lpSystemName,
                //[MarshalAs(UnmanagedType.LPArray)] 
                IntPtr Sid,
                StringBuilder lpName,
                ref UInt32 cchName,
                StringBuilder ReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out WinNT._SID_NAME_USE peUse
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean LookupPrivilegeName(
                String lpSystemName,
                IntPtr lpLuid,
                StringBuilder lpName,
                ref Int32 cchName
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean LookupPrivilegeValue(
                String lpSystemName,
                String lpName,
                ref WinNT._LUID luid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean PrivilegeCheck(
                IntPtr ClientToken,
                WinNT._PRIVILEGE_SET RequiredPrivileges,
                out IntPtr pfResult
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern int RegOpenKeyEx(
                UIntPtr hKey,
                String subKey,
                Int32 ulOptions,
                Int32 samDesired,
                out UIntPtr hkResult
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern uint RegQueryValueEx(
                UIntPtr hKey,
                String lpValueName,
                Int32 lpReserved,
                ref MW32.RegistryValueKind lpType,
                IntPtr lpData,
                ref Int32 lpcbData
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Int32 RegQueryInfoKey(
                UIntPtr hKey,
                StringBuilder lpClass,
                ref UInt32 lpcchClass,
                IntPtr lpReserved,
                out UInt32 lpcSubkey,
                out UInt32 lpcchMaxSubkeyLen,
                out UInt32 lpcchMaxClassLen,
                out UInt32 lpcValues,
                out UInt32 lpcchMaxValueNameLen,
                out UInt32 lpcbMaxValueLen,
                IntPtr lpSecurityDescriptor,
                IntPtr lpftLastWriteTime
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean RevertToSelf();

            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms682434(v=vs.85).aspx
            [Flags]
            public enum CREATION_FLAGS
            {
                NONE = 0x0,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                CREATE_NEW_CONSOLE = 0x00000010,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SUSPENDED = 0x00000004,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000
            }

            [Flags]
            public enum LOGON_FLAGS
            {
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

            [DllImport("dbghelp.dll", SetLastError = true)]
            public static extern bool MiniDumpWriteDump(
                IntPtr hProcess,
                UInt32 ProcessId,
                SafeHandle hFile,
                MINIDUMP_TYPE DumpType,
                IntPtr ExceptionParam,
                IntPtr UserStreamParam,
                IntPtr CallbackParam
            );
        }

        public static class ActiveDs
        {
            [DllImport("activeds.dll")]
            public static extern IntPtr Init(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] string bstrADsPath
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr Set(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] string bstrADsPath
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr Get(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] ref string pbstrADsPath
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr InitEx(
                Int32 lnSetType,
                [MarshalAs(UnmanagedType.BStr)] string bstrADsPath,
                [MarshalAs(UnmanagedType.BStr)] string bstrUserID,
                [MarshalAs(UnmanagedType.BStr)] string bstrDomain,
                [MarshalAs(UnmanagedType.BStr)] string bstrPassword
            );

            [DllImport("activeds.dll")]
            public static extern IntPtr put_ChaseReferral(
                Int32 lnChangeReferral
            );
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
            public enum ACCESS_MASK : UInt32
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
            //https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
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
            [DllImport("Secur32.dll", SetLastError = false)]
            public static extern uint LsaGetLogonSessionData(
                IntPtr luid,
                out IntPtr ppLogonSessionData
            );

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

        public class NtDll
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
                ref WinNT._TOKEN_MANDATORY_LABEL TokenInformation,
                Int32 TokenInformationLength
            );

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle
            );

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern NTSTATUS NtMapViewOfSection(
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
            public static extern NTSTATUS NtUnmapViewOfSection(
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
            /// <param name="creationFlags"></param>
            /// <param name="stackZeroBits"></param>
            /// <param name="sizeOfStack"></param>
            /// <param name="maximumStackSize"></param>
            /// <param name="attributeList"></param>
            /// <returns></returns>
            [DllImport("ntdll.dll")]
            public static extern IntPtr NtCreateThreadEx(
                out IntPtr threadHandle,
                WinNT.ACCESS_MASK desiredAccess,
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
                PROCESSINFOCLASS pic,
                ref PROCESS_BASIC_INFORMATION pbi,
                int cb,
                out int pSize
            );

            public struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr ExitStatus;
                public IntPtr PebBaseAddress;
                public IntPtr AffinityMask;
                public IntPtr BasePriority;
                public UIntPtr UniqueProcessId;
                public int InheritedFromUniqueProcessId;

                public int Size
                {
                    get { return (int)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)); }
                }
            }

            public enum PROCESSINFOCLASS : int
            {
                ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
                ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
                ProcessIoCounters, // q: IO_COUNTERS
                ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
                ProcessTimes, // q: KERNEL_USER_TIMES
                ProcessBasePriority, // s: KPRIORITY
                ProcessRaisePriority, // s: ULONG
                ProcessDebugPort, // q: HANDLE
                ProcessExceptionPort, // s: HANDLE
                ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
                ProcessLdtInformation, // 10
                ProcessLdtSize,
                ProcessDefaultHardErrorMode, // qs: ULONG
                ProcessIoPortHandlers, // (kernel-mode only)
                ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
                ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
                ProcessUserModeIOPL,
                ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
                ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
                ProcessWx86Information,
                ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
                ProcessAffinityMask, // s: KAFFINITY
                ProcessPriorityBoost, // qs: ULONG
                ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
                ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
                ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
                ProcessWow64Information, // q: ULONG_PTR
                ProcessImageFileName, // q: UNICODE_STRING
                ProcessLUIDDeviceMapsEnabled, // q: ULONG
                ProcessBreakOnTermination, // qs: ULONG
                ProcessDebugObjectHandle, // 30, q: HANDLE
                ProcessDebugFlags, // qs: ULONG
                ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
                ProcessIoPriority, // qs: ULONG
                ProcessExecuteFlags, // qs: ULONG
                ProcessResourceManagement,
                ProcessCookie, // q: ULONG
                ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
                ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
                ProcessPagePriority, // q: ULONG
                ProcessInstrumentationCallback, // 40
                ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
                ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
                ProcessImageFileNameWin32, // q: UNICODE_STRING
                ProcessImageFileMapping, // q: HANDLE (input)
                ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
                ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
                ProcessGroupInformation, // q: USHORT[]
                ProcessTokenVirtualizationEnabled, // s: ULONG
                ProcessConsoleHostProcess, // q: ULONG_PTR
                ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
                ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
                ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
                ProcessDynamicFunctionTableInformation,
                ProcessHandleCheckingMode,
                ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
                ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
                MaxProcessInfoClass
            };

            /// <summary>
            /// NT_CREATION_FLAGS is an undocumented enum. https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html
            /// </summary>
            public enum NT_CREATION_FLAGS : ulong
            {
                CREATE_SUSPENDED = 0x00000001,
                SKIP_THREAD_ATTACH = 0x00000002,
                HIDE_FROM_DEBUGGER = 0x00000004,
                HAS_SECURITY_DESCRIPTOR = 0x00000010,
                ACCESS_CHECK_IN_TARGET = 0x00000020,
                INITIAL_THREAD = 0x00000080
            }

            /// <summary>
            /// NTSTATUS is an undocument enum. https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
            /// https://www.pinvoke.net/default.aspx/Enums/NtStatus.html
            /// </summary>
            public enum NTSTATUS : uint
            {
                // Success
                Success = 0x00000000,
                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,
                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,
                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,
                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalidHandle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                ConflictingAddresses = 0xc0000018,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,

                MaximumNtStatus = 0xffffffff
            }
        }
    }
}
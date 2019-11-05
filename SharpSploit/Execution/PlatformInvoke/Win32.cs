// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Text;
using System.Runtime.InteropServices;

using MW32 = Microsoft.Win32;
using Execute = SharpSploit.Execution;

namespace SharpSploit.Execution.PlatformInvoke
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
                out Execute.Win32.WinBase._SYSTEM_INFO lpSystemInfo
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
                Execute.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
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
                out Execute.Win32.WinNT._MEMORY_BASIC_INFORMATION32 lpBuffer,
                UInt32 dwLength
            );

            [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
            public static extern Int32 VirtualQueryEx64(
                IntPtr hProcess,
                IntPtr lpAddress,
                out Execute.Win32.WinNT._MEMORY_BASIC_INFORMATION64 lpBuffer,
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
                ref Execute.Win32.Kernel32.SYSTEM_INFO lpSystemInfo
            );
        }

        public static class User32
        {
            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr CallNextHookEx(
                IntPtr hhk,
                int nCode,
                IntPtr wParam,
                IntPtr lParam
            );

            [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
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
                Execute.Win32.User32.HookProc lpfn,
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

            [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
            public static extern int NetShareEnum(
                StringBuilder ServerName,
                int level,
                ref IntPtr bufPtr,
                uint prefmaxlen,
                ref int entriesread,
                ref int totalentries,
                ref int resume_handle
            );

            [DllImport("netapi32.dll", SetLastError = true)]
            public static extern int NetApiBufferFree(IntPtr Buffer);
        }

        public static class Advapi32
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AdjustTokenPrivileges(
                IntPtr TokenHandle,
                Boolean DisableAllPrivileges,
                ref Execute.Win32.WinNT._TOKEN_PRIVILEGES NewState,
                UInt32 BufferLengthInBytes,
                ref Execute.Win32.WinNT._TOKEN_PRIVILEGES PreviousState,
                out UInt32 ReturnLengthInBytes
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean AllocateAndInitializeSid(
                ref Execute.Win32.WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
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
                ref Execute.Win32.WinNT._SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                byte nSubAuthorityCount,
                Int32 dwSubAuthority0,
                Int32 dwSubAuthority1,
                Int32 dwSubAuthority2,
                Int32 dwSubAuthority3,
                Int32 dwSubAuthority4,
                Int32 dwSubAuthority5,
                Int32 dwSubAuthority6,
                Int32 dwSubAuthority7,
                ref Execute.Win32.WinNT._SID pSid
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
                ref Execute.Win32.WinBase._SECURITY_ATTRIBUTES lpProcessAttributes,
                ref Execute.Win32.WinBase._SECURITY_ATTRIBUTES lpThreadAttributes,
                Boolean bInheritHandles,
                Execute.Win32.Advapi32.CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref Execute.Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out Execute.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CreateProcessAsUserW(
                IntPtr hToken,
                IntPtr lpApplicationName,
                IntPtr lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                Boolean bInheritHandles,
                Execute.Win32.Advapi32.CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                IntPtr lpCurrentDirectory,
                ref Execute.Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out Execute.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
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
                ref Execute.Win32.ProcessThreadsAPI._STARTUPINFO startupInfo,
                out Execute.Win32.ProcessThreadsAPI._PROCESS_INFORMATION processInformation
            );

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessWithTokenW(
                IntPtr hToken,
                Execute.Win32.Advapi32.LOGON_FLAGS dwLogonFlags,
                string lpApplicationName,
                string lpCommandLine,
                Execute.Win32.Advapi32.CREATION_FLAGS dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref Execute.Win32.ProcessThreadsAPI._STARTUPINFO lpStartupInfo,
                out Execute.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInfo
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
                Execute.Win32.WinCred.CRED_TYPE type,
                Int32 reservedFlag,
                out IntPtr credentialPtr
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean CredWriteW(
                ref Execute.Win32.WinCred._CREDENTIAL userCredential,
                UInt32 flags
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean DuplicateTokenEx(
                IntPtr hExistingToken,
                UInt32 dwDesiredAccess,
                ref Execute.Win32.WinBase._SECURITY_ATTRIBUTES lpTokenAttributes,
                Execute.Win32.WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                Execute.Win32.WinNT.TOKEN_TYPE TokenType,
                out IntPtr phNewToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean GetTokenInformation(
                IntPtr TokenHandle,
                Execute.Win32.WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass,
                IntPtr TokenInformation,
                UInt32 TokenInformationLength,
                out UInt32 ReturnLength
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean GetTokenInformation(
                IntPtr TokenHandle,
                Execute.Win32.WinNT._TOKEN_INFORMATION_CLASS TokenInformationClass,
                ref Execute.Win32.WinNT._TOKEN_STATISTICS TokenInformation,
                UInt32 TokenInformationLength,
                out UInt32 ReturnLength
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean ImpersonateLoggedOnUser(
                IntPtr hToken
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean ImpersonateSelf(
                Execute.Win32.WinNT._SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LogonUserA(
                string lpszUsername,
                string lpszDomain,
                string lpszPassword,
                Execute.Win32.Advapi32.LOGON_TYPE dwLogonType,
                Execute.Win32.Advapi32.LOGON_PROVIDER dwLogonProvider,
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
                out Execute.Win32.WinNT._SID_NAME_USE peUse
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
                ref Execute.Win32.WinNT._LUID luid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean PrivilegeCheck(
                IntPtr ClientToken,
                Execute.Win32.WinNT._PRIVILEGE_SET RequiredPrivileges,
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

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern IntPtr OpenSCManager(
                string machineName,
                string databaseName,
                Execute.Win32.Advapi32.SCM_ACCESS dwAccess
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern IntPtr OpenService(
                IntPtr hSCManager,
                string lpServiceName,
                Execute.Win32.Advapi32.SERVICE_ACCESS dwDesiredAccess
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern IntPtr CreateService(
                IntPtr hSCManager,
                string lpServiceName,
                string lpDisplayName,
                Execute.Win32.Advapi32.SERVICE_ACCESS dwDesiredAccess,
                Execute.Win32.Advapi32.SERVICE_TYPE dwServiceType,
                Execute.Win32.Advapi32.SERVICE_START dwStartType,
                Execute.Win32.Advapi32.SERVICE_ERROR dwErrorControl,
                string lpBinaryPathName,
                string lpLoadOrderGroup,
                string lpdwTagId,
                string lpDependencies,
                string lpServiceStartName,
                string lpPassword
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool DeleteService(
                IntPtr hService
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CloseServiceHandle(
                IntPtr hSCObject
            );
        }

        public static class Dbghelp
        {

            [DllImport("dbghelp.dll", SetLastError = true)]
            public static extern bool MiniDumpWriteDump(
                IntPtr hProcess,
                UInt32 ProcessId,
                SafeHandle hFile,
                Execute.Win32.Dbghelp.MINIDUMP_TYPE DumpType,
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

        public class Secur32
        {
            [DllImport("Secur32.dll", SetLastError = false)]
            public static extern uint LsaGetLogonSessionData(
                IntPtr luid,
                out IntPtr ppLogonSessionData
            );
        }
    }
}

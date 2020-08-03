# SharpSploit - Quick Command Reference

## SharpSploit.Credentials

### SharpSploit.Credentials.Mimikatz

* `Command()` - Loads the Mimikatz PE with `PE.Load()` and executes a chosen Mimikatz command.
* `LogonPasswords()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve plaintext passwords from LSASS. Equates to `Command("privilege::debug sekurlsa::logonPasswords")`. (Requires Admin)
* `SamDump()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve password hashes from the SAM database. Equates to `Command("privilege::debug lsadump::sam")`. (Requires Admin)
* `LsaSecrets()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve LSA secrets stored in registry. Equates to `Command("privilege::debug lsadump::secrets")`. (Requires Admin)
* `LsaCache()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve Domain Cached Credentials hashes from registry. Equates to `Command("privilege::debug lsadump::cache")`. (Requires Admin)
* `Wdigest()` - Loads the Mimikatz PE with `PE.Load()` and executes the Mimikatz command to retrieve Wdigest credentials from registry. Equates to `Command("sekurlsa::wdigest")`.
* `All()` - Loads the Mimikatz PE with `PE.Load()` and executes each of the above builtin, local credential dumping commands. (Requires Admin)
* `DCSync()` - Loads the Mimikatz PE with `PE.Load()` and executes the "dcsync" module to retrieve the NTLM hash of a specified (or all) Domain user. (Requires Domain Admin (or equivalent rights))
* `PassTheHash()` - Loads the Mimikatz PE with `PE.Load()` and executes the "pth" module to start a new process as a user using an NTLM password hash for authentication. (Requires Admin)

### SharpSploit.Credentials.Tokens

* `WhoAmI()` - Gets the username of the currently used/impersonated token.
* `ImpersonateUser()` - Impersonate the token of a process owned by the specified user. Used to execute subsequent commands as the specified user. (Requires Admin)
* `ImpersonateProcess()` - Impersonate the token of the specified process. Used to execute subsequent commands as the user associated with the token of the specified process. (Requires Admin)
* `GetSystem()` - Impersonate the SYSTEM user. Equates to `ImpersonateUser("NT AUTHORITY\SYSTEM")`. (Requires Admin)
* `BypassUAC()` - Bypasses UAC through token duplication and spawns a specified process with high integrity. (Requires Admin)
* `RunAs()` - Makes a new token to run a specified function as a specified user with a specified password. Automatically calls `RevertToSelf()` after executing the function.
* `MakeToken()` - Makes a new token with a specified username and password, and impersonates it to conduct future actions as the specified user.
* `RevertToSelf()` - Ends the impersonation of any token, reverting back to the initial token associated with the current process. Useful in conjuction with functions that impersonate a token and do not automatically RevertToSelf, such as: `ImpersonateUser()`, `ImpersonateProcess()`, `GetSystem()`, and `MakeToken()`.
* `EnableTokenPrivilege()` - Enables a specified security privilege for a specified token. (Requires Admin)

## SharpSploit.Enumeration

### SharpSploit.Enumeration.Host

* `GetProcessList()` - Gets a list of running processes on the system.
* `GetArchitecture()` - Gets the architecuture of the OS.
* `GetParentProcess()` - Gets the parent process if of a process.
* `GetProcessOwner()` - Gets the username of the owner of a process.
* `IsWow64()` - Checks if a process is a Wow64 process.
* `CreateProcessDump()` - Creates a minidump of the memory of a running process. Useful for offline Mimikatz if dumping the LSASS process. (Requires Admin)
* `GetHostname()` - Gets the hostname of the system.
* `GetUsername()` - Gets the current Domain and username of the process running.
* `GetCurrentDirectory()` - Gets the current working directory full path.
* `GetDacl()` - Gets the Discretionary Access Control List (DACL) of a file or directory.
* `GetDirectoryListing()` - Gets a directory listing of the current working directory.
* `ChangeCurrentDirectory()` - Changes the current directory by appending a specified string to the current working directory.

### SharpSploit.Enumeration.Network

* `PortScan()` - Conducts a port scan of specified computer(s) and port(s) and reports open ports.
* `Ping()` - Pings specified computer(s) to identify live systems.

### SharpSploit.Enumeration.Domain

### SharpSploit.Enumeration.Domain.DomainSearcher

* `GetDomainUsers()` - Gets a list of specified (or all) user `DomainObject`s in the current Domain.
* `GetDomainGroups()` - Gets a list of specified (or all) group `DomainObject`s in the current Domain.
* `GetDomainComputers()` - Gets a list of specified (or all) computer `DomainObject`s in the current Domain.
* `GetDomainSPNTickets()` - Gets `SPNTicket`s for specified `DomainObject`s.
* `Kerberoast()` - Gets a list of `SPNTicket`s for specified (or all) users with a SPN set in the current Domain.

### SharpSploit.Enumeration.Net

* `GetNetLocalGroups()` - Gets a list of `LocalGroup`s from specified remote computer(s).
* `GetNetLocalGroupMembers()` - Gets a list of `LocalGroupMember`s from specified remote computer(s) for a specified group.
* `GetNetLoggedOnUsers()` - Gets a list of `LoggedOnUser`s from specified remote computer(s).
* `GetNetSessions()` - Gets a list of `SessionInfo`s from specified remote computer(s).
* `GetNetShares()` - Gets a list of `ShareInfo`s from specified remote computer(s).

### SharpSploit.Enumeration.Keylogger

* `StartKeylogger()` - Starts a keylogger that gets keystrokes for a specified amount of time.

## SharpSploit.Evastion

### SharpSploit.Evasion.Amsi

* `PatchAmsiScanBuffer()` - Patch the AmsiScanBuffer function in amsi.dll to disable the AMSI for the current process.

## SharpSploit.Execution

### SharpSploit.Execution.Assembly

* `Load()` - Loads a .NET assembly byte array or base64-encoded byte array.
* `AssemblyExecute()` - Loads a .NET assembly byte array or base64-encoded byte array and executes a specified method within a specified type with specified parameters using reflection.

### SharpSploit.Execution.PE

* `Load()` - Loads a PE with a specified byte array. (Requires Admin) **(*Currently broken. Works for Mimikatz, but not arbitrary PEs*)
* `GetFunctionExport()` - Get a pointer to an exported function in a loaded PE. The pointer can then be used to execute the function in the PE.

### SharpSploit.Execution.Shell

* `PowerShellExecute()` - Executes specified PowerShell code using System.Management.Automation.dll and bypasses AMSI, ScriptBlock Logging, and Module Logging (but not Transcription Logging).
* `CreateProcess()` - Creates a specified process, optionally with an alternative username and password. Uses the CreateProcess API and returns the output of the process.
* `CreateCmdProcess()` - Creates a specified cmd.exe process, optionally with an alternative username and password. Uses the CreateProcess API and returns the output of the process.
* `ShellExecute()` - Executes a specified shell command, optionally with an alternative username and password. Uses the ShellExecuteEx API and does not return the output of the command.
* `ShellCmdExecute()` - Executes a specified cmd.exe shell command, optionally with an alternative username and password. Uses the ShellExecuteEx API and does not return the output of the command.
* `Execute()` - Executes a specified command, optionally with an alternative username and password. May return the output of the command, depending upon the value of the UseShellExecute parameter.
* `CreateProcessWithToken()` - Creates a specified process with an impersonated token. Uses the CreateProcessWithToken API and returns the output of the process. (Requires Admin)

### SharpSploit.Execution.ShellCode

The `SharpSploit.Execution.ShellCode` class includes a method for executing shellcode. Shellcode execution is accomplished by copying it to pinned memory, modifying the memory permissions with `Win32.Kernel32.VirtualProtect()`, and executing with a .NET `delegate`.

The `SharpSploit.Execution.ShellCode` class includes the following primary function:

* `ShellCodeExecute()` - Executes a specified shellcode byte array by copying it to pinned memory, modifying the memory permissions with `Win32.Kernel32.VirtualProtect()`, and executing with a .NET `delegate`.

### SharpSploit.Execution.Win32

Win32 contains a library of enums and structures for Win32 API functions that can be used with PlatformInvoke or DynamicInvoke function execution.

### SharpSploit.Execution.Native

Native contains a library of enums and structures for Native NT API functions that can be used PlatformInvoke or DynamicInvoke function execution.

## SharpSploit.Execution.PlatformInvoke

The `SharpSploit.Execution.PlatformInvoke` namespace contains classes for invoking unmanaged exported DLL functions from the Win32 API or the Native NT API.

### SharpSploit.Execution.PlatformInvoke.Win32

The `SharpSploit.Execution.PlatformInvoke.Win32` class contains a library of PlatformInvoke signatures for Win32 API functions.

### SharpSploit.Execution.PlatformInvoke.Native

The `SharpSploit.Execution.PlatformInvoke.Native` class contains a library of PlatformInvoke signatures for NT API functions.

## SharpSploit.Execution.DynamicInvoke

The `SharpSploit.Execution.DynamicInvoke` namespace contains classes for dynamically invoking unmanaged DLL functions. Allows the user to call functions in Win32, the NT API, or third-party APIs without using P/Invoke. This avoids suspicious imports and can help evade static analysis tools. It also assists in invoking unmanaged code from function pointers, which can be used to invoke shellcode, exported functions from manually mapped DLLs, direct syscall execution, or many other use cases. Helper functions are also included for manually mapping PE modules in a variety of ways, including Module Overloading.

Function prototypes for delegates are much less forgiving than P/Invoke. Data types used as parameters must have exactly the same format in memory as the unmanaged function expects, whereas P/Invoke is forgiving and lets you use data types that are close but not the same. There is no existing library of delegates that is verified to be compatable with the Win32 and NT APIs. As such, the library of delegates in SharpSploit will be updated over time as they are discovered, tested, and used by SharpSploit commands.

### SharpSploit.Execution.DynamicInvoke.Win32

The `SharpSploit.Execution.DyanmicInvoke.Win32` class contains a library of DyanmicInvoke signatures for Win32 API functions.

### SharpSploit.Execution.DynamicInvoke.Native

The `SharpSploit.Execution.DyanmicInvoke.Native` class contains a library of DyanmicInvoke signatures for NT API functions.

### SharpSploit.Execution.DynamicInvoke.Generic

The `SharpSploit.Execution.DynamicInvoke.Generic` class contains helper functions for invoking arbitrary unmanaged functions by name or from pointers.

* `DynamicAPIInvoke()` - Dynamically invokes a specified API call from a DLL on disk.
* `DynamicFunctionInvoke()` - Dynamically invokes a function at a specified pointer.
* `LoadModuleFromDisk()` - Resolves `LdrLoadDll` and uses that function to load a DLL from disk.
* `GetLibraryAddress()` - Helper function that obtains the pointer to a function using in-memory export parsing.
* `GetLoadedModuleAddress()` - Gets the base address of a module loaded by the current process.
* `GetPebLdrModuleEntry()` - Helper for getting the base address of a module loaded by the current process. This base address could be passed to `GetProcAddress`/`GetNativeExportAddress`/`LdrGetProcedureAddress` or it could be used for manual export parsing.
* `GetAPIHash()` - Gets a HMAC-MD5 hash for unique hash based API lookups.
* `GetExportAddress()` - Gets the address of an exported function given the base address of a module.
* `GetNativeExportAddress()` - Given a module base address, resolve the address of a function by calling `LdrGetProcedureAddress`.
* `GetPeMetaData()` - Retrieve PE header information from the module base pointer.
* `GetApiSetMapping()` - Resolve host DLL for API Set DLL (Win10+).
* `CallMappedPEModule()` - Call a manually mapped PE by its EntryPoint.
* `CallMappedDLLModule()` - Call a manually mapped DLL by DllMain -> DLL_PROCESS_ATTACH.
* `CallMappedDLLModuleExport()` - Call a manually mapped DLL by Export.
* `GetSyscallStub()` - Read ntdll from disk, find/copy the appropriate syscall stub and free ntdll.

## SharpSploit.Execution.ManaulMap

The `SharpSploit.Execution.ManualMap.Map` class contains helper functions for manually mapping PE modules.

* `MapModuleFromDisk()` - Maps a module from disk into a Section using `NtCreateSection`.
* `AllocateFileToMemory()` - Allocate file to memory, either from disk or from a byte array.
* `RelocateModule()` - Relocates a module in memory.
* `MapModuleToMemory()` - Manually map module into current process.
* `SetModuleSectionPermissions()` - Set correct module section permissions.
* `RewriteModuleIAT()` - Rewrite IAT for manually mapped module.

The `SharpSploit.Execution.ManualMap.Overload` class contains helper functions for Module Overloading.

* `FindDecoyModule()` - Locate a signed module with a minimum size which can be used for overloading.
* `OverloadModule()` - Load a signed decoy module into memory, creating legitimate file-backed memory sections within the process. Afterwards overload that module by manually mapping a payload in it's place causing the payload to execute from what appears to be file-backed memory.

## SharpSploit.Execution.Injection

The `SharpSploit.Execution.Injection` namespace contains classes for modular process injection components that can be combined to build custom injectors. An `AllocationTechnique` makes a `PayloadType` available to the target process. An `ExecutionTechnique` executes a `PayloadType` that is present in memory within a target process.

### SharpSploit.Execution.Injection.AllocationTechnique

The `SharpSploit.Execution.Injection.AllocationTechnique` class is an abstract parent class providing the requirements for all allocation components.

### SharpSploit.Execution.Injection.SectionMapAlloc

The `SharpSploit.Execution.Injection.SectionMapAlloc` class inherits from `AllocationTechnique` and is an Allocation component that allocates a payload to a target process using a locally-written, remotely-mapped shared memory section.

### SharpSploit.Execution.Injection.ExecutionTechnique

The `SharpSploit.Execution.Injection.ExecutionTechnique` class is an abstract parent class providing the requirements for all execution components.

### SharpSploit.Execution.Injection.RemoteThreadCreate

The `SharpSploit.Execution.Injection.RemoteThreadCreate` class inherits from `ExecutionTechnique` and is an Execution component that executes a payload in a remote process by creating a new thread. Allows the user to specify which API call to use for remote thread creation.

### SharpSploit.Execution.Injection.PayloadType

The `SharpSploit.Execution.Injection.PayloadType` class is an abstract parent class providing the requirements for all types of payloads. Allocation and Execution components may behave differently for each subclass of `PayloadType`.

### SharpSploit.Execution.Injection.Injector

The `SharpSploit.Execution.Injection.Injector` class provides static functions for performing injection using a combination of Allocation and Execution components, along with a Payload.

## SharpSploit.LateralMovement

### SharpSploit.LateralMovement.WMI

* `WMIExecute()` - Execute a process on a remote system with Win32_Process Create4 with specified credentials.

### SharpSploit.LateralMovement.DCOM

* `DCOMExecute()` - Execute a command on a remote system using various DCOM methods.

### SharpSploit.LateralMovement.SCM

* `GetService()` - Gets a service on a remote machine.
* `GetServices()` - Gets a list of all services on a remote machine.
* `CreateService()` - Creates a service on a remote machine.
* `StartService()` - Starts a service on a remote machine.
* `StopService()` - Stops a service on a remote machine.
* `DeleteService()` - Deletes a service on a remote machine.
* `PSExec()` - Executes a command on a remote computer using a PSExec-like technique.

### SharpSploit.LateralMovement.PowerShellRemoting

* `InvokeCommand()` - Invoke a PowerShell command on a remote machine.

// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace SharpSploit.Execution.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes for third-party code, and functionality for dynamically invoking arbitrary API calls from memory or disk.
    /// Allows you to avoid suspicious P/Invokes, imports, and IAT entries by loading modules and invoking their functions at runtime rather than referencing them at compile-time.
    /// </summary>
    class Generic
    {

        /// <summary>
        /// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments.
        /// </summary>
        /// <param name="dllName">Name of the DLL.</param>
        /// <param name="procedureName">Name of the function.</param>
        /// <param name="funcType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="args">Arbitrary set of arguments to pass it. Can be modified if function uses call by reference.</param>
        /// <returns>Anything returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicAPIInvoke(string dllName, string procedureName, Type funcType, ref object[] args)
        {
            IntPtr hModule = Execution.Win32.Kernel32.LoadLibrary(dllName);

            IntPtr pFunction = Execution.Win32.Kernel32.GetProcAddress(hModule, procedureName);

            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pFunction, funcType);

            Object result = funcDelegate.DynamicInvoke(args);

            return result;
        }


        /// <summary>
        /// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory.
        /// </summary>
        /// <param name="pFunction">A pointer to the unmanaged function.</param>
        /// <param name="funcType">Prototype for the function, represented as a Delegate object.</param>
        /// <param name="args">Arbitrary set of arguments to pass it. Can be modified if function uses call by reference.</param>
        /// <returns>Anything returned by the function. Must be unmarshalled by the caller.</returns>
        public static object DynamicFunctionInvoke(IntPtr pFunction, Type funcType, ref object[] args)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pFunction, funcType);

            Object result = funcDelegate.DynamicInvoke(args);

            return result;
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL on disk.
        /// </summary>
        /// <param name="dllName">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <param name="procedureName">Name of the exported procedure.</param>
        /// <returns>Handle to the function.</returns>
        public static IntPtr GetLibraryAddress(string dllName, string procedureName)
        {
            IntPtr hModule = Execution.Win32.Kernel32.LoadLibrary(dllName);

            return Execution.Win32.Kernel32.GetProcAddress(hModule, procedureName);
        }
    }
}

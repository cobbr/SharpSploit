// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

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
            IntPtr hModule = Execution.Win32.Kernel32.LoadLibrary(DLLName);

            IntPtr pFunction = Execution.Win32.Kernel32.GetProcAddress(hModule, FunctionName);

            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pFunction, FunctionDelegateType);

            Object result = funcDelegate.DynamicInvoke(Parameters);

            return result;
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

            Object result = funcDelegate.DynamicInvoke(Parameters);

            return result;
        }

        /// <summary>
        /// Helper for getting the pointer to a function from a DLL on disk.
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="DLLName">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
        /// <param name="FunctionName">Name of the exported procedure.</param>
        /// <returns>IntPtr handle to the function.</returns>
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName)
        {
            IntPtr hModule = Execution.Win32.Kernel32.LoadLibrary(DLLName);

            return Execution.Win32.Kernel32.GetProcAddress(hModule, FunctionName);
        }
    }
}

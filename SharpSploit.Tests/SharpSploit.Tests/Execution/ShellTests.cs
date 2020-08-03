// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Execution;
using PInvoke = SharpSploit.Execution.PlatformInvoke;

namespace SharpSploit.Tests.Execution
{
    [TestClass]
    public class ShellTest
    {
        [TestMethod]
        public void TestPowerShellExecute()
        {
            string output = Shell.PowerShellExecute("Get-ChildItem");
            Assert.AreNotEqual(null, output);
            Assert.IsTrue(output.Length > 10);
        }

        [TestMethod]
        public void TestPowerShellExecuteEmptyString()
        {
            string output = Shell.PowerShellExecute("");
            Assert.AreNotEqual(null, output);
            Assert.AreEqual("", output);
        }

        [TestMethod]
        public void TestPowerShellExecuteNull()
        {
            string output = Shell.PowerShellExecute(null);
            Assert.AreNotEqual(null, output);
            Assert.AreEqual("", output);
        }

        [TestMethod]
        public void TestPowerShellExecuteVerbose()
        {
            string output = Shell.PowerShellExecute(@"
function Test-Verbose {
    [CmdletBinding()]
    Param()
    Write-Verbose ""verbose""
}
Test-Verbose -Verbose");
            Assert.AreEqual("verbose\r\n", output);
        }

        [TestMethod]
        public void TestPowerShellExecuteError()
        {
            string output = Shell.PowerShellExecute("Write-Error 'error'");
            Assert.AreEqual("error\r\n", output);
        }

        [TestMethod]
        public void TestShellCreateProcess()
        {
            string output = Shell.CreateProcess("tasklist /v");
            Assert.AreNotEqual(null, output);
            Assert.IsTrue(output.Length > 10);
            Assert.IsTrue(output.Contains("svchost.exe"));
        }

        [TestMethod]
        public void TestShellExecute()
        {
            int current = Process.GetProcessesByName("Calculator").Length;
            string output = Shell.ShellExecute("calc.exe");
            Assert.AreNotEqual(null, output);
            Assert.AreEqual("", output);
            System.Threading.Thread.Sleep(1000);
            int after = Process.GetProcessesByName("Calculator").Length;
            Assert.IsTrue(after > current);
        }

        [TestMethod]
        public void TestCreateProcessWithToken()
        {
            // Assumes that we have a single explorer process running that we can access
            PInvoke.Win32.Kernel32.OpenProcessToken(
                Process.GetProcessesByName("notepad")[0].Handle,
                (uint)TokenAccessLevels.MaximumAllowed,
                out IntPtr hToken
            );
            Win32.WinBase._SECURITY_ATTRIBUTES sec = new Win32.WinBase._SECURITY_ATTRIBUTES();
            PInvoke.Win32.Advapi32.DuplicateTokenEx(
                hToken,
                (uint)TokenAccessLevels.MaximumAllowed,
                ref sec,
                Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                Win32.WinNT.TOKEN_TYPE.TokenImpersonation,
                out IntPtr hProcessToken
            );
            
            string output = Shell.CreateProcessWithToken("whoami /all", @"C:\Windows\System32", hProcessToken);
            Console.WriteLine(output);
            Assert.AreNotEqual(null, output);
            Assert.IsTrue(output.Length > 10);
            Assert.IsTrue(output.Contains("PRIVILEGES INFORMATION"));
        }

        [TestMethod]
        public void TestShellExecuteEmptyString()
        {
            string output = Shell.Execute("");
            Assert.AreNotEqual(null, output);
            Assert.AreEqual("", output);
        }

        [TestMethod]
        public void TestShellExecuteNull()
        {
            String output = Shell.Execute(null);
            Assert.AreNotEqual(null, output);
            Assert.AreEqual("", output);
        }
    }
}

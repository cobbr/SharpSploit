// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Execution;
using SharpSploit.Credentials;
using System.Security.Principal;
using System.Diagnostics;

namespace SharpSploit.Tests.Execution
{
    [TestClass]
    public class ShellTest
    {
        [TestMethod]
        public void TestPowerShellExecute()
        {
            String output = Shell.PowerShellExecute("Get-ChildItem");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output.Length > 10);
        }

        [TestMethod]
        public void TestPowerShellExecuteEmptyString()
        {
            String output = Shell.PowerShellExecute("");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }

        [TestMethod]
        public void TestPowerShellExecuteNull()
        {
            String output = Shell.PowerShellExecute(null);
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }

        [TestMethod]
        public void TestShellExecute()
        {
            String output = Shell.ShellExecute("tasklist /v");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output.Length > 10);
        }


        [TestMethod]
        public void TestCreateProcessWithToken()
        {
            IntPtr hToken = IntPtr.Zero;
            // Assumes that we have a single explorer process running that we can access
            Win32.Kernel32.OpenProcessToken(Process.GetProcessesByName("explorer")[0].Handle, (uint)TokenAccessLevels.MaximumAllowed, out hToken);
            IntPtr hStolenHandle = IntPtr.Zero;
            Win32.WinBase._SECURITY_ATTRIBUTES sec = new Win32.WinBase._SECURITY_ATTRIBUTES();
            Win32.Advapi32.DuplicateTokenEx(hToken, (uint)TokenAccessLevels.MaximumAllowed, ref sec, (Win32.WinNT._SECURITY_IMPERSONATION_LEVEL)TokenImpersonationLevel.Impersonation,
                Win32.WinNT.TOKEN_TYPE.TokenImpersonation, out hStolenHandle);
            String output = Shell.CreateProcessWithToken("whoami /priv", Environment.CurrentDirectory, hStolenHandle);
            Debug.WriteLine(output);
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output.Length > 10);
        }

        [TestMethod]
        public void TestShellExecuteEmptyString()
        {
            String output = Shell.ShellExecute("");
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }

        [TestMethod]
        public void TestShellExecuteNull()
        {
            String output = Shell.ShellExecute(null);
            Assert.AreNotEqual(output, null);
            Assert.IsTrue(output == "");
        }
    }
}

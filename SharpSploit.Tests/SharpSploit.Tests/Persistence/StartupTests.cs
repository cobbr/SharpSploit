// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Persistence;

namespace SharpSploit.Tests.Persistence
{
    [TestClass]
    public class StartupTests
    {
        [TestMethod]
        public void InstallStartupScript()
        {
            string Payload = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -enc <blah>";
            Startup.InstallStartup(Payload);

            string FilePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + $@"\Microsoft\Windows\Start Menu\Programs\Startup\startup.bat";
            Assert.IsTrue(File.Exists(FilePath));
        }
    }
}

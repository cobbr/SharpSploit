// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpSploit.Persistence;

namespace SharpSploit.Framework.Tests.Persistence
{
    [TestClass]
    public class ConfigPersistTest
    {
        [TestMethod]
        public void TestInstallation()
        {
            var configPersist = new ConfigPersist();
            bool result = configPersist.InstallConfigPersist(@"System.Diagnostics.Process.Start(""calc.exe"")");

            Assert.IsTrue(result);
        }
    }
}

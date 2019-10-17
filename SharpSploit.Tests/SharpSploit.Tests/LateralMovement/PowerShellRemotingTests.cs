// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.LateralMovement;

namespace SharpSploit.Tests.LateralMovement
{
    [TestClass]
    public class PowerShellRemotingTests
    {
        [TestMethod]
        public void TestInvokeCommand()
        {
            string FileName = Path.GetTempFileName();
            bool result = PowerShellRemoting.InvokeCommand("localhost", $@"'test' | Out-File '{FileName}'");
            Assert.IsTrue(result);
            System.Threading.Thread.Sleep(2000);
            string text = File.ReadAllText(FileName);
            Assert.AreEqual("test", text);
            File.Delete(FileName);
        }
    }
}

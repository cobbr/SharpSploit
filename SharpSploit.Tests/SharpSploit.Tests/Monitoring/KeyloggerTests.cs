// Author: Scottie Austin (@checkymander)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Generic;
using SharpSploit.Monitoring;

namespace SharpSploit.Tests.Monitoring
{
    [TestClass]
    public class KeyloggerTests
    {
        [TestMethod]
        public void TestKeylogger()
        {
            string results = Keylogger.Start(10);
            Assert.IsTrue(results.Length > 0);
        }
    }
}
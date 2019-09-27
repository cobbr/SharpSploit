// Author: Scottie Austin (@checkymander)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Linq;
using System.Timers;
using Threads = System.Threading;
using Forms = System.Windows.Forms;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using SharpSploit.Generic;
using SharpSploit.Enumeration;

namespace SharpSploit.Tests.Enumeration
{
    [TestClass]
    public class KeyloggerTests
    {
        [TestMethod]
        public void TestKeylogger()
        {
            string results = "";
            Threads.Thread t = new Threads.Thread(() =>
            {
                results = Keylogger.StartKeylogger(3);
            });

            t.Start();
            Forms.SendKeys.SendWait("test123");
            t.Join(3000);

            Assert.IsTrue(results.Length > 0);
            Assert.IsTrue(results.Contains("test123"));
        }
    }
}